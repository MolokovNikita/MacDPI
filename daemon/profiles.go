package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed profiles/default.json
var bundledProfiles []byte

const profileURL = "https://raw.githubusercontent.com/MolokovNikita/MacDPI/main/daemon/profiles/default.json"
const upstreamURL = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/commits/main"

var activeProfiles atomic.Pointer[strategyProfiles]
var profileService = &profileManager{}
var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
var profilePosition = regexp.MustCompile(`^(1|[1-9][0-9]{0,3}|sni(\+[0-9]{1,3})?|mid|end|host(\+[0-9]{1,3})?)$`)
var commitID = regexp.MustCompile(`^[a-f0-9]{40}$`)

type profilePattern struct {
	Data   []byte `json:"data"`
	SHA256 string `json:"sha256"`
}
type strategyProfiles struct {
	Schema       int        `json:"schema"`
	Revision     uint64     `json:"revision"`
	Version      string     `json:"version"`
	MinEngine    int        `json:"min_engine"`
	SourceCommit string     `json:"source_commit"`
	Strategies   []Strategy `json:"strategies"`
	Orders       struct {
		Discord []string `json:"discord"`
		YouTube []string `json:"youtube"`
	} `json:"orders"`
	Patterns       map[string]profilePattern `json:"patterns"`
	GoogleOverlap  int                       `json:"google_overlap"`
	GeneralOverlap int                       `json:"general_overlap"`
	QUICRepeats    int                       `json:"quic_repeats"`
	VoiceRepeats   int                       `json:"voice_repeats"`
}

func parseProfiles(raw []byte) (*strategyProfiles, error) {
	if len(raw) > 64*1024 {
		return nil, errors.New("profile exceeds 64 KiB")
	}
	var p strategyProfiles
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing profile content")
	}
	if p.Schema != 1 || p.Revision == 0 || len(p.Version) == 0 || len(p.Version) > 80 || !commitID.MatchString(p.SourceCommit) {
		return nil, errors.New("invalid profile identity")
	}
	if p.MinEngine > serviceVersion || p.MinEngine < 11 {
		return nil, errors.New("profile requires a different MacDPI engine")
	}
	if p.GoogleOverlap < 1 || p.GoogleOverlap > 1200 || p.GeneralOverlap < 1 || p.GeneralOverlap > 1200 || p.QUICRepeats < 1 || p.QUICRepeats > 12 || p.VoiceRepeats < 1 || p.VoiceRepeats > 12 {
		return nil, errors.New("unsafe profile bounds")
	}
	if len(p.Strategies) == 0 || len(p.Strategies) > 24 {
		return nil, errors.New("invalid number of strategies")
	}
	names := map[string]bool{}
	for _, s := range p.Strategies {
		if !profileName.MatchString(s.Name) || s.Name == "auto" || s.Name == "none" || names[s.Name] || len(s.Title) > 100 || len(s.Cuts) > 6 || s.BlockQUIC || s.UDPFake != 0 || s.UDPFakePorts != "" {
			return nil, errors.New("invalid profile strategy")
		}
		names[s.Name] = true
		if s.PacketMode != "" && s.PacketMode != "seqovl" && s.PacketMode != "seqovl-google" && s.PacketMode != "badseq" {
			return nil, errors.New("unsupported packet mode")
		}
		if s.TLSRec != "" && !profilePosition.MatchString(s.TLSRec) {
			return nil, errors.New("unsupported record position")
		}
		for _, cut := range s.Cuts {
			if !profilePosition.MatchString(cut.Pos) || cut.Mode != "split" && cut.Mode != "oob" && cut.Mode != "disorder" {
				return nil, errors.New("unsupported split")
			}
		}
	}
	for _, order := range [][]string{p.Orders.Discord, p.Orders.YouTube} {
		if len(order) == 0 || len(order) > 16 {
			return nil, errors.New("invalid strategy order")
		}
		seen := map[string]bool{}
		for _, name := range order {
			if !names[name] || seen[name] {
				return nil, errors.New("unknown or duplicate ordered strategy")
			}
			seen[name] = true
		}
	}
	for _, name := range []string{"flowseal-general", "flowseal-google", "flowseal-fake-tls", "tlsrec-split", "tcp-sni", "multisplit", "tlsrec", "oob", "disorder"} {
		if !names[name] {
			return nil, errors.New("missing built-in strategy")
		}
	}
	if len(p.Patterns) != 5 {
		return nil, errors.New("invalid pattern set")
	}
	for _, key := range []string{"tls_general", "tls_google", "quic_google", "discord_udp", "stun"} {
		pattern, ok := p.Patterns[key]
		sum := sha256.Sum256(pattern.Data)
		if !ok || len(pattern.Data) == 0 || len(pattern.Data) > 1400 || hex.EncodeToString(sum[:]) != pattern.SHA256 {
			return nil, fmt.Errorf("invalid %s pattern or checksum", key)
		}
		switch key {
		case "tls_general", "tls_google":
			if !isTLSHello(pattern.Data) {
				return nil, errors.New("invalid TLS pattern")
			}
		case "quic_google", "discord_udp":
			if !quicInitial(pattern.Data) {
				return nil, errors.New("invalid QUIC pattern")
			}
		case "stun":
			if !stunPacket(pattern.Data) {
				return nil, errors.New("invalid STUN pattern")
			}
		}
	}
	return &p, nil
}
func profileBytes(key string, fallback []byte) []byte {
	if p := activeProfiles.Load(); p != nil {
		return p.Patterns[key].Data
	}
	return fallback
}
func profileRepeats(voice bool) int {
	if p := activeProfiles.Load(); p != nil {
		if voice {
			return p.VoiceRepeats
		}
		return p.QUICRepeats
	}
	return 6
}

type profileStatus struct {
	Active          string `json:"active"`
	Available       string `json:"available,omitempty"`
	LastChecked     string `json:"last_checked,omitempty"`
	Error           string `json:"error,omitempty"`
	UpstreamChanged bool   `json:"upstream_changed"`
}
type profileManager struct {
	mu       sync.Mutex
	checking bool
	state    profileStatus
}

func (m *profileManager) status() profileStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	if p := activeProfiles.Load(); p != nil {
		s.Active = p.Version
	}
	return s
}
func (m *profileManager) activate() {
	p, err := parseProfiles(bundledProfiles)
	if err != nil {
		panic(err)
	}
	if raw, err := os.ReadFile(filepath.Join(stateDirectory, "strategies.json")); err == nil {
		if cached, e := parseProfiles(raw); e == nil && cached.Revision >= p.Revision {
			p = cached
		}
	}
	activeProfiles.Store(p)
}
func profileHTTPClient() *http.Client {
	return &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{DialContext: dialBound, ForceAttemptHTTP2: true}}
}
func fetchProfiles(ctx context.Context, client *http.Client, url string) ([]byte, *strategyProfiles, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "MacDPI-profiles")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("profile HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, nil, err
	}
	p, err := parseProfiles(raw)
	return raw, p, err
}
func (m *profileManager) check(ctx context.Context) {
	m.mu.Lock()
	if m.checking {
		m.mu.Unlock()
		return
	}
	m.checking = true
	m.mu.Unlock()
	var updateErr error
	var version string
	var upstreamChanged bool
	defer func() {
		m.mu.Lock()
		m.checking = false
		m.state.LastChecked = time.Now().UTC().Format(time.RFC3339)
		if updateErr != nil {
			m.state.Error = updateErr.Error()
		} else {
			m.state.Error = ""
			m.state.Available = version
			m.state.UpstreamChanged = upstreamChanged
		}
		m.mu.Unlock()
	}()
	client := profileHTTPClient()
	defer client.CloseIdleConnections()
	raw, p, err := fetchProfiles(ctx, client, profileURL)
	if err != nil {
		updateErr = err
		return
	}
	current := activeProfiles.Load()
	if current != nil && p.Revision < current.Revision {
		updateErr = errors.New("profile rollback rejected")
		return
	}
	if oldRaw, err := os.ReadFile(filepath.Join(stateDirectory, "strategies.json")); err == nil {
		if old, e := parseProfiles(oldRaw); e == nil && old.Revision > p.Revision {
			updateErr = errors.New("cached profile rollback rejected")
			return
		}
	}
	if err = saveProfileCache(raw); err != nil {
		updateErr = err
		return
	}
	version = p.Version
	req, _ := http.NewRequestWithContext(ctx, "GET", upstreamURL, nil)
	req.Header.Set("User-Agent", "MacDPI-profiles")
	if resp, e := client.Do(req); e == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var latest struct {
				SHA string `json:"sha"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&latest) == nil && commitID.MatchString(latest.SHA) {
				upstreamChanged = latest.SHA != p.SourceCommit
			}
		}
	}
	event("profiles.checked", map[string]any{"version": version, "upstream_changed": upstreamChanged})
}
func saveProfileCache(raw []byte) error {
	if err := os.MkdirAll(stateDirectory, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(stateDirectory, ".profiles-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(stateDirectory, "strategies.json"))
}
func (m *profileManager) monitor(ctx context.Context) {
	m.check(ctx)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

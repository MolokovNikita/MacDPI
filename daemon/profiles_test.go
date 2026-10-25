package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledProfiles(t *testing.T) {
	p, err := parseProfiles(bundledProfiles)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version == "" || len(p.Patterns) != 5 {
		t.Fatal("empty built-in profile")
	}
	old := activeProfiles.Swap(p)
	defer activeProfiles.Store(old)
	st, ok := findPreset("flowseal-google")
	if !ok || st.PacketMode != "seqovl-google" {
		t.Fatal("downloadable preset not used")
	}
	h := wireFixture()
	frames, err := makeDesyncFrames(h, hello(t), st.PacketMode)
	if err != nil || len(frames) != 1 {
		t.Fatal("profile packet builder failed", err)
	}
	if profileRepeats(true) != p.VoiceRepeats || profileRepeats(false) != p.QUICRepeats {
		t.Fatal("profile repeats ignored")
	}
}
func TestProfilesRejectUnsupportedOrUnsafeUpdates(t *testing.T) {
	for _, change := range []func(*strategyProfiles){
		func(p *strategyProfiles) { p.MinEngine = serviceVersion + 1 },
		func(p *strategyProfiles) { p.Strategies[0].PacketMode = "run-command" },
		func(p *strategyProfiles) { p.Strategies[0].Cuts[0].Pos = "$(touch /tmp/no)" },
		func(p *strategyProfiles) { p.QUICRepeats = 100000 },
		func(p *strategyProfiles) { p.GeneralOverlap = 1400 },
		func(p *strategyProfiles) {
			p.Patterns["quic_google"] = profilePattern{Data: []byte("bad"), SHA256: "bad"}
		},
		func(p *strategyProfiles) { p.SourceCommit = "../../main" },
		func(p *strategyProfiles) { p.Orders.Discord = []string{"unknown"} },
	} {
		p, err := parseProfiles(bundledProfiles)
		if err != nil {
			t.Fatal(err)
		}
		change(p)
		raw, _ := json.Marshal(p)
		if _, err = parseProfiles(raw); err == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
	if _, err := parseProfiles(append(append([]byte(nil), bundledProfiles...), []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := parseProfiles([]byte(strings.Repeat(" ", 65537))); err == nil {
		t.Fatal("oversized profile accepted")
	}
}
func TestFetchProfilesDoesNotAcceptHTTPErrorsOrMalformedContent(t *testing.T) {
	for _, bad := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bad {
				w.Write([]byte(`{"schema":1,"command":"sh"}`))
			} else {
				w.Write(bundledProfiles)
			}
		}))
		_, p, err := fetchProfiles(context.Background(), server.Client(), server.URL)
		server.Close()
		if bad && err == nil || !bad && (err != nil || p == nil) {
			t.Fatal("incorrect profile fetch validation", err)
		}
	}
}
func TestProfilesCacheActivationKeepsInvalidCacheOut(t *testing.T) {
	oldDirectory := stateDirectory
	stateDirectory = t.TempDir()
	defer func() { stateDirectory = oldDirectory }()
	old := activeProfiles.Load()
	defer activeProfiles.Store(old)
	manager := &profileManager{}
	if err := os.WriteFile(filepath.Join(stateDirectory, "strategies.json"), []byte(`{"command":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	manager.activate()
	baseline := activeProfiles.Load()
	if baseline == nil {
		t.Fatal("invalid cache displaced built-in profile")
	}
	p, _ := parseProfiles(bundledProfiles)
	p.Revision++
	p.Version = "test-next"
	raw, _ := json.Marshal(p)
	if err := saveProfileCache(raw); err != nil {
		t.Fatal(err)
	}
	if activeProfiles.Load().Version != baseline.Version {
		t.Fatal("cache write changed active connections")
	}
	manager.activate()
	if activeProfiles.Load().Version != "test-next" {
		t.Fatal("cached profile not activated on reconnect")
	}
	info, err := os.Stat(filepath.Join(stateDirectory, "strategies.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("profile cache permissions", err)
	}
}

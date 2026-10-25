package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type learnedStrategy struct {
	name    string
	expires time.Time
}
type strategyPolicy struct {
	sync.Mutex
	learned          map[string]learnedStrategy
	discordPreferred string
	verified         map[string]verifiedEndpoint
	dnsHints         map[string]dnsAddressHint
}

type verifiedEndpoint struct {
	address string
	expires time.Time
}

func newStrategyPolicy() *strategyPolicy {
	return &strategyPolicy{learned: map[string]learnedStrategy{}, verified: map[string]verifiedEndpoint{}}
}
func discordHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
func videoHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range []string{"youtube.com", "youtube-nocookie.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com", "yt3.googleusercontent.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
func adaptiveHost(host string) bool { return discordHost(host) || videoHost(host) }
func (p *strategyPolicy) candidates(host, address string, base Strategy) []Strategy {
	names := []string{base.Name, "tlsrec-split", "tcp-sni", "oob", "multisplit"}
	// Many googlevideo nodes only pass handshakes whose SNI is on an allowlist
	// (e.g. www.google.com), so splitting the real ClientHello cannot help there.
	// Flowseal sends a www.google.com ClientHello in a sequence overlap first.
	if videoHost(host) && activePacketEngine.Load() != nil {
		names = append([]string{"flowseal-google"}, names...)
	}
	if discordHost(host) {
		names = []string{"oob", "multisplit", "tcp-sni", "tlsrec-split"}
		if activePacketEngine.Load() != nil {
			names = append([]string{"flowseal-general", "flowseal-fake-tls"}, names...)
		}
	}
	if profiles := activeProfiles.Load(); profiles != nil {
		if discordHost(host) {
			names = append([]string(nil), profiles.Orders.Discord...)
		} else if videoHost(host) {
			names = append([]string(nil), profiles.Orders.YouTube...)
		}
	}
	p.Lock()
	if discordHost(host) && p.discordPreferred != "" {
		names = append([]string{p.discordPreferred}, names...)
	}
	cached, ok := p.learned[host+"|"+address]
	p.Unlock()
	seen := map[string]bool{}
	var result []Strategy
	for _, name := range names {
		if seen[name] {
			continue
		}
		if st, ok := findPreset(name); ok {
			if st.PacketMode != "" && activePacketEngine.Load() == nil {
				continue
			}
			seen[name] = true
			result = append(result, st)
		}
	}
	// Rotate the stable order instead of prepending the cached strategy. A
	// prepend changes its successor and causes oob -> multisplit -> oob loops
	// after partial-response failures, never trying the remaining profiles.
	if ok && time.Now().Before(cached.expires) {
		for i, st := range result {
			if st.Name == cached.name {
				rotated := make([]Strategy, 0, len(result))
				rotated = append(rotated, result[i:]...)
				result = append(rotated, result[:i]...)
				break
			}
		}
	}
	return result
}

func (p *strategyPolicy) seed(checks []serviceCheck) {
	p.Lock()
	defer p.Unlock()
	for _, check := range checks {
		if discordHost(check.Host) && check.HTTPS {
			p.discordPreferred = check.Strategy
			if check.Address != "" {
				p.verified[check.Host] = verifiedEndpoint{check.Address, time.Now().Add(10 * time.Minute)}
				p.learned[check.Host+"|"+check.Address] = learnedStrategy{check.Strategy, time.Now().Add(10 * time.Minute)}
			}
		}
	}
}

// Only reuse an endpoint for the exact DNS name whose HTTPS identity and complete
// response were verified. CDN/voice hosts are never mapped to the website IP.
func (p *strategyPolicy) endpoint(host string) string {
	p.Lock()
	defer p.Unlock()
	entry := p.verified[host]
	if time.Now().Before(entry.expires) {
		return entry.address
	}
	return ""
}

func (h *systemRelay) verifiedRemote(remote *net.TCPConn, host, address string) (*net.TCPConn, string) {
	if _, port, err := net.SplitHostPort(address); err != nil || port != "443" {
		return remote, address
	}
	verified := h.policy.endpoint(host)
	if verified == "" || verified == address {
		return remote, address
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := dialBound(ctx, "tcp", verified)
	if err != nil {
		return remote, address
	}
	if !h.track(raw) {
		raw.Close()
		return remote, address
	}
	h.untrack(remote)
	event("tls.verified_endpoint", map[string]any{"host": host, "original": address, "verified": verified})
	return raw.(*net.TCPConn), verified
}
func (p *strategyPolicy) remember(host, address, name string) {
	p.Lock()
	defer p.Unlock()
	if len(p.learned) >= 512 {
		clear(p.learned)
	}
	p.learned[host+"|"+address] = learnedStrategy{name: name, expires: time.Now().Add(10 * time.Minute)}
}

func (p *strategyPolicy) advanceFailedWindow(host, address string, candidates []Strategy) {
	if len(candidates) <= 4 {
		return
	}
	p.Lock()
	defer p.Unlock()
	key := host + "|" + address
	if current, ok := p.learned[key]; ok && time.Now().Before(current.expires) && current.name != candidates[0].Name {
		return
	}
	if len(p.learned) >= 512 {
		clear(p.learned)
	}
	p.learned[key] = learnedStrategy{name: candidates[4].Name, expires: time.Now().Add(10 * time.Minute)}
	event("tls.window_advanced", map[string]any{"host": host, "destination": address, "next": candidates[4].Name})
}
func (p *strategyPolicy) penalize(host, address string, used Strategy, base Strategy) {
	p.Lock()
	if p.verified[host].address == address {
		delete(p.verified, host)
	}
	p.Unlock()
	candidates := p.candidates(host, address, base)
	next := ""
	for i, st := range candidates {
		if st.Name == used.Name {
			next = candidates[(i+1)%len(candidates)].Name
			break
		}
	}
	if next != "" {
		p.Lock()
		// An older failed flow must not overwrite a newer strategy selection.
		if current, ok := p.learned[host+"|"+address]; ok && current.name != used.Name {
			p.Unlock()
			return
		}
		p.learned[host+"|"+address] = learnedStrategy{name: next, expires: time.Now().Add(10 * time.Minute)}
		p.Unlock()
		event("tls.profile_rotated", map[string]any{"host": host, "destination": address, "failed": used.Name, "next": next})
	}
}
func readServerHello(c net.Conn, timeout time.Duration) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})
	head := make([]byte, 5)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[3:]))
	if head[1] != 3 || n < 1 || n > 18432 {
		return nil, errors.New("invalid first TLS server record")
	}
	packet := make([]byte, 5+n)
	copy(packet, head)
	if _, err := io.ReadFull(c, packet[5:]); err != nil {
		return nil, err
	}
	if head[0] != 0x16 || packet[5] != 2 {
		return packet, fmt.Errorf("TLS server did not return ServerHello (record=%d)", head[0])
	}
	return packet, nil
}

// Replay only the initial ClientHello, before delivering any server bytes to the
// client or forwarding further client data. Encrypted HTTP requests are never replayed.
func (h *systemRelay) negotiate(initial *net.TCPConn, first []byte, host, address string, flow uint64) (*net.TCPConn, []byte, Strategy, error) {
	candidates := h.policy.candidates(host, address, h.strategy)
	timeout := h.helloTimeout
	if timeout == 0 {
		timeout = 1800 * time.Millisecond
	}
	remote := initial
	for attempt, st := range candidates {
		if attempt >= 4 {
			break
		} // Bound handshake latency; later flows continue the stable cycle.
		if attempt > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			raw, err := dialBound(ctx, "tcp", address)
			cancel()
			if err != nil {
				failure("tls.retry_dial", err, map[string]any{"flow": flow, "strategy": st.Name})
				continue
			}
			remote = raw.(*net.TCPConn)
			if !h.track(remote) {
				remote.Close()
				return nil, nil, st, net.ErrClosed
			}
		}
		event("tls.attempt", map[string]any{"flow": flow, "host": host, "destination": address, "strategy": st.Name, "attempt": attempt + 1})
		remote.SetWriteDeadline(time.Now().Add(3 * time.Second))
		err := st.SendFirst(remote, first)
		var reply []byte
		if err == nil {
			reply, err = readServerHello(remote, timeout)
		}
		if err == nil {
			remote.SetWriteDeadline(time.Time{})
			h.policy.remember(host, address, st.Name)
			event("tls.server_hello", map[string]any{"flow": flow, "host": host, "strategy": st.Name, "bytes": len(reply)})
			return remote, reply, st, nil
		}
		failure("tls.before_server_response", err, map[string]any{"flow": flow, "host": host, "strategy": st.Name})
		h.untrack(remote)
	}
	h.policy.Lock()
	if h.policy.verified[host].address == address {
		delete(h.policy.verified, host)
	}
	h.policy.Unlock()
	h.policy.advanceFailedWindow(host, address, candidates)
	return nil, nil, Strategy{}, errors.New("all initial TLS strategies failed")
}

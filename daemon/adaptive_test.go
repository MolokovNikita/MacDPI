package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestStrategyIsolationAndRotation(t *testing.T) {
	p := newStrategyPolicy()
	base, _ := findPreset("tlsrec-split")
	if !adaptiveHost("rr1.googlevideo.com") || !discordHost("gateway.discord.gg") || adaptiveHost("evil-discord.com") || adaptiveHost("discord.com.example.org") {
		t.Fatal("domain boundary error")
	}
	p.remember("discord.com", "1.1.1.1:443", "multisplit")
	if p.candidates("discord.com", "1.1.1.1:443", base)[0].Name != "multisplit" {
		t.Fatal("cache ignored")
	}
	if p.candidates("discord.com", "2.2.2.2:443", base)[0].Name != "oob" {
		t.Fatal("profile leaked across IPs")
	}
	if p.candidates("www.youtube.com", "1.1.1.1:443", base)[0].Name != base.Name {
		t.Fatal("profile leaked across hosts")
	}
	used, _ := findPreset("multisplit")
	p.penalize("discord.com", "1.1.1.1:443", used, base)
	if p.candidates("discord.com", "1.1.1.1:443", base)[0].Name == used.Name {
		t.Fatal("stalled profile not rotated")
	}
	p.remember("discord.com", "1.1.1.1:443", "tcp-sni")
	p.penalize("discord.com", "1.1.1.1:443", used, base)
	if p.candidates("discord.com", "1.1.1.1:443", base)[0].Name != "tcp-sni" {
		t.Fatal("stale flow replaced newer selection")
	}
	p.seed([]serviceCheck{{Host: "discord.com", TLS: true, HTTPS: false, Strategy: "multisplit"}})
	if p.candidates("gateway.discord.gg", "2.2.2.2:443", base)[0].Name != "oob" {
		t.Fatal("TLS-only result seeded profile")
	}
	p.seed([]serviceCheck{{Host: "discord.com", HTTPS: true, Strategy: "tlsrec-split"}})
	if p.candidates("gateway.discord.gg", "2.2.2.2:443", base)[0].Name != "tlsrec-split" {
		t.Fatal("full HTTPS result not seeded")
	}
}

func TestVerifiedEndpointRequiresCompleteExactHost(t *testing.T) {
	p := newStrategyPolicy()
	p.seed([]serviceCheck{{Host: "discord.com", TLS: true, HTTPS: false, Address: "1.1.1.1:443", Strategy: "multisplit"}})
	if p.endpoint("discord.com") != "" {
		t.Fatal("partial page accepted as verified endpoint")
	}
	p.seed([]serviceCheck{{Host: "discord.com", TLS: true, HTTPS: true, Address: "1.1.1.1:443", Strategy: "tlsrec-split"}})
	if p.endpoint("discord.com") != "1.1.1.1:443" || p.endpoint("gateway.discord.gg") != "" || p.endpoint("cdn.discordapp.com") != "" {
		t.Fatal("verified IP leaked to a different TLS identity")
	}
	st, _ := findPreset("tlsrec-split")
	p.penalize("discord.com", "1.1.1.1:443", st, st)
	if p.endpoint("discord.com") != "" {
		t.Fatal("stalled endpoint retained")
	}
}

func TestRepeatedPartialFailuresTryEveryProfileBeforeRepeating(t *testing.T) {
	for _, host := range []string{"discord.com", "rr1.googlevideo.com"} {
		for _, preferred := range []string{"", "tlsrec-split"} {
			p := newStrategyPolicy()
			p.discordPreferred = preferred
			base, _ := findPreset("multisplit")
			address := "192.0.2.1:443"
			initial := p.candidates(host, address, base)
			seen := map[string]bool{}
			for range len(initial) {
				candidates := p.candidates(host, address, base)
				used := candidates[0]
				if seen[used.Name] {
					t.Fatalf("%s preferred=%s: repeated %s before all candidates: %v", host, preferred, used.Name, seen)
				}
				seen[used.Name] = true
				p.remember(host, address, used.Name) // ServerHello arrives, then body stalls.
				p.penalize(host, address, used, base)
			}
			if next := p.candidates(host, address, base)[0].Name; next != initial[0].Name {
				t.Fatalf("cycle did not wrap: %s", next)
			}
		}
	}
}

type dropFirstListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *dropFirstListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.accepted.Add(1) != 1 {
			return c, nil
		}
		// Emulate a DPI black hole: consume ClientHello without sending a response.
		go func() { defer c.Close(); io.Copy(io.Discard, c) }()
	}
}

func TestAdaptiveRetriesHelloWithoutReplayingRequest(t *testing.T) {
	var requests atomic.Int32
	payload := bytes.Repeat([]byte("request-once-"), 20000)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(b, payload) {
			t.Error("application request changed", err)
		}
		w.Write(b)
	}))
	listener := &dropFirstListener{Listener: server.Listener}
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	base, _ := findPreset("tcp-sni")
	relay := newSystemRelay(base)
	relay.helloTimeout = 60 * time.Millisecond
	defer relay.close()
	app, flow := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() {
		defer flow.Close()
		reader := bufio.NewReader(flow)
		first, err := readFirst(reader, flow)
		if err != nil {
			done <- err
			return
		}
		address := listener.Addr().String()
		raw, err := net.Dial("tcp", address)
		if err != nil {
			done <- err
			return
		}
		relay.track(raw)
		remote, prefix, st, err := relay.negotiate(raw.(*net.TCPConn), first, "www.youtube.com", address, 1)
		if err != nil {
			done <- err
			return
		}
		defer relay.untrack(remote)
		if st.Name != "tlsrec-split" {
			t.Error("did not switch strategy", st.Name)
		}
		down := make(chan error, 1)
		go func() {
			_, e := flow.Write(prefix)
			if e == nil {
				_, e = io.Copy(flow, remote)
			}
			down <- e
		}()
		_, err = io.Copy(remote, reader)
		remote.CloseWrite()
		<-down
		done <- err
	}()
	// Self-signed fixture only; production clients retain normal verification.
	secure := tls.Client(app, &tls.Config{ServerName: "www.youtube.com", InsecureSkipVerify: true})
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	req, _ := http.NewRequest("POST", "https://www.youtube.com/", bytes.NewReader(payload))
	req.Close = true
	if err := req.Write(secure); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(secure), req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatal("TLS response changed after retry", err)
	}
	secure.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || listener.accepted.Load() != 2 {
		t.Fatalf("requests=%d connections=%d", requests.Load(), listener.accepted.Load())
	}
	if relay.policy.candidates("www.youtube.com", listener.Addr().String(), base)[0].Name != "tlsrec-split" {
		t.Fatal("successful retry not remembered")
	}
}

func TestServerHelloRejectsAlertAndBoundsRead(t *testing.T) {
	for _, packet := range [][]byte{{21, 3, 3, 0, 2, 2, 40}, {22, 3, 3, 255, 255}} {
		client, server := net.Pipe()
		go func() { defer server.Close(); server.Write(packet) }()
		if _, err := readServerHello(client, time.Second); err == nil {
			t.Error("invalid response accepted")
		}
		client.Close()
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := readServerHello(client, 10*time.Millisecond); err == nil {
		t.Fatal("silent server accepted")
	}
}

func TestVideoHostsLeadWithGoogleOverlapWhenPacketEngineIsReady(t *testing.T) {
	base, _ := findPreset("multisplit")
	p := newStrategyPolicy()
	if got := p.candidates("rr5---sn-q4flrnes.googlevideo.com", "192.0.2.1:443", base)[0].Name; got != base.Name {
		t.Fatal("packet profile offered without a packet engine", got)
	}
	old := activePacketEngine.Swap(&packetEngine{})
	defer activePacketEngine.Store(old)
	for _, host := range []string{"rr5---sn-q4flrnes.googlevideo.com", "www.youtube.com", "i.ytimg.com"} {
		candidates := p.candidates(host, "192.0.2.1:443", base)
		if candidates[0].Name != "flowseal-google" || candidates[1].Name != base.Name {
			t.Fatal("video host does not start with the Google overlap", host, candidates[0].Name, candidates[1].Name)
		}
	}
	if got := p.candidates("example.com", "192.0.2.1:443", base)[0].Name; got != base.Name {
		t.Fatal("Google overlap leaked to unrelated hosts", got)
	}
	if got := p.candidates("discord.com", "192.0.2.1:443", base)[0].Name; got != "flowseal-general" {
		t.Fatal("Discord profile order changed", got)
	}
	p.remember("rr5---sn-q4flrnes.googlevideo.com", "192.0.2.1:443", "tcp-sni")
	if got := p.candidates("rr5---sn-q4flrnes.googlevideo.com", "192.0.2.1:443", base)[0].Name; got != "tcp-sni" {
		t.Fatal("learned profile for this node ignored", got)
	}
}

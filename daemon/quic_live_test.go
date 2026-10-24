package main

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type firstUDPFlow struct {
	*udpFlow
	first []byte
}

func (c *firstUDPFlow) Read(b []byte) (int, error) {
	if c.first != nil {
		n := copy(b, c.first)
		c.first = nil
		return n, nil
	}
	return c.udpFlow.Read(b)
}

// Optional physical integration fixture. A separate HTTP/3 client sends normal
// QUIC through these loopback frontends; only the production relay adds fakes.
func TestPhysicalQUICRelay(t *testing.T) {
	ready := os.Getenv("MACDPI_QUIC_RELAY")
	if ready == "" {
		t.Skip("opt-in physical QUIC relay; no route/DNS changes")
	}
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureBoundInterface(iface); err != nil {
		t.Fatal(err)
	}
	defer func() { interfaceIndex.Store(0); boundSources.Store(nil) }()
	st, _ := findPreset("multisplit")
	h := newSystemRelay(st)
	var fronts []*net.UDPConn
	var workers sync.WaitGroup
	defer func() {
		for _, c := range fronts {
			c.Close()
		}
		h.close()
		workers.Wait()
	}()
	addresses := map[string]int{}
	for _, ip := range strings.Split(os.Getenv("MACDPI_QUIC_TARGETS"), ",") {
		parsed := net.ParseIP(ip)
		if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
			t.Fatal("expected public IPv4 target")
		}
		front, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		fronts = append(fronts, front)
		addresses[ip] = front.LocalAddr().(*net.UDPAddr).Port
		workers.Add(1)
		go func(front *net.UDPConn, ip string) {
			defer workers.Done()
			b := make([]byte, 65535)
			n, peer, e := front.ReadFromUDP(b)
			if e != nil {
				return
			}
			raw, e := dialBound(t.Context(), "udp", net.JoinHostPort(ip, "443"))
			if e != nil {
				t.Error(e)
				return
			}
			h.track(raw)
			flow := &firstUDPFlow{udpFlow: &udpFlow{UDPConn: front, peer: peer}, first: append([]byte(nil), b[:n]...)}
			h.relayUDP(flow, raw.(*net.UDPConn), flowSequence.Add(1), 443)
		}(front, ip)
	}
	data, _ := json.Marshal(addresses)
	if err = os.WriteFile(ready, data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(ready + ".done"); err == nil {
			t.Logf("production QUIC relay fake datagrams: %d", h.quicFakes.Load())
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("external HTTP/3 client did not finish")
}

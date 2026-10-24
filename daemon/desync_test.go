package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func hello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() { tls.Client(client, &tls.Config{ServerName: "example.com"}).Handshake(); client.Close() }()
	defer server.Close()
	server.SetReadDeadline(time.Now().Add(time.Second))
	h := make([]byte, 5)
	if _, err := io.ReadFull(server, h); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, int(binary.BigEndian.Uint16(h[3:])))
	if _, err := io.ReadFull(server, b); err != nil {
		t.Fatal(err)
	}
	return append(h, b...)
}
func TestSNI(t *testing.T) {
	h := hello(t)
	p, n, ok := sniSpan(h)
	if !ok || string(h[p:p+n]) != "example.com" {
		t.Fatal("SNI not found")
	}
	for i := 0; i < len(h); i++ {
		if _, _, ok := sniSpan(h[:i]); ok {
			t.Fatalf("truncated hello accepted: %d", i)
		}
	}
	// A name must fit inside its extension, even when bytes exist after it.
	bad := append([]byte(nil), h...)
	binary.BigEndian.PutUint16(bad[p-2:p], 65535)
	if _, _, ok := sniSpan(bad); ok {
		t.Fatal("oversized SNI accepted")
	}
}
func TestRecordSplit(t *testing.T) {
	h := hello(t)
	p, _, _ := sniSpan(h)
	out, _, ok := splitTLSRecord(h, p+1)
	if !ok {
		t.Fatal("no split")
	}
	size := int(binary.BigEndian.Uint16(out[3:5]))
	second := 5 + size
	rejoined := append(append([]byte(nil), out[5:second]...), out[second+5:]...)
	if !bytes.Equal(rejoined, h[5:]) {
		t.Fatal("TLS payload changed")
	}
	if int(binary.BigEndian.Uint16(out[second+3:second+5]))+size != len(h)-5 {
		t.Fatal("incorrect record sizes")
	}
}
func TestPlan(t *testing.T) {
	h := hello(t)
	for _, s := range Presets {
		out, pieces := s.plan(h)
		last := 0
		for _, p := range pieces {
			if p.end <= last || p.end >= len(out) {
				t.Fatal(s.Name, p)
			}
			last = p.end
		}
	}
}
func FuzzSNI(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 40, 1})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, n, ok := hostSpan(b)
		if ok && (p < 0 || n <= 0 || p+n > len(b)) {
			t.Fatal("span out of bounds")
		}
		for _, s := range Presets {
			s.plan(b)
		}
	})
}

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startProxy(t *testing.T, strategy string) *url.URL {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := findPreset(strategy)
	s := &tunnelServer{strategy: st, dns: "system"}
	done := make(chan struct{})
	go func() { s.serve(l); close(done) }()
	t.Cleanup(func() { s.close(); <-done })
	u, _ := url.Parse("http://" + l.Addr().String())
	return u
}
func TestHTTPSRelay(t *testing.T) {
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }))
	defer remote.Close()
	for _, preset := range []string{"tlsrec-split", "multisplit", "tlsrec", "none"} {
		t.Run(preset, func(t *testing.T) {
			proxy := startProxy(t, preset)
			// Self-signed httptest fixture only. Production TLS is never terminated by MacDPI.
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"}}
			defer transport.CloseIdleConnections()
			c := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			payload := bytes.Repeat([]byte("macdpi-test"), 10000)
			resp, err := c.Post(remote.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(body, payload) {
				t.Fatalf("relay corruption: %v", err)
			}
		})
	}
}
func TestRejectHTTP(t *testing.T) {
	u := startProxy(t, "none")
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "405") {
		t.Fatal(line, err)
	}
}
func TestFragmentedFirstRecord(t *testing.T) {
	h := hello(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		for _, v := range h {
			if _, err := a.Write([]byte{v}); err != nil {
				return
			}
		}
	}()
	result, err := readFirst(bufio.NewReader(b), b)
	if err != nil || !bytes.Equal(result, h) {
		t.Fatal("fragmented TLS failed", err)
	}
}

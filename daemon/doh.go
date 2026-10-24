package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

var dohServers = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"}
var dohPreferred atomic.Uint32
var dohClient = &http.Client{
	Timeout:       4 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{DialContext: dialBound, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second},
}

func dohQuery(ctx context.Context, q []byte) ([]byte, error) {
	var last error
	start := int(dohPreferred.Load()) % len(dohServers)
	for i := range dohServers {
		idx := (start + i) % len(dohServers)
		data, err := dohOnce(ctx, dohServers[idx], q)
		if err == nil {
			dohPreferred.Store(uint32(idx))
			return data, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
func dohOnce(ctx context.Context, endpoint string, q []byte) (result []byte, resultErr error) {
	begin := time.Now()
	defer func() {
		event("doh.result", map[string]any{"endpoint": endpoint, "question": dnsQuestion(q), "response_bytes": len(result), "elapsed_ms": time.Since(begin).Milliseconds(), "error": fmt.Sprint(resultErr)})
	}()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || media != "application/dns-message" {
		return nil, fmt.Errorf("DoH: HTTP %d, type %q", resp.StatusCode, media)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if len(raw) > 65535 {
		return nil, fmt.Errorf("oversized DNS response")
	}
	return raw, err
}
func lookupIP4(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	var idBytes [2]byte
	if _, err = rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	q, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}).Pack()
	if err != nil {
		return nil, err
	}
	raw, err := dohQuery(ctx, q)
	if err != nil {
		return nil, err
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(raw); err != nil {
		return nil, err
	}
	if !answer.Response || answer.ID != id || answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 || answer.Questions[0] != question {
		return nil, fmt.Errorf("invalid DNS response for %s", host)
	}
	// Accept only addresses belonging to the queried name or its CNAME chain.
	allowed := map[string]bool{strings.ToLower(name.String()): true}
	for i := 0; i < len(answer.Answers); i++ {
		for _, rr := range answer.Answers {
			if c, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && allowed[strings.ToLower(rr.Header.Name.String())] {
				allowed[strings.ToLower(c.CNAME.String())] = true
			}
		}
	}
	for _, rr := range answer.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok && rr.Header.Class == dnsmessage.ClassINET && allowed[strings.ToLower(rr.Header.Name.String())] {
			return net.IP(a.A[:]), nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address for %s", host)
}

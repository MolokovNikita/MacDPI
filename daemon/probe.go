package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type serviceCheck struct {
	Host     string `json:"host"`
	TLS      bool   `json:"tls"`
	HTTPS    bool   `json:"https"`
	Bytes    int64  `json:"bytes"`
	Strategy string `json:"strategy"`
	Address  string `json:"address,omitempty"`
	Error    string `json:"error,omitempty"`
}

func probeStrategy(st Strategy, host string) (check serviceCheck) {
	return probeStrategyAddress(st, host, "")
}

func probeStrategyAddress(st Strategy, host, address string) (check serviceCheck) {
	begin := time.Now()
	defer func() {
		event("probe.https", map[string]any{"strategy": st.Name, "host": host, "address": check.Address, "tls": check.TLS, "bytes": check.Bytes, "ok": check.HTTPS, "error": check.Error, "elapsed_ms": time.Since(begin).Milliseconds()})
	}()
	result := serviceCheck{Host: host, Strategy: st.Name}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if address == "" {
		ip, err := lookupIP4(ctx, host)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		address = net.JoinHostPort(ip.String(), "443")
	}
	result.Address = address
	raw, err := dialBound(ctx, "tcp", address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	conn := tls.Client(&firstWriteConn{TCPConn: raw.(*net.TCPConn), st: &st}, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, NextProtos: []string{"h2", "http/1.1"}})
	if err = conn.HandshakeContext(ctx); err != nil {
		result.Error = err.Error()
		return result
	}
	result.TLS = true
	response, err := probeResponse(ctx, conn, host)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.Bytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if result.Bytes > 4*1024*1024 {
		result.Error = "HTTPS probe body exceeds 4 MiB"
		return result
	}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		result.Error = fmt.Sprintf("HTTPS status %d", response.StatusCode)
		return result
	}
	result.HTTPS = true
	return result
}

// Match browser protocol negotiation; HTTP/1-only checks miss HTTP/2 behavior.
func probeResponse(ctx context.Context, conn *tls.Conn, host string) (*http.Response, error) {
	path := "/"
	if host == "discord.com" {
		path = "/app"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		transport := &http2.Transport{}
		client, err := transport.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return client.RoundTrip(request)
	}
	request.Close = true
	if err = request.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), request)
}

func chooseStrategy() (Strategy, []serviceCheck) {
	return selectStrategy(probeStrategy)
}

func selectStrategy(probe func(Strategy, string) serviceCheck) (Strategy, []serviceCheck) {
	checks := make([]serviceCheck, 2)
	var wg sync.WaitGroup
	for i, host := range []string{"www.youtube.com", "discord.com"} {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			names := []string{"multisplit", "tlsrec-split", "tcp-sni", "oob"}
			if discordHost(host) && activePacketEngine.Load() != nil {
				names = append([]string{"flowseal-general", "flowseal-fake-tls"}, names...)
			}
			if profiles := activeProfiles.Load(); profiles != nil {
				if discordHost(host) {
					names = profiles.Orders.Discord
				} else {
					names = profiles.Orders.YouTube
				}
			}
			for _, name := range names {
				st, _ := findPreset(name)
				if st.PacketMode != "" && activePacketEngine.Load() == nil {
					continue
				}
				checks[i] = probe(st, host)
				if checks[i].HTTPS {
					break
				}
			}
		}(i, host)
	}
	wg.Wait()
	best, _ := findPreset("tlsrec-split")
	if checks[0].HTTPS {
		best, _ = findPreset(checks[0].Strategy)
	}
	return best, checks
}

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Explicit opt-in only: uses the physical interface without touching routes/DNS.
func TestPhysicalAdaptiveHTTPS(t *testing.T) {
	name := os.Getenv("MACDPI_PHYSICAL_SMOKE")
	if name == "" {
		t.Skip("set MACDPI_PHYSICAL_SMOKE to a physical interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = configureBoundInterface(iface); err != nil {
		t.Fatal(err)
	}
	defer func() { interfaceIndex.Store(0); boundSources.Store(nil) }()
	base, _ := findPreset("multisplit")
	relay := newSystemRelay(base)
	// Use the same full-HTTPS startup selection as the system controller.
	selected, checks := chooseStrategy()
	relay.strategy = selected
	relay.policy.seed(checks)
	defer relay.close()
	for _, host := range []string{"discord.com", "www.youtube.com"} {
		t.Run(host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ip, err := lookupIP4(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			address := net.JoinHostPort(ip.String(), "443")
			raw, err := dialBound(ctx, "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			relay.track(raw)
			app, flow := net.Pipe()
			defer app.Close()
			completed := make(chan struct{})
			go func() {
				defer close(completed)
				defer flow.Close()
				reader := bufio.NewReader(flow)
				first, e := readFirst(reader, flow)
				if e != nil {
					relay.untrack(raw)
					return
				}
				initial, target := relay.verifiedRemote(raw.(*net.TCPConn), host, address)
				remote, prefix, st, e := relay.negotiate(initial, first, host, target, 100)
				if e != nil {
					return
				}
				defer relay.untrack(remote)
				t.Logf("%s: strategy=%s", host, st.Name)
				down := make(chan struct{})
				go func() {
					defer close(down)
					if _, e := flow.Write(prefix); e == nil {
						io.Copy(flow, remote)
					}
					flow.Close()
				}()
				io.Copy(remote, reader)
				remote.Close()
				<-down
			}()
			secure := tls.Client(app, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
			secure.SetDeadline(time.Now().Add(18 * time.Second))
			response, err := probeResponse(ctx, secure, host)
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024*1024+1))
			response.Body.Close()
			secure.Close()
			<-completed
			if err != nil || response.StatusCode != 200 || n == 0 || n > 4*1024*1024 {
				t.Fatalf("HTTP %d bytes=%d err=%v", response.StatusCode, n, err)
			}
			t.Logf("HTTP %d, complete body=%d bytes, certificate verified", response.StatusCode, n)
		})
	}
}

func TestPhysicalStrategyMatrix(t *testing.T) {
	name := os.Getenv("MACDPI_PHYSICAL_MATRIX")
	if name == "" {
		t.Skip("opt-in physical diagnostics")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = configureBoundInterface(iface); err != nil {
		t.Fatal(err)
	}
	defer func() { interfaceIndex.Store(0); boundSources.Store(nil) }()
	variants := []Strategy{}
	for _, name := range []string{"tlsrec-split", "multisplit", "tcp-sni", "oob"} {
		st, _ := findPreset(name)
		variants = append(variants, st)
	}

	var wg sync.WaitGroup
	for _, st := range variants {
		wg.Add(1)
		go func(st Strategy) {
			defer wg.Done()
			check := probeStrategy(st, "discord.com")
			t.Logf("%s: tls=%v https=%v bytes=%d address=%s error=%s", st.Name, check.TLS, check.HTTPS, check.Bytes, check.Address, check.Error)
		}(st)
	}
	wg.Wait()
}

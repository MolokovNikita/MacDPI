package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"
)

// Read-only with respect to macOS routing/DNS: only public HTTPS requests.
// Extra arguments are video hosts (e.g. rr5---sn-xxxx.googlevideo.com from a
// report) to compare the Google overlap against a plain split.
func runPacketProbe(name string, videoHosts []string) error {
	if os.Geteuid() != 0 {
		return errors.New("packet probe requires root for BPF")
	}
	if name == "" {
		return errors.New("packet probe requires an explicit physical --interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if err = configureBoundInterface(iface); err != nil {
		return err
	}
	engine, err := openPacketEngine(name, boundSources.Load().IPv4)
	if err != nil {
		return err
	}
	activePacketEngine.Store(engine)
	defer func() { activePacketEngine.Store(nil); engine.close() }()
	checks := []serviceCheck{}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	ip, err := lookupIP4(ctx, "discord.com")
	cancel()
	if err != nil {
		return err
	}
	address := net.JoinHostPort(ip.String(), "443")
	for _, name := range []string{"flowseal-general", "flowseal-fake-tls", "oob", "flowseal-general"} {
		st, _ := findPreset(name)
		checks = append(checks, probeStrategyAddress(st, "discord.com", address))
	}
	for _, host := range append([]string{"www.youtube.com"}, videoHosts...) {
		for _, name := range []string{"multisplit", "flowseal-google"} {
			st, _ := findPreset(name)
			checks = append(checks, probeStrategy(st, host))
		}
	}
	result := struct {
		Interface    string         `json:"interface"`
		PacketEngine bool           `json:"packet_engine"`
		SYNHeaders   uint64         `json:"syn_headers"`
		Injected     uint64         `json:"injected_packets"`
		Checks       []serviceCheck `json:"checks"`
	}{name, true, engine.observed.Load(), engine.injected.Load(), checks}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

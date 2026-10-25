package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsHintFixture(t *testing.T, host string, ip [4]byte, ttl uint32) ([]byte, []byte) {
	t.Helper()
	name, _ := dnsmessage.NewName(host + ".")
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	q, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 19, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}).Pack()
	raw, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 19, Response: true}, Questions: []dnsmessage.Question{question}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: ip}}}}).Pack()
	return q, raw
}
func TestECHPolicyUsesOnlyFreshUnambiguousDNSHints(t *testing.T) {
	st, _ := findPreset("multisplit")
	h := newSystemRelay(st)
	h.targetOnly = true
	ip := [4]byte{162, 159, 129, 233}
	address := "162.159.129.233:443"
	q, raw := dnsHintFixture(t, "cdn.discordapp.com", ip, 60)
	h.policy.observeDNS(q, raw)
	if h.policyHost("cloudflare-ech.com", address) != "cdn.discordapp.com" {
		t.Fatal("encrypted CDN policy missing")
	}
	if h.policyHost("unrelated.example", address) != "" {
		t.Fatal("DNS hint overrode explicit unrelated SNI")
	}
	if !h.appliesToUDP(443, address) || h.appliesToUDP(443, "203.0.113.2:443") {
		t.Fatal("scoped UDP selection failed")
	}
	q, raw = dnsHintFixture(t, "other.example", ip, 60)
	h.policy.observeDNS(q, raw)
	if h.policyHost("cloudflare-ech.com", address) != "" {
		t.Fatal("ambiguous shared IP treated as Discord")
	}
	h.policy.Lock()
	h.policy.dnsHints[net.IP(ip[:]).String()] = dnsAddressHint{host: "cdn.discordapp.com", expires: time.Now().Add(-time.Second)}
	h.policy.Unlock()
	if h.policyHost("cloudflare-ech.com", address) != "" {
		t.Fatal("expired DNS hint used")
	}
}
func TestDNSHintsRejectUnrelatedAnswersAndMismatchedIDs(t *testing.T) {
	p := newStrategyPolicy()
	q, raw := dnsHintFixture(t, "cdn.discordapp.com", [4]byte{162, 159, 129, 233}, 60)
	raw[1] ^= 1
	p.observeDNS(q, raw)
	if p.dnsHint("162.159.129.233:443") != "" {
		t.Fatal("mismatched ID trusted")
	}
	raw[1] ^= 1
	var answer dnsmessage.Message
	answer.Unpack(raw)
	answer.Answers[0].Header.Name, _ = dnsmessage.NewName("unrelated.example.")
	raw, _ = answer.Pack()
	p.observeDNS(q, raw)
	if p.dnsHint("162.159.129.233:443") != "" {
		t.Fatal("unrelated A record trusted")
	}
}
func TestSystemDNSForwardingPreservesQueryAndResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	q, response := dnsHintFixture(t, "intranet.example", [4]byte{10, 0, 0, 7}, 30)
	go func() {
		b := make([]byte, 2048)
		n, peer, e := server.ReadFromUDP(b)
		if e == nil && string(b[:n]) == string(q) {
			server.WriteToUDP(response, peer)
		}
	}()
	raw, err := systemDNSQuery(context.Background(), []string{server.LocalAddr().String()}, q)
	if err != nil || string(raw) != string(response) {
		t.Fatal("original resolver response changed", err)
	}
}

func TestCaptureOriginalDHCPResolvers(t *testing.T) {
	old := run
	defer func() { run = old }()
	run = func(command string, args ...string) (string, error) {
		if command == "ipconfig" {
			return "192.168.1.1 1.1.1.1\n", nil
		}
		if len(args) > 0 && args[0] == "-listnetworkserviceorder" {
			return "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n", nil
		}
		return "There aren't any DNS Servers set on Wi-Fi.\n", nil
	}
	servers, err := captureSystemResolvers("en0")
	if err != nil || len(servers) != 2 || servers[0] != "192.168.1.1" {
		t.Fatal("DHCP DNS discovery failed", servers, err)
	}
}

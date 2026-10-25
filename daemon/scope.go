package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsAddressHint struct {
	host      string
	expires   time.Time
	ambiguous bool
}

func dnsMessages(q, raw []byte) (dnsmessage.Message, dnsmessage.Message, bool) {
	var query, answer dnsmessage.Message
	if query.Unpack(q) != nil || answer.Unpack(raw) != nil || query.Response || !answer.Response || answer.ID != query.ID || len(query.Questions) != 1 || len(answer.Questions) != 1 {
		return query, answer, false
	}
	a, b := query.Questions[0], answer.Questions[0]
	return query, answer, a.Type == b.Type && a.Class == b.Class && strings.EqualFold(a.Name.String(), b.Name.String())
}

// Hints select a packet policy only. They never change the address, SNI,
// certificate verification or encrypted ECH contents of an application flow.
func (p *strategyPolicy) observeDNS(q, raw []byte) {
	query, answer, ok := dnsMessages(q, raw)
	if !ok || answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess {
		return
	}
	question := query.Questions[0]
	if question.Class != dnsmessage.ClassINET || question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
		return
	}
	host := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	allowed := map[string]uint32{strings.ToLower(question.Name.String()): 300}
	for i := 0; i < len(answer.Answers); i++ {
		for _, rr := range answer.Answers {
			if c, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && rr.Header.Class == dnsmessage.ClassINET {
				if ttl, ok := allowed[strings.ToLower(rr.Header.Name.String())]; ok {
					allowed[strings.ToLower(c.CNAME.String())] = min(ttl, rr.Header.TTL)
				}
			}
		}
	}
	p.Lock()
	defer p.Unlock()
	if p.dnsHints == nil {
		p.dnsHints = map[string]dnsAddressHint{}
	}
	now := time.Now()
	for _, rr := range answer.Answers {
		ttl, valid := allowed[strings.ToLower(rr.Header.Name.String())]
		if !valid || rr.Header.Class != dnsmessage.ClassINET {
			continue
		}
		ttl = min(ttl, rr.Header.TTL)
		if ttl == 0 {
			continue
		}
		var ip net.IP
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			if question.Type != dnsmessage.TypeA {
				continue
			}
			ip = net.IP(body.A[:])
		case *dnsmessage.AAAAResource:
			if question.Type != dnsmessage.TypeAAAA {
				continue
			}
			ip = net.IP(body.AAAA[:])
		}
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		if len(p.dnsHints) >= 1024 {
			clear(p.dnsHints)
		}
		key := ip.String()
		next := dnsAddressHint{host: host, expires: now.Add(time.Duration(ttl) * time.Second)}
		old := p.dnsHints[key]
		if now.Before(old.expires) && old.host != host {
			sameService := discordHost(old.host) && discordHost(host) || videoHost(old.host) && videoHost(host)
			next.ambiguous = old.ambiguous || !sameService
			if next.ambiguous && next.expires.Before(old.expires) {
				next.expires = old.expires
			}
		} else if now.Before(old.expires) {
			next.ambiguous = old.ambiguous
		}
		p.dnsHints[key] = next
	}
}
func (p *strategyPolicy) dnsHint(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	p.Lock()
	defer p.Unlock()
	hint := p.dnsHints[ip.String()]
	if hint.ambiguous || !time.Now().Before(hint.expires) || !adaptiveHost(hint.host) {
		return ""
	}
	return hint.host
}
func (h *systemRelay) policyHost(sni, address string) string {
	if adaptiveHost(sni) {
		return sni
	}
	if strings.EqualFold(strings.TrimSuffix(sni, "."), "cloudflare-ech.com") || sni == "" {
		return h.policy.dnsHint(address)
	}
	return ""
}
func (h *systemRelay) appliesToUDP(port uint16, address string) bool {
	if !h.targetOnly {
		return true
	}
	return h.policy.dnsHint(address) != ""
}
func (h *systemRelay) resolveDNS(ctx context.Context, q []byte) ([]byte, error) {
	var query dnsmessage.Message
	if query.Unpack(q) != nil || len(query.Questions) == 0 {
		return nil, errors.New("invalid DNS query")
	}
	if len(query.Questions) != 1 && h.targetOnly {
		return systemDNSQuery(ctx, h.getSystemResolvers(), q)
	}
	host := strings.TrimSuffix(query.Questions[0].Name.String(), ".")
	var response []byte
	var err error
	if h.targetOnly && !adaptiveHost(host) {
		response, err = systemDNSQuery(ctx, h.getSystemResolvers(), q)
	} else {
		response, err = dohQuery(ctx, q)
	}
	if err == nil {
		h.policy.observeDNS(q, response)
	}
	return response, err
}
func systemDNSQuery(ctx context.Context, servers []string, q []byte) ([]byte, error) {
	var last error = errors.New("original DNS servers are unavailable")
	for _, server := range servers {
		raw, err := dnsExchange(ctx, "udp", server, q)
		if err == nil && len(raw) >= 4 && binary.BigEndian.Uint16(raw[2:4])&0x0200 != 0 {
			raw, err = dnsExchange(ctx, "tcp", server, q)
		}
		if err == nil {
			if matchingDNSReply(q, raw) {
				return raw, nil
			}
			err = errors.New("DNS reply does not match query")
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
func dnsExchange(ctx context.Context, network, server string, q []byte) ([]byte, error) {
	if len(q) > 65535 {
		return nil, errors.New("oversized DNS query")
	}
	address := server
	if net.ParseIP(server) != nil {
		address = net.JoinHostPort(server, "53")
	}
	c, err := dialBound(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if network == "tcp" {
		data := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(data, uint16(len(q)))
		copy(data[2:], q)
		if _, err = c.Write(data); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(c, data[:2]); err != nil {
			return nil, err
		}
		raw := make([]byte, int(binary.BigEndian.Uint16(data)))
		_, err = io.ReadFull(c, raw)
		return raw, err
	}
	if _, err = c.Write(q); err != nil {
		return nil, err
	}
	raw := make([]byte, 65535)
	n, err := c.Read(raw)
	return raw[:n], err
}
func captureSystemResolvers(iface string) ([]string, error) {
	service, err := serviceForIface(iface)
	if err != nil {
		return nil, err
	}
	servers, err := getDNS(service)
	if err != nil {
		return nil, err
	}
	if len(servers) == 1 && servers[0] == dnsAddr4 {
		backups, e := readBackups()
		if e != nil {
			return nil, e
		}
		servers = nil
		for _, b := range backups {
			if b.Service == service {
				servers = b.Servers
				break
			}
		}
	}
	if len(servers) == 0 {
		out, e := run("ipconfig", "getoption", iface, "domain_name_server")
		if e == nil {
			for _, word := range strings.Fields(out) {
				if net.ParseIP(word) != nil {
					servers = append(servers, word)
				}
			}
		}
	}
	var result []string
	for _, server := range servers {
		if net.ParseIP(server) != nil && server != dnsAddr4 {
			result = append(result, server)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("Не удалось определить исходные DNS для %s. Отключите режим «Только YouTube и Discord» или задайте DNS в настройках сети", iface)
	}
	return result, nil
}

func (h *systemRelay) setSystemResolvers(servers []string) {
	h.mu.Lock()
	h.systemResolvers = append([]string(nil), servers...)
	h.mu.Unlock()
}
func (h *systemRelay) getSystemResolvers() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.systemResolvers...)
}

func matchingDNSReply(q, raw []byte) bool {
	var query, answer dnsmessage.Message
	if query.Unpack(q) != nil || answer.Unpack(raw) != nil || query.Response || !answer.Response || query.ID != answer.ID || len(query.Questions) != len(answer.Questions) {
		return false
	}
	for i, a := range query.Questions {
		b := answer.Questions[i]
		if a.Type != b.Type || a.Class != b.Class || !strings.EqualFold(a.Name.String(), b.Name.String()) {
			return false
		}
	}
	return true
}

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Cut describes where the first client packet is cut and how the piece
// that ends at this position is sent.
type Cut struct {
	Pos  string `json:"pos"`  // "1", "sni", "sni+1", "mid", "end"
	Mode string `json:"mode"` // "split", "disorder", "oob"
}

// Strategy is a set of DPI bypass tricks, similar to ByeDPI/zapret options.
type Strategy struct {
	Name  string `json:"name"`
	Title string `json:"title"`

	// TCP: applied to the first packet (TLS ClientHello or HTTP request).
	TLSRec     string `json:"tlsrec,omitempty"` // split the TLS record at this position
	PacketMode string `json:"packet_mode,omitempty"`
	Cuts       []Cut  `json:"cuts,omitempty"`

	// UDP.
	BlockQUIC    bool   `json:"block_quic"`     // drop UDP/443 so browsers fall back to TCP
	UDPFake      int    `json:"udp_fake"`       // fake datagrams sent before the first real one
	UDPFakePorts string `json:"udp_fake_ports"` // e.g. "19294-19344,50000-65535"
}

const discordVoicePorts = "19294-19344,50000-65535"

func udpDefaults(s Strategy) Strategy {
	s.BlockQUIC = false
	s.UDPFake = 0
	s.UDPFakePorts = discordVoicePorts
	return s
}

// Presets are ordered from the simplest to the most aggressive.
var Presets = []Strategy{
	{Name: "flowseal-general", Title: "General · seq-overlap (экспериментально)", PacketMode: "seqovl", Cuts: []Cut{{"1", "split"}}},
	{Name: "flowseal-fake-tls", Title: "Fake TLS · badseq (экспериментально)", PacketMode: "badseq", Cuts: []Cut{{"1", "split"}}},
	{Name: "flowseal-google", Title: "Google · seq-overlap (экспериментально)", PacketMode: "seqovl-google", Cuts: []Cut{{"1", "split"}}},
	{Name: "tcp-sni", Title: "TCP split по SNI", Cuts: []Cut{{"1", "split"}, {"sni+1", "split"}}},
	udpDefaults(Strategy{Name: "tlsrec-split", Title: "TLS-запись + split",
		TLSRec: "sni+1", Cuts: []Cut{{"1", "split"}}}),
	udpDefaults(Strategy{Name: "disorder", Title: "Disorder",
		TLSRec: "sni+1", Cuts: []Cut{{"1", "disorder"}}}),
	udpDefaults(Strategy{Name: "disorder-sni", Title: "Disorder по SNI",
		Cuts: []Cut{{"1", "split"}, {"sni+1", "disorder"}}}),
	udpDefaults(Strategy{Name: "multisplit", Title: "Multisplit по SNI",
		TLSRec: "sni+1", Cuts: []Cut{{"1", "split"}, {"sni+1", "split"}, {"mid", "split"}}}),
	udpDefaults(Strategy{Name: "oob", Title: "OOB",
		TLSRec: "sni+1", Cuts: []Cut{{"1", "oob"}}}),
	udpDefaults(Strategy{Name: "oob-disorder", Title: "OOB + disorder",
		Cuts: []Cut{{"1", "oob"}, {"sni+1", "disorder"}}}),
	udpDefaults(Strategy{Name: "tlsrec", Title: "Только TLS-запись",
		TLSRec: "sni+1"}),
	udpDefaults(Strategy{Name: "udp-only", Title: "Только звонки (TCP без обхода)"}),
}

var noStrategy = Strategy{Name: "none", Title: "Без обхода"}

func findPreset(name string) (Strategy, bool) {
	for _, p := range Presets {
		if p.Name == name {
			return p, true
		}
	}
	return Strategy{}, false
}

func (s *Strategy) hasTCP() bool { return s.PacketMode != "" || s.TLSRec != "" || len(s.Cuts) > 0 }

func (s *Strategy) fakePort(port uint16) bool {
	if s.UDPFake <= 0 {
		return false
	}
	for _, r := range strings.Split(s.UDPFakePorts, ",") {
		lo, hi, ok := strings.Cut(strings.TrimSpace(r), "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if ok {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 == nil && err2 == nil && int(port) >= a && int(port) <= b {
			return true
		}
	}
	return false
}

// hostSpan returns the offset and length of the host name in a TLS
// ClientHello (SNI) or an HTTP request (Host header).
func hostSpan(data []byte) (int, int, bool) {
	if off, n, ok := sniSpan(data); ok {
		return off, n, true
	}
	return httpHostSpan(data)
}

func isTLSHello(data []byte) bool {
	return len(data) >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01
}

func isHTTPRequest(data []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT "} {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return false
}

func sniSpan(d []byte) (int, int, bool) {
	if !isTLSHello(d) || len(d) < 44 {
		return 0, 0, false
	}
	recordEnd := 5 + int(binary.BigEndian.Uint16(d[3:5]))
	if recordEnd > len(d) || recordEnd < 44 {
		return 0, 0, false
	}
	d = d[:recordEnd]
	handshakeEnd := 9 + int(d[6])<<16 + int(d[7])<<8 + int(d[8])
	if handshakeEnd > len(d) || handshakeEnd < 44 {
		return 0, 0, false
	}
	d = d[:handshakeEnd]
	p := 43
	p += 1 + int(d[p])
	if p+2 > len(d) {
		return 0, 0, false
	}
	p += 2 + int(binary.BigEndian.Uint16(d[p:]))
	if p >= len(d) {
		return 0, 0, false
	}
	p += 1 + int(d[p])
	if p+2 > len(d) {
		return 0, 0, false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(d[p:]))
	p += 2
	if end > len(d) {
		return 0, 0, false
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(d[p:])
		n := int(binary.BigEndian.Uint16(d[p+2:]))
		p += 4
		if p+n > end {
			return 0, 0, false
		}
		if typ == 0 {
			if n < 5 {
				return 0, 0, false
			}
			listEnd := p + 2 + int(binary.BigEndian.Uint16(d[p:]))
			if listEnd != p+n {
				return 0, 0, false
			}
			for q := p + 2; q+3 <= listEnd; {
				kind := d[q]
				size := int(binary.BigEndian.Uint16(d[q+1:]))
				q += 3
				if size == 0 || q+size > listEnd {
					return 0, 0, false
				}
				if kind == 0 {
					return q, size, true
				}
				q += size
			}
			return 0, 0, false
		}
		p += n
	}
	return 0, 0, false
}

func httpHostSpan(d []byte) (int, int, bool) {
	if !isHTTPRequest(d) {
		return 0, 0, false
	}
	lower := append([]byte(nil), d...)
	for i, v := range lower {
		if v >= 'A' && v <= 'Z' {
			lower[i] = v + ('a' - 'A')
		}
	}
	i := bytes.Index(lower, []byte("\r\nhost:"))
	if i < 0 {
		return 0, 0, false
	}
	p := i + len("\r\nhost:")
	for p < len(d) && (d[p] == ' ' || d[p] == '\t') {
		p++
	}
	e := bytes.IndexByte(d[p:], '\r')
	if e <= 0 {
		return 0, 0, false
	}
	return p, e, true
}

// resolvePos turns a position spec into an absolute offset in data.
func resolvePos(spec string, data []byte) (int, bool) {
	spec = strings.TrimSpace(spec)
	if n, err := strconv.Atoi(spec); err == nil {
		return n, n > 0 && n < len(data)
	}
	hoff, hlen, ok := hostSpan(data)
	if !ok {
		return 0, false
	}
	base, delta := spec, 0
	if i := strings.IndexAny(spec, "+-"); i > 0 {
		base = spec[:i]
		d, err := strconv.Atoi(spec[i:])
		if err != nil {
			return 0, false
		}
		delta = d
	}
	var p int
	switch base {
	case "sni", "host":
		p = hoff
	case "mid":
		p = hoff + hlen/2
	case "end":
		p = hoff + hlen
	default:
		return 0, false
	}
	p += delta
	return p, p > 0 && p < len(data)
}

// splitTLSRecord splits the first TLS record of data in two at absolute
// offset pos. It returns the new data and the inserted header offset.
func splitTLSRecord(data []byte, pos int) ([]byte, int, bool) {
	if !isTLSHello(data) {
		return data, 0, false
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if pos <= 5 || pos >= 5+recLen || 5+recLen > len(data) {
		return data, 0, false
	}
	out := make([]byte, 0, len(data)+5)
	out = append(out, data[0], data[1], data[2])
	out = binary.BigEndian.AppendUint16(out, uint16(pos-5))
	out = append(out, data[5:pos]...)
	out = append(out, data[0], data[1], data[2])
	out = binary.BigEndian.AppendUint16(out, uint16(recLen-(pos-5)))
	out = append(out, data[pos:]...)
	return out, pos, true
}

type piece struct {
	end  int
	mode string
}

// plan computes the transformed first packet and the pieces to send.
func (s *Strategy) plan(data []byte) ([]byte, []piece) {
	// Positions are resolved on the original packet, then shifted past the
	// extra record header if the record was split before them.
	var pieces []piece
	for _, c := range s.Cuts {
		if p, ok := resolvePos(c.Pos, data); ok {
			pieces = append(pieces, piece{p, c.Mode})
		}
	}
	if s.TLSRec != "" {
		if p, ok := resolvePos(s.TLSRec, data); ok {
			if out, at, ok := splitTLSRecord(data, p); ok {
				data = out
				for i := range pieces {
					if pieces[i].end > at {
						pieces[i].end += 5
					}
				}
			}
		}
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].end < pieces[j].end })
	uniq := pieces[:0]
	for _, p := range pieces {
		if len(uniq) == 0 || uniq[len(uniq)-1].end != p.end {
			uniq = append(uniq, p)
		}
	}
	return data, uniq
}

// SendFirst writes the first client packet to the server applying the strategy.
func (s *Strategy) SendFirst(c *net.TCPConn, data []byte) error {
	if s.PacketMode != "" && isTLSHello(data) {
		engine := activePacketEngine.Load()
		if engine == nil {
			return errPacketUnavailable
		}
		if err := engine.inject(c, data, s.PacketMode); err != nil {
			return err
		}
	}
	if !s.hasTCP() || (!isTLSHello(data) && !isHTTPRequest(data)) {
		_, err := c.Write(data)
		return err
	}
	out, pieces := s.plan(data)
	if len(pieces) == 0 {
		_, err := c.Write(out)
		return err
	}
	_ = c.SetNoDelay(true)
	v6 := isIPv6(c.RemoteAddr())
	prev := 0
	for _, p := range pieces {
		chunk := out[prev:p.end]
		prev = p.end
		var err error
		switch p.mode {
		case "disorder":
			err = writeLowTTL(c, chunk, v6)
		case "oob":
			if _, err = c.Write(chunk); err == nil {
				err = sendOOB(c)
			}
		default:
			_, err = c.Write(chunk)
		}
		if err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	_, err := c.Write(out[prev:])
	return err
}

func isIPv6(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	return ok && t.IP.To4() == nil
}

func ttlOpt(v6 bool) (int, int) {
	if v6 {
		return unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	return unix.IPPROTO_IP, unix.IP_TTL
}

// writeLowTTL sends a chunk that dies on the first hop. The kernel later
// may retransmit it later. This is experimental and depends on the OS TCP stack.
func writeLowTTL(c *net.TCPConn, chunk []byte, v6 bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	level, opt := ttlOpt(v6)
	orig := 64
	var serr error
	err = rc.Control(func(fd uintptr) {
		if v, err := unix.GetsockoptInt(int(fd), level, opt); err == nil && v > 0 {
			orig = v
		}
		serr = unix.SetsockoptInt(int(fd), level, opt, 1)
	})
	if err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("set ttl: %w", serr)
	}
	_, werr := c.Write(chunk)
	time.Sleep(3 * time.Millisecond)
	rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), level, opt, orig)
	})
	if werr != nil {
		return werr
	}
	return serr
}

// sendOOB sends one urgent byte. Receiver and DPI handling is implementation-dependent.
func sendOOB(c *net.TCPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	werr := rc.Write(func(fd uintptr) bool {
		serr = unix.Sendto(int(fd), []byte{'a'}, unix.MSG_OOB, nil)
		return serr != syscall.EAGAIN
	})
	if werr != nil {
		return werr
	}
	return serr
}

// firstWriteConn applies the strategy to the first Write (used by probes).
type firstWriteConn struct {
	*net.TCPConn
	st   *Strategy
	done bool
}

func (c *firstWriteConn) Write(b []byte) (int, error) {
	if c.done {
		return c.TCPConn.Write(b)
	}
	c.done = true
	if err := c.st.SendFirst(c.TCPConn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

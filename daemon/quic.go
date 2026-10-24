package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"time"
)

// Pinned Flowseal protocol pattern; provenance and SHA-256 in reference/flowseal/SOURCE.json.
//
//go:embed patterns/quic_initial_www_google_com.bin
var flowsealQUICFake []byte

// A bounded setup burst on the same UDP socket. Encrypted application packets
// are forwarded unchanged; retransmissions cannot create a continuous fake flood.
type quicUDPPolicy struct {
	known     bool
	bursts    int
	lastBurst time.Time
}

func (p *quicUDPPolicy) before(now time.Time, packet []byte) bool {
	if !quicInitial(packet) {
		return false
	}
	p.known = true
	if p.bursts >= 3 || !p.lastBurst.IsZero() && now.Sub(p.lastBurst) < 500*time.Millisecond {
		return false
	}
	p.bursts++
	p.lastBurst = now
	return true
}

func quicVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << uint(b[0]>>6)
	if len(b) < n {
		return 0, 0, false
	}
	value := uint64(b[0] & 0x3f)
	for _, v := range b[1:n] {
		value = value<<8 | uint64(v)
	}
	return value, n, true
}

// Initial type bits differ between QUIC v1 and v2. Bounds include both IDs,
// token and protected payload, so unrelated UDP/443 does not receive fakes.
func quicInitial(b []byte) bool {
	if len(b) < 1200 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	if !(version == 1 && b[0]&0x30 == 0 || version == 0x6b3343cf && b[0]&0x30 == 0x10) {
		return false
	}
	dcid := int(b[5])
	if dcid > 20 || 6+dcid >= len(b) {
		return false
	}
	pos := 6 + dcid
	scid := int(b[pos])
	pos++
	if scid > 20 || pos+scid >= len(b) {
		return false
	}
	pos += scid
	token, n, ok := quicVarint(b[pos:])
	if !ok {
		return false
	}
	pos += n
	if token > uint64(len(b)-pos) {
		return false
	}
	pos += int(token)
	size, n, ok := quicVarint(b[pos:])
	if !ok {
		return false
	}
	pos += n
	return size >= 17 && size <= uint64(len(b)-pos)
}

// Only literal echoes of the injected datagram are filtered. QUIC servers can
// reply with zero-length destination IDs; filtering by those IDs would lose real
// responses. The client's QUIC stack authenticates packets with its own keys.
func injectedQUICEcho(b []byte) bool { return bytes.Equal(b, flowsealQUICFake) }

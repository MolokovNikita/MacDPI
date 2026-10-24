package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// Flowseal's pinned default Discord UDP pattern (1200-byte QUIC Initial).
//
//go:embed patterns/ACTIVE_DISCORD_UDP.bin
var flowsealVoiceFake []byte

//go:embed patterns/stun2.bin
var stunVoiceFake []byte

const voiceReplyTimeout = 6 * time.Second

type voiceUDPPolicy struct {
	known              bool
	fallback           bool
	started, lastBurst time.Time
}

func discordDiscovery(b []byte) bool {
	return len(b) == 74 && binary.BigEndian.Uint16(b[:2]) == 1 && binary.BigEndian.Uint16(b[2:4]) == 70
}
func stunPacket(b []byte) bool {
	return len(b) >= 20 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == 0x2112a442 && int(binary.BigEndian.Uint16(b[2:4]))+20 <= len(b)
}
func rtpLike(b []byte) bool { return len(b) >= 12 && b[0]>>6 == 2 }

// Recognition may happen after latency probes on the same socket. A silent
// connection gets one STUN fallback, without changing its NAT mapping or
// replaying encrypted voice. No extra packets are sent on a timer by themselves.
func (p *voiceUDPPolicy) before(now time.Time, packet []byte, lastReply time.Time) ([]byte, string, string) {
	first := !p.known && voicePacket(packet)
	if first {
		p.known = true
		p.started = now
	}
	if !p.known {
		return nil, "", ""
	}
	if lastReply.IsZero() {
		lastReply = p.started
	}
	if !first && !p.fallback && now.Sub(p.started) >= voiceReplyTimeout && now.Sub(lastReply) >= voiceReplyTimeout {
		p.fallback = true
		p.lastBurst = now
		return stunVoiceFake, "stun", "replies-stalled"
	}
	setup := discordDiscovery(packet) || stunPacket(packet)
	if first || setup && now.Sub(p.lastBurst) >= 500*time.Millisecond {
		p.lastBurst = now
		if p.fallback {
			return stunVoiceFake, "stun", "setup"
		}
		return flowsealVoiceFake, "flowseal-quic", "setup"
	}
	return nil, "", ""
}

func injectedVoiceReply(b []byte) bool {
	if bytes.Equal(b, flowsealVoiceFake) || bytes.Equal(b, stunVoiceFake) {
		return true
	}
	return stunPacket(b) && bytes.Equal(b[8:20], stunVoiceFake[8:20])
}

// Use the socket's normal TTL, matching Flowseal's default UDP fake behavior.
// Every fake and original datagram uses the very same socket / five-tuple.
func sendVoiceFakes(c *net.UDPConn, payload []byte, count int) (int, error) {
	for i := 0; i < count; i++ {
		if _, err := c.Write(payload); err != nil {
			return i, err
		}
	}
	return count, nil
}

type udpCounters struct {
	upPackets, downPackets, upBytes, downBytes atomic.Uint64
	rtpUp, rtpDown, ignoredFakes               atomic.Uint64
	lastUp, lastDown                           atomic.Int64
	fakeSent                                   atomic.Bool
}

func lastTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
func ageMS(n int64) int64 {
	if n == 0 {
		return -1
	}
	return time.Since(time.Unix(0, n)).Milliseconds()
}
func (s *udpCounters) fields(flow uint64, begin time.Time) map[string]any {
	return map[string]any{"flow": flow, "elapsed_ms": time.Since(begin).Milliseconds(), "up_packets": s.upPackets.Load(), "down_packets": s.downPackets.Load(), "up_bytes": s.upBytes.Load(), "down_bytes": s.downBytes.Load(), "rtp_like_up": s.rtpUp.Load(), "rtp_like_down": s.rtpDown.Load(), "last_up_ms": ageMS(s.lastUp.Load()), "last_down_ms": ageMS(s.lastDown.Load()), "ignored_fake_replies": s.ignoredFakes.Load()}
}

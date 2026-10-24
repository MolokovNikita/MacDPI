package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

var flowSequence atomic.Uint64

// systemRelay terminates TCP/UDP flows from the userspace IP stack.
// Outbound sockets are bound to the physical interface, bypassing utun routes.
type systemRelay struct {
	strategy     Strategy
	adaptive     bool
	policy       *strategyPolicy
	helloTimeout time.Duration
	mu           sync.Mutex
	flows        map[net.Conn]struct{}
	closed       bool
	slots        chan struct{}
	tcpCount     atomic.Uint64
	udpCount     atomic.Uint64
	quicCount    atomic.Uint64
	quicFakes    atomic.Uint64
	fakeCount    atomic.Uint64
	errors       atomic.Uint64
}

func newSystemRelay(st Strategy) *systemRelay {
	return &systemRelay{policy: newStrategyPolicy(), strategy: st, flows: map[net.Conn]struct{}{}, slots: make(chan struct{}, 512)}
}
func (h *systemRelay) track(c net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.flows[c] = struct{}{}
	return true
}
func (h *systemRelay) untrack(c net.Conn) { c.Close(); h.mu.Lock(); delete(h.flows, c); h.mu.Unlock() }
func (h *systemRelay) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.flows {
		c.Close()
	}
}
func (h *systemRelay) close() {
	h.mu.Lock()
	h.closed = true
	for c := range h.flows {
		c.Close()
	}
	h.mu.Unlock()
}
func (h *systemRelay) claim(c net.Conn, handler func()) {
	select {
	case h.slots <- struct{}{}:
	default:
		c.Close()
		h.errors.Add(1)
		return
	}
	if !h.track(c) {
		<-h.slots
		c.Close()
		return
	}
	go func() { defer func() { h.untrack(c); <-h.slots }(); handler() }()
}
func (h *systemRelay) HandleTCP(c adapter.TCPConn) {
	h.claim(c, func() { h.tcpCount.Add(1); h.tcp(c) })
}
func (h *systemRelay) HandleUDP(c adapter.UDPConn) {
	h.claim(c, func() { h.udpCount.Add(1); h.udp(c) })
}
func (h *systemRelay) tcp(c adapter.TCPConn) {
	id := c.ID()
	flowID := flowSequence.Add(1)
	begin := time.Now()
	event("tcp.open", map[string]any{"flow": flowID, "destination": id.LocalAddress.String(), "port": id.LocalPort, "source": id.RemoteAddress.String()})
	defer event("tcp.closed", map[string]any{"flow": flowID})
	if id.LocalPort == 53 {
		h.dnsTCP(c)
		return
	}
	address := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstream, err := dialBound(ctx, "tcp", address)
	cancel()
	if err != nil {
		h.errors.Add(1)
		failure("tcp.dial", err, map[string]any{"flow": flowID, "destination": address})
		return
	}
	remote := upstream.(*net.TCPConn)
	if !h.track(remote) {
		remote.Close()
		return
	}
	defer func() {
		if remote != nil {
			h.untrack(remote)
		}
	}()
	event("tcp.connected", map[string]any{"flow": flowID, "local": remote.LocalAddr().String(), "remote": remote.RemoteAddr().String()})
	reader := bufio.NewReader(c)
	var first, serverPrefix []byte
	host := ""
	used := h.strategy
	sent := false
	// TLS on 443 is client-first. Other protocols retain server-first relay behavior.
	if tlsServicePort(id.LocalPort) {
		first, err = readFirst(reader, c)
		if err != nil {
			return
		}
		if offset, size, ok := sniSpan(first); ok {
			host = string(first[offset : offset+size])
		}
		event("tcp.first_read", map[string]any{"flow": flowID, "bytes": len(first), "sni": host, "tls": isTLSHello(first), "error": fmt.Sprint(err)})
		if h.adaptive && adaptiveHost(host) && isTLSHello(first) {
			remote, address = h.verifiedRemote(remote, host, address)
			var chosen *net.TCPConn
			chosen, serverPrefix, used, err = h.negotiate(remote, first, host, address, flowID)
			if err != nil {
				h.errors.Add(1)
				failure("tls.no_strategy", err, map[string]any{"flow": flowID, "host": host})
				return
			}
			remote = chosen
			sent = true
		} else {
			remote.SetWriteDeadline(time.Now().Add(15 * time.Second))
			err = used.SendFirst(remote, first)
			sent = true
			if err != nil {
				return
			}
		}
		event("tcp.strategy.sent", map[string]any{"flow": flowID, "host": host, "strategy": used.Name})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var prefixBytes int64
		var e error
		if len(serverPrefix) > 0 {
			c.SetWriteDeadline(time.Now().Add(15 * time.Second))
			var n int
			n, e = c.Write(serverPrefix)
			prefixBytes = int64(n)
		}
		var n int64
		if e == nil {
			n, e = copyIdle(c, remote, remote)
		}
		total := n + prefixBytes
		event("tcp.download.end", map[string]any{"flow": flowID, "host": host, "strategy": used.Name, "bytes": total, "elapsed_ms": time.Since(begin).Milliseconds(), "error": fmt.Sprint(e)})
		if h.adaptive && adaptiveHost(host) && e != nil && time.Since(begin) < 25*time.Second && total < 65536 {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				h.policy.penalize(host, address, used, h.strategy)
			}
		}
		if cw, ok := any(c).(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		if e != nil {
			c.Close()
		}
	}()
	if !sent {
		first, err = readFirst(reader, c)
		if err == nil {
			remote.SetWriteDeadline(time.Now().Add(15 * time.Second))
			err = used.SendFirst(remote, first)
		}
	}
	if err == nil {
		var n int64
		n, err = copyIdle(remote, reader, c)
		event("tcp.upload.end", map[string]any{"flow": flowID, "bytes": n, "error": fmt.Sprint(err)})
	}
	remote.CloseWrite()
	if err != nil {
		remote.Close()
		c.Close()
	}
	remote.SetReadDeadline(time.Now().Add(15 * time.Second))
	<-done
}

func tlsServicePort(port uint16) bool {
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
		return true
	}
	return false
}
func (h *systemRelay) dnsTCP(c net.Conn) {
	for {
		c.SetDeadline(time.Now().Add(15 * time.Second))
		var head [2]byte
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(head[:]))
		if size < 12 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		response, err := dohQuery(ctx, query)
		cancel()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(head[:], uint16(len(response)))
		if _, err = c.Write(append(head[:], response...)); err != nil {
			return
		}
	}
}
func (h *systemRelay) udp(c adapter.UDPConn) {
	id := c.ID()
	flowID := flowSequence.Add(1)
	event("udp.open", map[string]any{"flow": flowID, "destination": id.LocalAddress.String(), "port": id.LocalPort})
	defer event("udp.closed", map[string]any{"flow": flowID})
	if id.LocalPort == 53 {
		query := make([]byte, 65535)
		for {
			c.SetReadDeadline(time.Now().Add(15 * time.Second))
			n, err := c.Read(query)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			event("dns.query", map[string]any{"flow": flowID, "question": dnsQuestion(query[:n]), "bytes": n, "transport": "udp"})
			response, err := dohQuery(ctx, query[:n])
			cancel()
			if err == nil {
				_, writeErr := c.Write(response)
				event("dns.response", map[string]any{"flow": flowID, "bytes": len(response), "error": fmt.Sprint(writeErr)})
			} else {
				failure("dns.doh", err, map[string]any{"flow": flowID})
				h.errors.Add(1)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	upstream, err := dialBound(ctx, "udp", net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort))))
	if err != nil {
		h.errors.Add(1)
		failure("udp.dial", err, map[string]any{"flow": flowID, "bound_ifindex": interfaceIndex.Load()})
		return
	}
	if !h.track(upstream) {
		upstream.Close()
		return
	}
	defer h.untrack(upstream)
	remote := upstream.(*net.UDPConn)
	h.relayUDP(c, remote, flowID, id.LocalPort)
}

// Transport logic is independent of dialing, including privileged destination
// ports; tests can exercise the same relay against unprivileged local servers.
func (h *systemRelay) relayUDP(c net.Conn, remote *net.UDPConn, flowID uint64, port uint16) {
	begin := time.Now()
	stats := &udpCounters{}
	defer func() { event("udp.summary", stats.fields(flowID, begin)) }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			remote.SetReadDeadline(time.Now().Add(90 * time.Second))
			n, e := remote.Read(b)
			if e != nil {
				failure("udp.remote_read", e, stats.fields(flowID, begin))
				c.Close()
				return
			}
			if stats.fakeSent.Load() && injectedVoiceReply(b[:n]) || port == 443 && injectedQUICEcho(b[:n]) {
				stats.ignoredFakes.Add(1)
				continue
			}
			if stats.downPackets.Add(1) == 1 {
				event("udp.first_reply", map[string]any{"flow": flowID, "bytes": n})
			}
			stats.downBytes.Add(uint64(n))
			stats.lastDown.Store(time.Now().UnixNano())
			if rtpLike(b[:n]) {
				stats.rtpDown.Add(1)
			}
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, e = c.Write(b[:n]); e != nil {
				failure("udp.client_write", e, stats.fields(flowID, begin))
				c.Close()
				return
			}
		}
	}()
	b := make([]byte, 65535)
	policy := voiceUDPPolicy{}
	quic := quicUDPPolicy{}
	lastProgress := begin
	for {
		c.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, e := c.Read(b)
		if e != nil {
			failure("udp.client_read", e, stats.fields(flowID, begin))
			break
		}
		now := time.Now()
		if stats.upPackets.Load() == 0 {
			event("udp.first_datagram", map[string]any{"flow": flowID, "bytes": n, "recognized_voice": voicePacket(b[:n]), "voice_port": voicePort(port)})
		}
		remote.SetWriteDeadline(now.Add(10 * time.Second))
		if port == 443 && quic.before(now, b[:n]) {
			event("quic.fakes.begin", map[string]any{"flow": flowID, "count": 6, "payload_bytes": len(flowsealQUICFake), "ttl": "socket-default", "burst": quic.bursts})
			sent, fakeErr := sendVoiceFakes(remote, flowsealQUICFake, 6)
			h.quicFakes.Add(uint64(sent))
			if fakeErr != nil {
				failure("quic.fakes", fakeErr, map[string]any{"flow": flowID, "sent": sent})
				h.errors.Add(1)
			}
		}
		if voicePort(port) {
			payload, profile, reason := policy.before(now, b[:n], lastTime(stats.lastDown.Load()))
			if payload != nil {
				stats.fakeSent.Store(true)
				event("voice.fakes.begin", map[string]any{"flow": flowID, "count": 6, "profile": profile, "payload_bytes": len(payload), "ttl": "socket-default", "reason": reason})
				sent, fakeErr := sendVoiceFakes(remote, payload, 6)
				h.fakeCount.Add(uint64(sent))
				if fakeErr != nil {
					failure("voice.fakes", fakeErr, map[string]any{"flow": flowID, "sent": sent})
					h.errors.Add(1)
				}
			}
		}
		if _, e = remote.Write(b[:n]); e != nil {
			failure("udp.remote_write", e, stats.fields(flowID, begin))
			h.errors.Add(1)
			break
		}
		stats.upPackets.Add(1)
		stats.upBytes.Add(uint64(n))
		stats.lastUp.Store(now.UnixNano())
		if rtpLike(b[:n]) {
			stats.rtpUp.Add(1)
		}
		if (policy.known || quic.known) && now.Sub(lastProgress) >= 5*time.Second {
			name := "voice.progress"
			if quic.known {
				name = "quic.progress"
			}
			event(name, stats.fields(flowID, begin))
			lastProgress = now
		}
	}
	remote.Close()
	<-done
}

func voicePort(port uint16) bool { return port >= 19294 && port <= 19344 || port >= 50000 }

// Limit fake packets to recognizable voice discovery, STUN or Discord RTP data.
func voicePacket(b []byte) bool {
	if discordDiscovery(b) {
		return true
	}
	if stunPacket(b) {
		return true
	}
	return len(b) >= 12 && b[0]&0xc0 == 0x80 && b[1]&0x7f == 0x78
}

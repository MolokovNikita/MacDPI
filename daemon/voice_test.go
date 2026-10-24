package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/net/ipv4"
	"net"
	"testing"
	"time"
)

func discoveryFixture() []byte {
	b := make([]byte, 74)
	binary.BigEndian.PutUint16(b, 1)
	binary.BigEndian.PutUint16(b[2:], 70)
	return b
}
func TestVoiceDetectionAfterLatencyAndBoundedFallback(t *testing.T) {
	start := time.Now()
	p := voiceUDPPolicy{}
	if data, _, _ := p.before(start, make([]byte, 8), time.Time{}); data != nil {
		t.Fatal("latency ping mistaken for media handshake")
	}
	data, profile, _ := p.before(start.Add(time.Second), discoveryFixture(), start)
	if profile != "flowseal-quic" || !bytes.Equal(data, flowsealVoiceFake) || len(data) != 1200 {
		t.Fatal("Flowseal pattern not sent after earlier latency ping")
	}
	if data, _, _ := p.before(start.Add(1100*time.Millisecond), discoveryFixture(), start); data != nil {
		t.Fatal("setup burst not rate limited")
	}
	// Repeated discovery must also reach the fallback, instead of restarting it forever.
	data, profile, reason := p.before(start.Add(8*time.Second), discoveryFixture(), start.Add(time.Second))
	if profile != "stun" || reason != "replies-stalled" || !bytes.Equal(data, stunVoiceFake) {
		t.Fatal("silent voice flow not switched to STUN")
	}
	media := []byte{0x80, 0x78, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 1000; i++ {
		if data, _, _ := p.before(start.Add(20*time.Second), media, start); data != nil {
			t.Fatal("RTP stream flooded with fakes")
		}
	}
}
func TestVoiceHealthyFlowDoesNotSwitch(t *testing.T) {
	now := time.Now()
	p := voiceUDPPolicy{}
	p.before(now, discoveryFixture(), now)
	media := append([]byte{0x80, 0x78}, make([]byte, 30)...)
	for i := 1; i < 100; i++ {
		current := now.Add(time.Duration(i) * time.Second)
		if data, _, _ := p.before(current, media, current.Add(-time.Second)); data != nil {
			t.Fatal("healthy flow got a fallback")
		}
	}
}
func TestFakeSTUNReplyIsNotForwarded(t *testing.T) {
	reply := append([]byte(nil), stunVoiceFake...)
	reply[0] = 1
	reply[1] = 1
	if !injectedVoiceReply(reply) || !injectedVoiceReply(flowsealVoiceFake) {
		t.Fatal("injected reply not recognized")
	}
	reply[8] ^= 1
	if injectedVoiceReply(reply) {
		t.Fatal("unrelated STUN transaction dropped")
	}
}
func TestUDPVoiceSurvivesPast15SecondsOnSameSocket(t *testing.T) {
	var destination *net.UDPConn
	var err error
	for port := 50000; port < 50100; port++ {
		destination, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	packetConn := ipv4.NewPacketConn(destination)
	if err := packetConn.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		t.Fatal(err)
	}
	serverErrors := make(chan string, 1)
	go func() {
		b := make([]byte, 65535)
		port := ""
		normalTTL := 0
		for {
			n, control, peer, e := packetConn.ReadFrom(b)
			if e != nil {
				return
			}
			if port == "" {
				port = peer.String()
				normalTTL = control.TTL
			}
			if peer.String() != port || control.TTL != normalTTL {
				select {
				case serverErrors <- "UDP source port or TTL changed":
				default:
				}
			}
			packetConn.WriteTo(b[:n], nil, peer)
		}
	}()
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	st, _ := findPreset("tlsrec-split")
	relay := newSystemRelay(st)
	defer relay.close()
	id := targetID(destination.LocalAddr().String())
	relay.HandleUDP(&udpFlow{UDPConn: socket, peer: app.LocalAddr().(*net.UDPAddr), id: id})
	started := time.Now()
	for seq := 0; time.Since(started) < 18*time.Second; seq++ {
		payload := discoveryFixture()
		if seq > 0 {
			payload = make([]byte, 140)
			payload[0] = 0x80
			payload[1] = 0x78
			binary.BigEndian.PutUint32(payload[4:], uint32(seq))
		}
		app.SetDeadline(time.Now().Add(time.Second))
		if _, e := app.WriteToUDP(payload, socket.LocalAddr().(*net.UDPAddr)); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, 1500)
		n, _, e := app.ReadFromUDP(reply)
		if e != nil || !bytes.Equal(payload, reply[:n]) {
			t.Fatal("voice datagram changed or lost", seq, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
	if relay.fakeCount.Load() != 6 {
		t.Fatal("healthy long stream got repeated fakes", relay.fakeCount.Load())
	}
}

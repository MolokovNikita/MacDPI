package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func wireFixture() wireHandshake {
	return wireHandshake{key: wireTuple{local: [4]byte{192, 0, 2, 1}, remote: [4]byte{198, 51, 100, 2}, localPort: 42000, remotePort: 443},
		ethernet: [14]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0}, seq: 12345678, ack: 87654321, window: 65535, timestamp: 12, peerTimestamp: 13, hasTimestamp: true, ready: true}
}

func TestPacketChecksumsAndSequenceOverlap(t *testing.T) {
	first := hello(t)
	for _, mode := range []string{"seqovl", "seqovl-google", "badseq"} {
		h := wireFixture()
		original := append([]byte(nil), first...)
		frames, err := makeDesyncFrames(h, first, mode)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if mode == "badseq" {
			want = 6
		}
		if len(frames) != want {
			t.Fatal("wrong repeat count")
		}
		for _, frame := range frames {
			ip := frame[14:34]
			tcp := frame[34:]
			if checksum.Checksum(ip, 0) != 0xffff {
				t.Fatal("invalid IPv4 checksum")
			}
			pseudo := make([]byte, 12)
			copy(pseudo, ip[12:20])
			pseudo[9] = 6
			binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
			if checksum.Checksum(tcp, checksum.Checksum(pseudo, 0)) != 0xffff {
				t.Fatal("invalid TCP checksum")
			}
			if binary.BigEndian.Uint16(ip[2:]) != uint16(len(frame)-14) {
				t.Fatal("wrong IP length")
			}
			payload := tcp[int(tcp[12]>>4)*4:]
			seq := binary.BigEndian.Uint32(tcp[4:])
			if mode == "seqovl" || mode == "seqovl-google" {
				pattern, overlap := flowseal4pda, 568
				if mode == "seqovl-google" {
					pattern, overlap = flowsealGoogle, 681
				}
				if seq != h.seq-uint32(overlap) || len(payload) != overlap+1 || payload[overlap] != first[0] {
					t.Fatal("incorrect overlap geometry", mode)
				}
				if !bytes.Equal(payload[:min(overlap, len(pattern))], pattern[:min(overlap, len(pattern))]) {
					t.Fatal("fake prefix is not the Flowseal pattern", mode)
				}
				// Only the first legitimate byte falls inside the server's receive window.
				accepted := payload[int(h.seq-seq):]
				if !bytes.Equal(accepted, first[:1]) {
					t.Fatal("fake prefix would enter TLS stream")
				}
			} else {
				if seq+uint32(len(payload)) >= h.seq || binary.BigEndian.Uint32(tcp[8:]) != h.ack-66000 {
					t.Fatal("fake must remain outside sequence window")
				}
			}
		}
		if !bytes.Equal(original, first) {
			t.Fatal("original ClientHello changed")
		}
	}
}

func TestCaptureFilterExcludesApplicationData(t *testing.T) {
	vm, err := bpf.NewVM(packetCaptureProgram())
	if err != nil {
		t.Fatal(err)
	}
	h := wireFixture()
	frame, _ := buildWirePacket(h, bytes.Repeat([]byte("private"), 20), h.seq, h.ack)
	if n, err := vm.Run(frame); err != nil || n != 0 {
		t.Fatal("data packet captured", n, err)
	}
	frame[47] = 2 // SYN with TFO payload: snap length must still end at TCP header.
	n, err := vm.Run(frame)
	if err != nil || n != 66 {
		t.Fatal("SYN capture included payload or lost headers", n, err)
	}
	frame[47] = 0x12
	if n, _ := vm.Run(frame); n != 66 {
		t.Fatal("SYNACK not captured")
	}
	frame[23] = 17
	if n, _ := vm.Run(frame); n != 0 {
		t.Fatal("UDP captured")
	}
	frame[23] = 6
	frame[20] = 0x20
	if n, _ := vm.Run(frame); n != 0 {
		t.Fatal("fragment captured")
	}
	for i := 0; i < 54; i++ {
		if _, err := vm.Run(frame[:i]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHandshakeObservationAndBPFRecords(t *testing.T) {
	h := wireFixture()
	syn, _ := buildWirePacket(h, nil, h.seq-1, 0)
	syn[47] = 2
	peer := h
	peer.key.local, peer.key.remote = h.key.remote, h.key.local
	peer.key.localPort, peer.key.remotePort = h.key.remotePort, h.key.localPort
	ack, _ := buildWirePacket(peer, nil, h.ack-1, h.seq)
	ack[47] = 0x12
	engine := &packetEngine{source: net.IP(h.key.local[:]), handshakes: map[wireTuple]timedHandshake{}}
	engine.observe(syn)
	engine.observe(ack)
	if got := engine.handshakes[h.key]; !got.ready || got.seq != h.seq || got.ack != h.ack {
		t.Fatal("SYN/SYNACK correlation failed", got)
	}
	record := func(frame []byte) []byte {
		b := make([]byte, (20+len(frame)+3)&^3)
		binary.LittleEndian.PutUint32(b[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint16(b[16:], 20)
		copy(b[20:], frame)
		return b
	}
	stream := append(record(syn), record(ack)...)
	count := 0
	walkBPFRecords(stream, func([]byte) { count++ })
	if count != 2 {
		t.Fatal("BPF alignment failed", count)
	}
	for i := range stream {
		walkBPFRecords(stream[:i], func([]byte) {})
	}
	malformed := record(syn)
	binary.LittleEndian.PutUint32(malformed[8:], ^uint32(0))
	walkBPFRecords(malformed, func([]byte) { t.Fatal("invalid capture length accepted") })
}

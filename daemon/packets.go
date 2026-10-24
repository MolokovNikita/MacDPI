package main

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"net"
)

// Protocol test patterns from the pinned Flowseal reference; see SOURCE.json.
//
//go:embed patterns/tls_clienthello_4pda_to.bin
var flowseal4pda []byte

//go:embed patterns/tls_clienthello_www_google_com.bin
var flowsealGoogle []byte

type wireTuple struct {
	local, remote         [4]byte
	localPort, remotePort uint16
}
type wireHandshake struct {
	key                      wireTuple
	ethernet                 [14]byte
	seq, ack                 uint32
	window                   uint16
	timestamp, peerTimestamp uint32
	hasTimestamp, ready      bool
}

func tcpTimestamp(options []byte) (uint32, bool) {
	for len(options) > 0 {
		switch options[0] {
		case 0:
			return 0, false
		case 1:
			options = options[1:]
			continue
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			return 0, false
		}
		if options[0] == 8 && options[1] == 10 {
			return binary.BigEndian.Uint32(options[2:6]), true
		}
		options = options[int(options[1]):]
	}
	return 0, false
}

// Only Ethernet/IPv4 handshake headers are retained; application payload is ignored.
func parseWireSYN(frame []byte, source net.IP) (wireHandshake, bool, bool) {
	var h wireHandshake
	if len(frame) < 54 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return h, false, false
	}
	ip := frame[14:]
	ihl := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return h, false, false
	}
	tcp := ip[ihl:]
	thl := int(tcp[12]>>4) * 4
	if thl < 20 || len(tcp) < thl || tcp[13]&2 == 0 || tcp[13]&5 != 0 {
		return h, false, false
	}
	outgoing := net.IP(ip[12:16]).Equal(source)
	if !outgoing && !net.IP(ip[16:20]).Equal(source) {
		return h, false, false
	}
	if outgoing {
		if tcp[13]&16 != 0 {
			return h, false, false
		}
		copy(h.key.local[:], ip[12:16])
		copy(h.key.remote[:], ip[16:20])
		h.key.localPort = binary.BigEndian.Uint16(tcp)
		h.key.remotePort = binary.BigEndian.Uint16(tcp[2:])
		copy(h.ethernet[:], frame[:14])
		h.seq = binary.BigEndian.Uint32(tcp[4:]) + 1
		h.window = binary.BigEndian.Uint16(tcp[14:])
		h.timestamp, h.hasTimestamp = tcpTimestamp(tcp[20:thl])
	} else {
		if tcp[13]&16 == 0 {
			return h, false, false
		}
		copy(h.key.local[:], ip[16:20])
		copy(h.key.remote[:], ip[12:16])
		h.key.localPort = binary.BigEndian.Uint16(tcp[2:])
		h.key.remotePort = binary.BigEndian.Uint16(tcp)
		h.seq = binary.BigEndian.Uint32(tcp[8:])
		h.ack = binary.BigEndian.Uint32(tcp[4:]) + 1
		h.peerTimestamp, h.hasTimestamp = tcpTimestamp(tcp[20:thl])
		h.ready = true
	}
	return h, outgoing, true
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildWirePacket(h wireHandshake, payload []byte, seq, ack uint32) ([]byte, error) {
	if !h.ready || len(payload) > 1400 {
		return nil, errors.New("invalid packet handshake or payload size")
	}
	options := []byte{}
	if h.hasTimestamp {
		options = make([]byte, 12)
		copy(options, []byte{1, 1, 8, 10})
		binary.BigEndian.PutUint32(options[4:], h.timestamp)
		binary.BigEndian.PutUint32(options[8:], h.peerTimestamp)
	}
	tcpLen := 20 + len(options) + len(payload)
	frame := make([]byte, 14+20+tcpLen)
	copy(frame, h.ethernet[:])
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+tcpLen))
	ip[6] = 0x40
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], h.key.local[:])
	copy(ip[16:20], h.key.remote[:])
	binary.BigEndian.PutUint16(ip[10:], internetChecksum(ip))
	tcp := frame[34:]
	binary.BigEndian.PutUint16(tcp, h.key.localPort)
	binary.BigEndian.PutUint16(tcp[2:], h.key.remotePort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte((20+len(options))/4) << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:], h.window)
	copy(tcp[20:], options)
	copy(tcp[20+len(options):], payload)
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo, h.key.local[:])
	copy(pseudo[4:], h.key.remote[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], internetChecksum(pseudo))
	return frame, nil
}

func makeDesyncFrames(h wireHandshake, first []byte, mode string) ([][]byte, error) {
	if !isTLSHello(first) {
		return nil, errors.New("packet strategy requires ClientHello")
	}
	switch mode {
	case "seqovl":
		return sequenceOverlap(h, first, flowseal4pda, 568)
	case "seqovl-google":
		return sequenceOverlap(h, first, flowsealGoogle, len(flowsealGoogle))
	case "badseq":
		packet, err := buildWirePacket(h, flowsealGoogle, h.seq-10000, h.ack-66000)
		frames := make([][]byte, 6)
		for i := range frames {
			frames[i] = packet
		}
		return frames, err
	default:
		return nil, errors.New("unknown packet strategy")
	}
}

// sequenceOverlap sends a fake ClientHello that ends right where the real stream
// begins. DPI reads the fake (and its SNI); the server already acknowledged that
// sequence range, trims it and keeps only the first genuine byte.
func sequenceOverlap(h wireHandshake, first, pattern []byte, overlap int) ([][]byte, error) {
	payload := make([]byte, overlap+1)
	for i := range overlap {
		payload[i] = pattern[i%len(pattern)]
	}
	payload[overlap] = first[0]
	packet, err := buildWirePacket(h, payload, h.seq-uint32(overlap), h.ack)
	return [][]byte{packet}, err
}

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// A real TCP receiver must trim the fake overlap and see the exact ClientHello.
func TestTCPReceiverRejectsFakePrefixAndDuplicateFirstByte(t *testing.T) {
	for _, mode := range []string{"seqovl", "seqovl-google"} {
		t.Run(mode, func(t *testing.T) { receiveThroughOverlap(t, mode) })
	}
}

func receiveThroughOverlap(t *testing.T, mode string) {
	link := channel.New(128, 1500, "")
	receiver := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer func() { link.Close(); receiver.Close(); receiver.Wait() }()
	if err := receiver.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	h := wireFixture()
	addr := tcpip.AddrFrom4(h.key.remote)
	if err := receiver.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	receiver.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	listener, err := gonet.ListenTCP(receiver, tcpip.FullAddress{NIC: 1, Addr: addr, Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	first := hello(t)
	result := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			result <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, len(first))
		_, e = io.ReadFull(c, b)
		if e == nil && !bytes.Equal(b, first) {
			e = io.ErrUnexpectedEOF
		}
		result <- e
	}()
	inject := func(frame []byte) {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame[14:])})
		link.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}
	withFlags := func(frame []byte, flags byte) []byte {
		frame[47] = flags
		tcp := frame[34:]
		tcp[16] = 0
		tcp[17] = 0
		pseudo := make([]byte, 12+len(tcp))
		copy(pseudo, frame[26:34])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
		copy(pseudo[12:], tcp)
		binary.BigEndian.PutUint16(tcp[16:], internetChecksum(pseudo))
		return frame
	}
	syn, _ := buildWirePacket(h, nil, h.seq-1, 0)
	inject(withFlags(syn, 2))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response := link.ReadContext(ctx)
	if response == nil {
		t.Fatal("no SYNACK")
	}
	view := response.ToView()
	frame := append(append([]byte(nil), h.ethernet[:]...), view.AsSlice()...)
	view.Release()
	response.DecRef()
	observed, _, ok := parseWireSYN(frame, h.key.local[:])
	if !ok || !observed.ready {
		t.Fatal("bad SYNACK")
	}
	h.ack = observed.ack
	h.peerTimestamp = observed.peerTimestamp
	h.hasTimestamp = h.hasTimestamp && observed.hasTimestamp
	ack, _ := buildWirePacket(h, nil, h.seq, h.ack)
	inject(withFlags(ack, 16))
	fake, err := makeDesyncFrames(h, first, mode)
	if err != nil {
		t.Fatal(err)
	}
	inject(fake[0])
	// The kernel still sends its own first byte: the receiver must discard that duplicate.
	for pos := 0; pos < len(first); pos += 1000 {
		genuine, e := buildWirePacket(h, first[pos:min(pos+1000, len(first))], h.seq+uint32(pos), h.ack)
		if e != nil {
			t.Fatal(e)
		}
		inject(genuine)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("receiver stream corrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("receiver timed out")
	}
}

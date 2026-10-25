package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type tcpFlow struct {
	net.Conn
	id stack.TransportEndpointID
}

func (c *tcpFlow) ID() stack.TransportEndpointID { return c.id }

type udpFlow struct {
	*net.UDPConn
	peer *net.UDPAddr
	id   stack.TransportEndpointID
}

func (c *udpFlow) ID() stack.TransportEndpointID { return c.id }
func (c *udpFlow) Read(b []byte) (int, error)    { n, _, e := c.ReadFromUDP(b); return n, e }
func (c *udpFlow) Write(b []byte) (int, error)   { return c.WriteToUDP(b, c.peer) }
func targetID(address string) stack.TransportEndpointID {
	host, port, _ := net.SplitHostPort(address)
	p, _ := strconv.Atoi(port)
	return stack.TransportEndpointID{LocalAddress: tcpip.AddrFromSlice(net.ParseIP(host).To4()), LocalPort: uint16(p)}
}
func TestSystemHTTPSRelay(t *testing.T) {
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }))
	defer destination.Close()
	st, _ := findPreset("tlsrec-split")
	h := newSystemRelay(st)
	defer h.close()
	client, flow := net.Pipe()
	defer client.Close()
	h.HandleTCP(&tcpFlow{Conn: flow, id: targetID(destination.Listener.Addr().String())})
	// Self-signed local fixture only.
	secure := tls.Client(client, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	defer secure.Close()
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("voice-and-video"), 10000)
	fmt.Fprintf(secure, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))
	if _, err := secure.Write(payload); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatal("system TCP relay changed payload")
	}
}
func TestSystemUDPVoiceRelay(t *testing.T) {
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
	go func() {
		b := make([]byte, 65535)
		for {
			n, peer, e := destination.ReadFromUDP(b)
			if e != nil {
				return
			}
			// Echo fake datagrams too: the relay must not deliver them to the client.
			destination.WriteToUDP(b[:n], peer)
		}
	}()
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	flow, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	st, _ := findPreset("tlsrec-split")
	h := newSystemRelay(st)
	defer h.close()
	h.targetOnly = true
	h.HandleUDP(&udpFlow{UDPConn: flow, peer: app.LocalAddr().(*net.UDPAddr), id: targetID(destination.LocalAddr().String())})
	for _, size := range []int{8, 20, 74, 900, 1200} {
		data := bytes.Repeat([]byte{byte(size)}, size)
		if size == 20 {
			binary.BigEndian.PutUint16(data, 1)
			binary.BigEndian.PutUint16(data[2:], 0)
			binary.BigEndian.PutUint32(data[4:], 0x2112a442)
		}
		if size == 74 {
			binary.BigEndian.PutUint16(data[:2], 1)
			binary.BigEndian.PutUint16(data[2:4], 70)
		}
		app.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = app.WriteToUDP(data, flow.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 65535)
		n, _, e := app.ReadFromUDP(b)
		if e != nil || !bytes.Equal(data, b[:n]) {
			t.Fatal("UDP changed a datagram", e)
		}
		if size == 20 && h.fakeCount.Load() != 0 {
			t.Fatal("generic STUN received Discord fakes in scoped mode")
		}
	}
	if h.fakeCount.Load() != 6 {
		t.Fatal("voice fake sequence missing")
	}
}

// UDP/443 must pass application datagrams intact while fake replies never
// reach the client. All datagrams must retain one upstream source port.
func TestSystemQUICRelay(t *testing.T) {
	t.Run("all-services", func(t *testing.T) { testQUICRelay(t, false) })
	t.Run("unrelated-scoped", func(t *testing.T) { testQUICRelay(t, true) })
}
func testQUICRelay(t *testing.T, scoped bool) {
	destination, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	ports := make(chan int, 32)
	go func() {
		b := make([]byte, 65535)
		for {
			n, peer, e := destination.ReadFromUDP(b)
			if e != nil {
				return
			}
			ports <- peer.Port
			destination.WriteToUDP(b[:n], peer)
		}
	}()
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	flow, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	st, _ := findPreset("tlsrec-split")
	h := newSystemRelay(st)
	defer h.close()
	h.targetOnly = scoped
	remote, err := net.DialUDP("udp4", nil, destination.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	h.track(remote)
	go h.relayUDP(&udpFlow{UDPConn: flow, peer: app.LocalAddr().(*net.UDPAddr)}, remote, 1, 443)
	initial := append([]byte(nil), flowsealQUICFake...)
	initial[6] ^= 0x37
	stun := make([]byte, 20)
	binary.BigEndian.PutUint32(stun[4:], 0x2112a442)
	packets := [][]byte{initial, append([]byte{0x40}, bytes.Repeat([]byte{0x89}, 1300)...), stun}
	for _, packet := range packets {
		app.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = app.WriteToUDP(packet, flow.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 65535)
		n, _, e := app.ReadFromUDP(b)
		if e != nil || !bytes.Equal(b[:n], packet) {
			t.Fatal("UDP/443 payload changed or fake echo leaked", e)
		}
	}
	wantFakes := uint64(6)
	if scoped {
		wantFakes = 0
	}
	if h.quicFakes.Load() != wantFakes || h.quicCount.Load() != 0 || h.fakeCount.Load() != 0 {
		t.Fatal("wrong QUIC burst or voice path changed", h.quicFakes.Load(), h.fakeCount.Load())
	}
	source := 0
	for i := 0; i < len(packets)+int(wantFakes); i++ {
		select {
		case port := <-ports:
			if source == 0 {
				source = port
			}
			if port != source {
				t.Fatal("upstream source port changed")
			}
		case <-time.After(time.Second):
			t.Fatal("missing datagram")
		}
	}
}

func TestVoiceClassification(t *testing.T) {
	if voicePacket(make([]byte, 74)) {
		t.Fatal("generic UDP classified as Discord")
	}
	stun := make([]byte, 20)
	binary.BigEndian.PutUint32(stun[4:8], 0x2112a442)
	if !voicePacket(stun) {
		t.Fatal("STUN not detected")
	}
	if !voicePacket(append([]byte{0x80, 0x78}, make([]byte, 10)...)) {
		t.Fatal("Discord RTP not detected")
	}
}

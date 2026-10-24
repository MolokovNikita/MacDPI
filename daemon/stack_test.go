package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestIPStackHTTPSAndUDP(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var localIP net.IP
	for _, address := range addresses {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			localIP = ipnet.IP.To4()
			break
		}
	}
	if localIP == nil {
		t.Skip("requires an assigned local IPv4 address")
	}
	st, _ := findPreset("tlsrec-split")
	relay := newSystemRelay(st)
	serverLink := channel.New(128, 1500, "")
	serverStack, err := core.CreateStack(&core.Config{LinkEndpoint: serverLink, TransportHandler: relay})
	if err != nil {
		t.Fatal(err)
	}
	// Loopback destinations are used only for isolated test fixtures.
	allow := tcpip.AllowExternalLoopbackTrafficOption(true)
	if e := serverStack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &allow); e != nil {
		t.Fatal(e)
	}
	clientLink := channel.New(128, 1500, "")
	clientStack := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true})}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	if e := clientStack.CreateNIC(1, clientLink); e != nil {
		t.Fatal(e)
	}
	if e := clientStack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{198, 18, 1, 10}).WithPrefix()}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	clientStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	bridge := func(from, to *channel.Endpoint) {
		for {
			packet := from.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(view.AsSlice())})
			view.Release()
			to.InjectInbound(ipv4.ProtocolNumber, inbound)
			inbound.DecRef()
			packet.DecRef()
		}
	}
	go bridge(clientLink, serverLink)
	go bridge(serverLink, clientLink)
	defer func() {
		relay.close()
		cancel()
		clientLink.Close()
		serverLink.Close()
		clientStack.Close()
		serverStack.Close()
		clientStack.Wait()
		serverStack.Wait()
	}()
	remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "IP stack TLS OK") }))
	remote.Listener.Close()
	remote.Listener, err = net.Listen("tcp", net.JoinHostPort(localIP.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	remote.StartTLS()
	defer remote.Close()
	_, port, _ := net.SplitHostPort(remote.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	dialContext, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	conn, err := gonet.DialContextTCP(dialContext, clientStack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localIP), Port: uint16(p)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed fixture only.
	secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"})
	defer secure.Close()
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(secure, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	response, err := io.ReadAll(secure)
	if err != nil || !bytes.Contains(response, []byte("IP stack TLS OK")) {
		t.Fatalf("IP/TCP/TLS relay failed: %s %v", response, err)
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 1500)
		n, peer, e := echo.ReadFromUDP(b)
		if e == nil {
			echo.WriteToUDP(b[:n], peer)
		}
	}()
	udpConn, e := gonet.DialUDP(clientStack, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localIP), Port: uint16(echo.LocalAddr().(*net.UDPAddr).Port)}, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatal(e)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	udpConn.Write([]byte("IP stack UDP OK"))
	data := make([]byte, 100)
	n, err := udpConn.Read(data)
	if err != nil || string(data[:n]) != "IP stack UDP OK" {
		t.Fatal("IP/UDP relay failed", err)
	}
}

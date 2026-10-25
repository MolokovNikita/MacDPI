package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Optional real CDN check: certificate and ECH are verified by Go TLS. Only a
// public default avatar is requested; no Discord account/token is needed.
func TestPhysicalDiscordECHCDN(t *testing.T) {
	ifaceName := os.Getenv("MACDPI_CDN_MATRIX")
	if ifaceName == "" {
		t.Skip("set MACDPI_CDN_MATRIX to physical interface; root required for BPF")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	if err = configureBoundInterface(iface); err != nil {
		t.Fatal(err)
	}
	defer func() { interfaceIndex.Store(0); boundSources.Store(nil) }()
	engine, err := openPacketEngine(ifaceName, boundSources.Load().IPv4)
	if err != nil {
		t.Fatal(err)
	}
	activePacketEngine.Store(engine)
	defer func() { activePacketEngine.Store(nil); engine.close() }()
	name, _ := dnsmessage.NewName("cdn.discordapp.com.")
	query := func(kind dnsmessage.Type) ([]byte, []byte) {
		q, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 175, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}).Pack()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		raw, e := dohQuery(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		return q, raw
	}
	aq, ar := query(dnsmessage.TypeA)
	_, hr := query(dnsmessage.TypeHTTPS)
	var msg dnsmessage.Message
	if err = msg.Unpack(hr); err != nil {
		t.Fatal(err)
	}
	var ech []byte
	for _, rr := range msg.Answers {
		if body, ok := rr.Body.(*dnsmessage.HTTPSResource); ok {
			if value, ok := body.GetParam(dnsmessage.SVCParamKey(5)); ok {
				ech = value
			}
		}
	}
	if len(ech) == 0 {
		t.Fatal("CDN did not advertise ECH")
	}
	var address string
	msg.Unpack(ar)
	for _, rr := range msg.Answers {
		if body, ok := rr.Body.(*dnsmessage.AResource); ok {
			address = net.JoinHostPort(net.IP(body.A[:]).String(), "443")
			break
		}
	}
	if override := os.Getenv("MACDPI_CDN_ADDRESS"); override != "" {
		address = override
	}
	if address == "" {
		t.Fatal("missing A record")
	}
	for _, adaptive := range []bool{false, true} {
		label := "baseline"
		if adaptive {
			label = "dns-hint-adaptive"
		}
		t.Run(label, func(t *testing.T) {
			st, _ := findPreset("multisplit")
			h := newSystemRelay(st)
			h.adaptive = adaptive
			h.targetOnly = adaptive
			h.policy.observeDNS(aq, ar)
			ipText, _, _ := net.SplitHostPort(address)
			var fixed [4]byte
			copy(fixed[:], net.ParseIP(ipText).To4())
			fq, fr := dnsHintFixture(t, "cdn.discordapp.com", fixed, 60)
			h.policy.observeDNS(fq, fr)
			defer h.close()
			app, flow := net.Pipe()
			defer app.Close()
			h.HandleTCP(&tcpFlow{Conn: flow, id: targetID(address)})
			secure := tls.Client(app, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "cdn.discordapp.com", EncryptedClientHelloConfigList: ech, NextProtos: []string{"http/1.1"}})
			defer secure.Close()
			secure.SetDeadline(time.Now().Add(12 * time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Logf("%s TLS error: %v", label, err)
				if adaptive {
					t.Fatal(err)
				}
				return
			}

			var total int64
			reader := bufio.NewReader(secure)
			for i := 0; i < 64; i++ {
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://cdn.discordapp.com/embed/avatars/0.png", nil)
				if err = req.Write(secure); err != nil {
					break
				}
				var response *http.Response
				response, err = http.ReadResponse(reader, req)
				if err != nil {
					break
				}
				var n int64
				n, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
				response.Body.Close()
				total += n
				if err != nil || response.StatusCode != 200 {
					break
				}
			}
			t.Logf("host=cdn.discordapp.com address=%s ECH=%v total_bytes=%d error=%v", address, secure.ConnectionState().ECHAccepted, total, err)
			if adaptive && (err != nil || total < 65536 || !secure.ConnectionState().ECHAccepted) {
				t.Fatal("CDN repeated load/ECH failed")
			}

			if adaptive {
				h.policy.Lock()
				learned := h.policy.learned["cdn.discordapp.com|"+address]
				h.policy.Unlock()
				t.Logf("learned policy: %s", learned.name)
			}
		})
	}
}

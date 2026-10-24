package main

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoHValidation(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-id", "wrong-name", "wrong-type", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				var q dnsmessage.Message
				if err := q.Unpack(raw); err != nil {
					t.Error(err)
					return
				}
				q.Response = true
				q.RecursionAvailable = true
				switch mode {
				case "wrong-id":
					q.ID++
				case "wrong-name":
					q.Questions[0].Name, _ = dnsmessage.NewName("other.example.")
				}
				q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
				data, _ := q.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				if mode == "wrong-type" {
					w.Header().Set("Content-Type", "text/html")
				}
				if mode == "oversized" {
					data = make([]byte, 65536)
				}
				w.Write(data)
			}))
			defer server.Close()
			old := dohServers
			dohServers = []string{server.URL}
			defer func() { dohServers = old }()
			ip, err := lookupIP4(context.Background(), "example.com")
			if mode == "valid" {
				if err != nil || ip.String() != "192.0.2.1" {
					t.Fatal(ip, err)
				}
			} else if err == nil {
				t.Fatal("invalid response accepted", mode)
			}
		})
	}
}

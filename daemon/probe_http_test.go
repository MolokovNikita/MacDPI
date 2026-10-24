package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeReadsHTTP1AndHTTP2Bodies(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/app" || r.Host != "discord.com" {
					t.Error("wrong probe request")
				}
				io.WriteString(w, "complete page")
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{protocol}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := probeResponse(ctx, conn, "discord.com")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "complete page" {
				t.Fatal("incomplete HTTPS probe", err)
			}
			if protocol == "h2" && response.ProtoMajor != 2 {
				t.Fatal("HTTP/2 not negotiated")
			}
		})
	}
}

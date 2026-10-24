package main

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallerQuoting(t *testing.T) {
	value := "file with 'quotes' and $(echo injection) `echo other`"
	output, err := exec.Command("/bin/sh", "-c", "printf %s "+shellQuote(value)).Output()
	if err != nil || string(output) != value {
		t.Fatal("shell quoting changed value", err, string(output))
	}
	script, err := installationScript(501)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-n")
	command.Stdin = strings.NewReader(script)
	if err = command.Run(); err != nil {
		t.Fatal("installer syntax", err)
	}
	if _, err = installationScript(0); err == nil {
		t.Fatal("installer accepted root as GUI owner")
	}
}
func TestControlRejectsInvalidOwnerAndStrategy(t *testing.T) {
	c := &systemController{}
	if err := c.start(1, "auto"); err == nil {
		t.Fatal("accepted launchd as owner")
	}
	if err := c.start(os.Getpid(), "invalid"); err == nil {
		t.Fatal("accepted invalid strategy")
	}
	if err := runService(0); err == nil {
		t.Fatal("service accepted invalid UID")
	}
}
func TestUnixPeerCredentials(t *testing.T) {
	listener, err := net.Listen("unix", t.TempDir()+"/peer.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	if !peerIs(client, uint32(os.Getuid())) || !peerIs(server, uint32(os.Getuid())) {
		t.Fatal("valid peer rejected")
	}
	if os.Getuid() != 0 && peerIs(client, 0) {
		t.Fatal("unprivileged server accepted as root")
	}
}

package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func fixtureSources(t *testing.T) {
	t.Helper()
	previous, oldIndex, oldReader := boundSources.Load(), interfaceIndex.Load(), interfaceAddresses
	t.Cleanup(func() { boundSources.Store(previous); interfaceIndex.Store(oldIndex); interfaceAddresses = oldReader })
	interfaceAddresses = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd01::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	if err := configureBoundInterface(&net.Interface{Name: "en-test", Index: 14}); err != nil {
		t.Fatal(err)
	}
}
func TestBoundDialerSelectsPhysicalSource(t *testing.T) {
	fixtureSources(t)
	for _, network := range []string{"tcp", "udp"} {
		dialer, err := boundDialer(network, "8.8.8.8:443")
		if err != nil {
			t.Fatal(err)
		}
		if dialer.LocalAddr == nil || dialer.LocalAddr.String() != "192.0.2.10:0" {
			t.Fatal("source address left to tunnel route selection", dialer.LocalAddr)
		}
	}
	if _, err := boundDialer("tcp", "[2606:4700:4700::1111]:443"); err == nil {
		t.Fatal("ULA was accepted as a public IPv6 source")
	}
}
func TestBoundDialerUsesGlobalIPv6(t *testing.T) {
	fixtureSources(t)
	interfaceAddresses = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	if err := configureBoundInterface(&net.Interface{Name: "en-test", Index: 14}); err != nil {
		t.Fatal(err)
	}
	dialer, err := boundDialer("tcp", "[2606:4700:4700::1111]:443")
	if err != nil {
		t.Fatal(err)
	}
	if dialer.LocalAddr.String() != "[2001:db8::1]:0" {
		t.Fatal("wrong IPv6 source", dialer.LocalAddr)
	}
}
func TestUnboundDialStillSupportsLocalhost(t *testing.T) {
	fixtureSources(t)
	interfaceIndex.Store(0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dialBound(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
}
func TestInterfaceReadFailurePreservesBinding(t *testing.T) {
	fixtureSources(t)
	previous := boundSources.Load()
	interfaceAddresses = func(*net.Interface) ([]net.Addr, error) { return nil, errors.New("interface unavailable") }
	if err := configureBoundInterface(&net.Interface{Name: "other", Index: 99}); err == nil {
		t.Fatal("address read failure hidden")
	}
	if boundSources.Load() != previous || interfaceIndex.Load() != 14 {
		t.Fatal("valid binding lost on refresh failure")
	}
}

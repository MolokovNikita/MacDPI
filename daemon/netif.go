package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var interfaceIndex atomic.Int32

type interfaceSources struct {
	Name       string
	IPv4, IPv6 net.IP
}

var boundSources atomic.Pointer[interfaceSources]
var interfaceAddresses = func(iface *net.Interface) ([]net.Addr, error) { return iface.Addrs() }

func configureBoundInterface(iface *net.Interface) error {
	addresses, err := interfaceAddresses(iface)
	if err != nil {
		return err
	}
	sources := &interfaceSources{Name: iface.Name}
	for _, address := range addresses {
		ip, _, e := net.ParseCIDR(address.String())
		if e != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil && sources.IPv4 == nil {
			sources.IPv4 = append(net.IP(nil), v4...)
		}
		if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && sources.IPv6 == nil {
			sources.IPv6 = append(net.IP(nil), ip...)
		}
	}
	if sources.IPv4 == nil {
		return fmt.Errorf("На интерфейсе %s нет физического IPv4-адреса", iface.Name)
	}
	previous := boundSources.Load()
	if previous != nil && previous.Name == sources.Name && previous.IPv4.Equal(sources.IPv4) && previous.IPv6.Equal(sources.IPv6) && interfaceIndex.Load() == int32(iface.Index) {
		return nil
	}
	boundSources.Store(sources)
	interfaceIndex.Store(int32(iface.Index))
	event("network.bound_interface", map[string]any{"interface": iface.Name, "index": iface.Index, "source_ipv4": sources.IPv4.String(), "source_ipv6": sources.IPv6.String()})
	return nil
}
func bindControl(network, address string, c syscall.RawConn) error {
	index := int(interfaceIndex.Load())
	if index == 0 {
		return nil
	}
	var inner error
	err := c.Control(func(fd uintptr) {
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if strings.HasSuffix(network, "6") {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		inner = unix.SetsockoptInt(int(fd), level, option, index)
	})
	if err != nil {
		return err
	}
	return inner
}
func boundDialer(network, address string) (*net.Dialer, error) {
	dialer := &net.Dialer{Control: bindControl, Timeout: 10 * time.Second}
	if interfaceIndex.Load() == 0 {
		return dialer, nil
	}
	sources := boundSources.Load()
	if sources == nil {
		return dialer, nil
	}
	ip := sources.IPv4
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if remote := net.ParseIP(host); remote != nil && remote.To4() == nil {
		ip = sources.IPv6
	}
	if ip == nil {
		return nil, fmt.Errorf("На физическом интерфейсе %s нет маршрутизируемого адреса для %s", sources.Name, address)
	}
	switch {
	case strings.HasPrefix(network, "tcp"):
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	case strings.HasPrefix(network, "udp"):
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	default:
		return nil, fmt.Errorf("unsupported bound network %s", network)
	}
	return dialer, nil
}
func dialBound(ctx context.Context, network, address string) (net.Conn, error) {
	dialer, err := boundDialer(network, address)
	if err != nil {
		return nil, err
	}
	begin := time.Now()
	connection, err := dialer.DialContext(ctx, network, address)
	fields := map[string]any{"network": network, "remote": address, "bound_ifindex": interfaceIndex.Load(), "elapsed_ms": time.Since(begin).Milliseconds(), "error": fmt.Sprint(err)}
	if dialer.LocalAddr != nil {
		fields["requested_source"] = dialer.LocalAddr.String()
	}
	if err == nil {
		fields["actual_source"] = connection.LocalAddr().String()
	}
	event("socket.dial", fields)
	return connection, err
}

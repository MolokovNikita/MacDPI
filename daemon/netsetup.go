package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

var stateDirectory = "/Library/Application Support/MacDPI"
var dnsJournal = stateDirectory + "/dns-backup.json"

const tunAddr4 = "198.18.0.1"
const dnsAddr4 = "198.18.0.2"
const tunAddr6 = "fdfe:dcba:9876::1"

type dnsBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

var run = runNetworkCommand

func runNetworkCommand(name string, args ...string) (string, error) {
	paths := map[string]string{"route": "/sbin/route", "ifconfig": "/sbin/ifconfig", "networksetup": "/usr/sbin/networksetup", "dscacheutil": "/usr/bin/dscacheutil", "killall": "/usr/bin/killall"}
	path, ok := paths[name]
	if !ok {
		return "", fmt.Errorf("unsupported network command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.WaitDelay = 3 * time.Second
	start := time.Now()
	out, err := c.CombinedOutput()
	text := string(out)
	if len(text) > 4096 {
		text = text[:4096]
	}
	event("network.command", map[string]any{"command": name, "args": args, "output": text, "error": fmt.Sprint(err), "elapsed_ms": time.Since(start).Milliseconds()})
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
func defaultIface(v6 bool) (string, error) {
	args := []string{"-n", "get"}
	if v6 {
		args = append(args, "-inet6")
	}
	out, err := run("route", append(args, "default")...)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && k == "interface" {
			name := strings.TrimSpace(v)
			if strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "lo") {
				event("network.conflicting_tunnel", map[string]any{"interface": name})
				return "", fmt.Errorf("Подключён другой VPN/TUN (%s). Отключи его перед запуском MacDPI", name)
			}
			return name, nil
		}
	}
	return "", errors.New("no default route")
}

func serviceForIface(dev string) (string, error) {
	out, err := run("networksetup", "-listnetworkserviceorder")
	if err != nil {
		return "", err
	}
	var last string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "(Hardware Port:") {
			if strings.Contains(line, "Device: "+dev+")") && last != "" {
				return last, nil
			}
			continue
		}
		if strings.HasPrefix(line, "(") {
			if i := strings.Index(line, ") "); i > 0 {
				last = line[i+2:]
			}
		}
	}
	return "", fmt.Errorf("no network service for %s", dev)
}

func getDNS(service string) ([]string, error) {
	out, err := run("networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if net.ParseIP(l) != nil {
			servers = append(servers, l)
		}
	}
	return servers, nil
}

func setDNS(service string, servers []string) error {
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, servers...)
	}
	_, err := run("networksetup", args...)
	run("dscacheutil", "-flushcache")
	run("killall", "-HUP", "mDNSResponder")
	return err
}

func readBackups() ([]dnsBackup, error) {
	raw, err := os.ReadFile(dnsJournal)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b []dnsBackup
	err = json.Unmarshal(raw, &b)
	return b, err
}
func saveBackups(b []dnsBackup) error {
	if err := os.MkdirAll(stateDirectory, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(stateDirectory, ".dns-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	raw, err := json.Marshal(b)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), dnsJournal)
}
func switchDNS(dev string) error {
	service, err := serviceForIface(dev)
	if err != nil {
		return err
	}
	current, err := getDNS(service)
	if err != nil {
		return err
	}
	backups, err := readBackups()
	if err != nil {
		return err
	}
	found := false
	for _, b := range backups {
		if b.Service == service {
			found = true
			break
		}
	}
	if !found {
		if len(current) == 1 && current[0] == dnsAddr4 {
			return errors.New("DNS already points to MacDPI but recovery journal is missing")
		}
		backups = append(backups, dnsBackup{Service: service, Servers: current})
		if err = saveBackups(backups); err != nil {
			return err
		}
	}
	event("dns.override", map[string]any{"service": service, "previous": current, "next": dnsAddr4})
	return setDNS(service, []string{dnsAddr4})
}
func recoverDNS() error {
	backups, err := readBackups()
	if err != nil {
		return err
	}
	var remaining []dnsBackup
	var errs []error
	for _, b := range backups {
		current, e := getDNS(b.Service)
		if e == nil && len(current) == 1 && current[0] == dnsAddr4 {
			event("dns.restore", map[string]any{"service": b.Service, "servers": b.Servers})
			e = setDNS(b.Service, b.Servers)
		}
		// Preserve a DNS change made by the user or another app after activation.
		if e != nil {
			remaining = append(remaining, b)
			errs = append(errs, e)
		}
	}
	if len(remaining) > 0 {
		if e := saveBackups(remaining); e != nil {
			errs = append(errs, e)
		}
	} else {
		if e := os.Remove(dnsJournal); e != nil && !errors.Is(e, os.ErrNotExist) {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}

// Darwin's rt_primary_default() checks the zero destination address, not its mask.
// Installing 0.0.0.0/1 or ::/1 can replace the kernel's primary scope with utun,
// breaking IP_BOUND_IF sockets. Keep zero-based default routes untouched.
// IPv4 follows tun2socks' upstream macOS route recipe; IPv6 covers global unicast.
func tunRoutes(v6 bool) [][2]string {
	routes := [][2]string{
		{"-inet", "1.0.0.0/8"}, {"-inet", "2.0.0.0/7"}, {"-inet", "4.0.0.0/6"},
		{"-inet", "8.0.0.0/5"}, {"-inet", "16.0.0.0/4"}, {"-inet", "32.0.0.0/3"},
		{"-inet", "64.0.0.0/2"}, {"-inet", "128.0.0.0/1"}, {"-inet", "198.18.0.0/15"},
	}
	if v6 {
		routes = append(routes, [2]string{"-inet6", "2000::/3"})
	}
	return routes
}
func physicalIPv6Available(iface string) bool {
	sources := boundSources.Load()
	if sources == nil || sources.IPv6 == nil {
		return false
	}
	output, err := run("route", "-n", "get", "-inet6", "-ifscope", iface, "default")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && key == "interface" {
			return strings.TrimSpace(value) == iface
		}
	}
	return false
}
func configureSystemTun(name string, v6 bool) error {
	if _, err := run("ifconfig", name, "inet", tunAddr4, tunAddr4, "alias"); err != nil {
		return err
	}
	if v6 {
		if _, err := run("ifconfig", name, "inet6", tunAddr6+"/64", "alias"); err != nil {
			return err
		}
	}
	if _, err := run("ifconfig", name, "up"); err != nil {
		return err
	}
	for _, route := range tunRoutes(v6) {
		args := []string{"-q", "-n", "add", route[0], "-net", route[1]}
		if route[0] == "-inet6" {
			args = append(args, "-interface", name)
		} else {
			args = append(args, tunAddr4)
		}
		if _, err := run("route", args...); err != nil {
			return err
		}
	}
	return nil
}
func removeSystemRoutes(name string, v6 bool) {
	for _, route := range tunRoutes(v6) {
		output, err := run("route", "-n", "get", route[0], route[1])
		if err != nil {
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(output, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["interface"] != name {
			continue
		}
		args := []string{"-q", "-n", "delete", route[0], "-net", route[1]}
		if route[0] == "-inet6" {
			args = append(args, "-interface", name)
		} else {
			if fields["gateway"] != tunAddr4 {
				continue
			}
			args = append(args, tunAddr4)
		}
		run("route", args...)
	}
}

// Migrate only the exact local HTTPS proxy used by MacDPI 0.1. Other proxies are preserved.
func disableLegacyProxy(dev string) error {
	service, err := serviceForIface(dev)
	if err != nil {
		return err
	}
	output, err := run("networksetup", "-getsecurewebproxy", service)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	if values["Enabled"] == "Yes" && values["Server"] == "127.0.0.1" && values["Port"] == "18080" {
		_, err = run("networksetup", "-setsecurewebproxystate", service, "off")
	}
	return err
}

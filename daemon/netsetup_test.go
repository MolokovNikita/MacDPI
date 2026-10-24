package main

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func mockNetwork(t *testing.T, initial []string) (*[]string, *bool) {
	t.Helper()
	oldDir, oldJournal, oldRun := stateDirectory, dnsJournal, run
	stateDirectory = t.TempDir()
	dnsJournal = stateDirectory + "/dns.json"
	current := append([]string(nil), initial...)
	fail := false
	run = func(command string, args ...string) (string, error) {
		if command != "networksetup" {
			return "", nil
		}
		switch args[0] {
		case "-listnetworkserviceorder":
			return "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n", nil
		case "-getdnsservers":
			return strings.Join(current, "\n"), nil
		case "-setdnsservers":
			if fail {
				return "", errors.New("fixture failure")
			}
			current = append([]string(nil), args[2:]...)
			if current[0] == "Empty" {
				current = nil
			}
			return "", nil
		}
		return "", errors.New("unexpected command")
	}
	t.Cleanup(func() { stateDirectory, dnsJournal, run = oldDir, oldJournal, oldRun })
	return &current, &fail
}
func TestDNSRecoveryJournal(t *testing.T) {
	original := []string{"9.9.9.9", "149.112.112.112"}
	current, _ := mockNetwork(t, original)
	if err := switchDNS("en0"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*current, []string{dnsAddr4}) {
		t.Fatal("DNS not switched")
	}
	if err := switchDNS("en0"); err != nil {
		t.Fatal(err)
	} // Never replace the saved original on repeated start.
	if err := recoverDNS(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*current, original) {
		t.Fatal("original DNS not restored", *current)
	}
	if _, err := os.Stat(dnsJournal); !os.IsNotExist(err) {
		t.Fatal("journal not removed")
	}
}
func TestDNSRecoveryPreservesExternalChange(t *testing.T) {
	current, _ := mockNetwork(t, nil)
	if err := switchDNS("en0"); err != nil {
		t.Fatal(err)
	}
	*current = []string{"1.1.1.1"}
	if err := recoverDNS(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*current, []string{"1.1.1.1"}) {
		t.Fatal("external DNS change overwritten")
	}
}
func TestDNSRecoveryRetriesFailure(t *testing.T) {
	current, fail := mockNetwork(t, nil)
	if err := switchDNS("en0"); err != nil {
		t.Fatal(err)
	}
	*fail = true
	if err := recoverDNS(); err == nil {
		t.Fatal("recovery failure hidden")
	}
	if _, err := os.Stat(dnsJournal); err != nil {
		t.Fatal("recovery journal lost")
	}
	*fail = false
	if err := recoverDNS(); err != nil {
		t.Fatal(err)
	}
	if len(*current) != 0 {
		t.Fatal("DHCP DNS not restored")
	}
}

func TestTunnelRoutesPreserveDarwinPrimaryScope(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, route := range tunRoutes(v6) {
			prefix, err := netip.ParsePrefix(route[1])
			if err != nil {
				t.Fatal(err)
			}
			if prefix.Addr().IsUnspecified() {
				t.Fatal("zero-address route changes XNU primary scope", route)
			}
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "74.125.1.1", "142.250.1.1", "198.18.0.2", "203.0.113.1"} {
		found := false
		for _, route := range tunRoutes(false) {
			p, _ := netip.ParsePrefix(route[1])
			if p.Contains(netip.MustParseAddr(address)) {
				found = true
			}
		}
		if !found {
			t.Fatal("public IPv4 destination not intercepted", address)
		}
	}
	for _, route := range tunRoutes(false) {
		p, _ := netip.ParsePrefix(route[1])
		if p.Contains(netip.MustParseAddr("0.0.0.0")) {
			t.Fatal("default source lookup intercepted")
		}
	}
}
func TestRouteCleanupPreservesForeignRoutes(t *testing.T) {
	old := run
	defer func() { run = old }()
	deletes := 0
	run = func(command string, args ...string) (string, error) {
		if slices.Contains(args, "get") {
			return "interface: utun-other\ngateway: 198.18.0.1\n", nil
		}
		if slices.Contains(args, "delete") {
			deletes++
		}
		return "", nil
	}
	removeSystemRoutes("utun-test", false)
	if deletes != 0 {
		t.Fatal("cleanup deleted routes owned by another tunnel")
	}
	run = func(command string, args ...string) (string, error) {
		if slices.Contains(args, "get") {
			return "interface: utun-test\ngateway: 198.18.0.1\n", nil
		}
		if slices.Contains(args, "delete") {
			deletes++
			if args[len(args)-1] != tunAddr4 {
				t.Fatal("gateway route deleted with a different identity", args)
			}
		}
		return "", nil
	}
	removeSystemRoutes("utun-test", false)
	if deletes != len(tunRoutes(false)) {
		t.Fatal("owned routes not removed", deletes)
	}
}

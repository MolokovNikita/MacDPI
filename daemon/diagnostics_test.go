package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

type testDevice struct{ *channel.Endpoint }

func (*testDevice) Name() string { return "utun-test" }
func (*testDevice) Type() string { return "test" }

func TestConnectivityFailureRollsBack(t *testing.T) {
	current, _ := mockNetwork(t, []string{"9.9.9.9"})
	oldRun := run
	run = func(command string, args ...string) (string, error) {
		if command == "route" && len(args) > 1 && args[1] == "get" {
			return "interface: en0\n", nil
		}
		if command == "networksetup" && args[0] == "-getsecurewebproxy" {
			return "Enabled: No\n", nil
		}
		return oldRun(command, args...)
	}
	oldOpen, oldLookup, oldVerify := createSystemDevice, lookupSystemInterface, verifySystemConnectivity
	oldIndex := interfaceIndex.Load()
	oldSources, oldAddresses := boundSources.Load(), interfaceAddresses
	interfaceAddresses = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(192, 0, 2, 2), Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() {
		createSystemDevice, lookupSystemInterface, verifySystemConnectivity = oldOpen, oldLookup, oldVerify
		interfaceIndex.Store(oldIndex)
		boundSources.Store(oldSources)
		interfaceAddresses = oldAddresses
	})
	createSystemDevice = func(string, uint32) (device.Device, error) { return &testDevice{channel.New(16, 1500, "")}, nil }
	lookupSystemInterface = func(string) (*net.Interface, error) { return &net.Interface{Name: "en0", Index: 14}, nil }
	sentinel := errors.New("fixture: DNS path unreachable")
	verifySystemConnectivity = func() error { return sentinel }
	controller := &systemController{}
	if err := controller.start(os.Getpid(), "tlsrec-split"); !errors.Is(err, sentinel) {
		t.Fatal("connectivity failure hidden", err)
	}
	if controller.dev != nil || controller.status().Active {
		t.Fatal("failed tunnel remained active")
	}
	if len(*current) != 1 || (*current)[0] != "9.9.9.9" {
		t.Fatal("DNS was not rolled back", *current)
	}
	if _, err := os.Stat(dnsJournal); !os.IsNotExist(err) {
		t.Fatal("DNS journal not cleaned after successful rollback")
	}
}
func TestDiagnosticLogPersistsAndRotates(t *testing.T) {
	oldDirectory := stateDirectory
	stateDirectory = t.TempDir()
	t.Cleanup(func() {
		diagnosticLog.Lock()
		if diagnosticLog.file != nil {
			diagnosticLog.file.Close()
		}
		diagnosticLog.file = nil
		diagnosticLog.path = ""
		diagnosticLog.Unlock()
		stateDirectory = oldDirectory
	})
	if err := openDiagnostics(); err != nil {
		t.Fatal(err)
	}
	failure("fixture.dns", errors.New("resolver timed out"), nil)
	event("system.stop.end", nil)
	path := filepath.Join(stateDirectory, "diagnostics.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var entry map[string]any
		if err = json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal("invalid JSONL", err)
		}
	}
	if !strings.Contains(string(raw), "fixture.dns") || !strings.Contains(string(raw), "system.stop.end") {
		t.Fatal("failure history lost on stop")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("log permissions", info.Mode())
	}
	for i := 0; i < 4; i++ {
		event("rotation.fixture", map[string]any{"value": strings.Repeat("x", 800000)})
	}
	if _, err = os.Stat(path + ".1"); err != nil {
		t.Fatal("log did not rotate", err)
	}
	info, _ = os.Stat(path)
	if info.Size() > diagnosticLogLimit {
		t.Fatal("unbounded log size")
	}
	event("fixture.report", map[string]any{"error": "ошибка после отключения"})
	report := diagnosticReport(systemState{Version: serviceVersion, Active: false, Error: "fixture failure"})
	if !strings.Contains(report, "fixture.report") || !strings.Contains(report, "fixture failure") || !strings.Contains(report, "\"active\": false") {
		t.Fatal("report lost failure history for a stopped tunnel")
	}
}

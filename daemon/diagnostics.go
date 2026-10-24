package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var diagnosticLog struct {
	sync.Mutex
	file *os.File
	path string
}

const diagnosticLogLimit = 2 * 1024 * 1024

func openDiagnostics() error {
	if err := os.MkdirAll(stateDirectory, 0755); err != nil {
		return err
	}
	path := filepath.Join(stateDirectory, "diagnostics.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	diagnosticLog.Lock()
	diagnosticLog.file = f
	diagnosticLog.path = path
	diagnosticLog.Unlock()
	event("service.started", map[string]any{"version": serviceVersion, "pid": os.Getpid(), "go": runtime.Version(), "arch": runtime.GOARCH})
	return nil
}
func event(name string, fields map[string]any) {
	diagnosticLog.Lock()
	defer diagnosticLog.Unlock()
	if diagnosticLog.file == nil {
		return
	}
	entry := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "event": name}
	for key, value := range fields {
		entry[key] = value
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if info, e := diagnosticLog.file.Stat(); e == nil && info.Size()+int64(len(raw)) > diagnosticLogLimit {
		diagnosticLog.file.Close()
		os.Rename(diagnosticLog.path+".1", diagnosticLog.path+".2")
		os.Rename(diagnosticLog.path, diagnosticLog.path+".1")
		diagnosticLog.file, _ = os.OpenFile(diagnosticLog.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	}
	if diagnosticLog.file != nil {
		diagnosticLog.file.Write(append(raw, '\n'))
	}
}
func failure(stage string, err error, fields map[string]any) {
	if err == nil {
		return
	}
	copyFields := map[string]any{}
	for k, v := range fields {
		copyFields[k] = v
	}
	copyFields["stage"] = stage
	copyFields["error"] = err.Error()
	event("failure", copyFields)
}
func dnsQuestion(raw []byte) string {
	var query dnsmessage.Message
	if query.Unpack(raw) != nil || len(query.Questions) == 0 {
		return "unparsed"
	}
	q := query.Questions[0]
	return fmt.Sprintf("%s %s", q.Name.String(), q.Type.String())
}
func diagnosticCommand(path string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout = &out
	command.Stderr = &out
	err := command.Run()
	text := out.String()
	if len(text) > 32768 {
		text = text[:32768] + "\n[truncated]"
	}
	if err != nil {
		text += "\nERROR: " + err.Error()
	}
	return strings.ToValidUTF8(text, "�")
}
func routeSnapshot(stage string) {
	diagnosticLog.Lock()
	enabled := diagnosticLog.file != nil
	diagnosticLog.Unlock()
	if !enabled {
		return
	}
	if sources := boundSources.Load(); sources != nil {
		event("route.scoped_snapshot", map[string]any{"stage": stage, "interface": sources.Name, "output": diagnosticCommand("/sbin/route", "-n", "get", "-ifscope", sources.Name, "1.1.1.1")})
	}
	for _, target := range []string{"default", dnsAddr4, "1.1.1.1"} {
		event("route.snapshot", map[string]any{"stage": stage, "target": target, "output": diagnosticCommand("/sbin/route", "-n", "get", target)})
	}
	event("dns.snapshot", map[string]any{"stage": stage, "output": diagnosticCommand("/usr/sbin/scutil", "--dns")})
}
func diagnosticReport(state systemState) string {
	var out strings.Builder
	fmt.Fprintf(&out, "MacDPI diagnostics · %s\nHelper version: %d\nGo: %s\n", time.Now().UTC().Format(time.RFC3339), serviceVersion, runtime.Version())
	raw, _ := json.MarshalIndent(state, "", "  ")
	fmt.Fprintf(&out, "\nSTATUS\n%s\n", raw)
	for _, command := range []struct {
		label, path string
		args        []string
	}{
		{"macOS", "/usr/bin/sw_vers", []string{"-productVersion"}},
		{"IPv4 routes", "/usr/sbin/netstat", []string{"-rn", "-f", "inet"}},
		{"IPv6 routes", "/usr/sbin/netstat", []string{"-rn", "-f", "inet6"}},
		{"DNS configuration", "/usr/sbin/scutil", []string{"--dns"}},
		{"Default route", "/sbin/route", []string{"-n", "get", "default"}},
		{"Route to local DNS", "/sbin/route", []string{"-n", "get", dnsAddr4}},
		{"Network services", "/usr/sbin/networksetup", []string{"-listnetworkserviceorder"}},
	} {
		fmt.Fprintf(&out, "\n%s\n%s\n", command.label, diagnosticCommand(command.path, command.args...))
	}
	for _, suffix := range []string{".2", ".1", ""} {
		path := filepath.Join(stateDirectory, "diagnostics.jsonl"+suffix)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err == nil && info.Size() > 384*1024 {
			f.Seek(-384*1024, io.SeekEnd)
		}
		data, _ := io.ReadAll(io.LimitReader(f, 384*1024))
		f.Close()
		fmt.Fprintf(&out, "\nEVENTS %s (tail)\n%s\n", suffix, strings.ToValidUTF8(string(data), "�"))
	}
	return out.String()
}

// Verify the host-to-utun path with ordinary HTTPS, not the bound outbound bypass.
// A failed check rolls the activation back instead of leaving the machine offline.
var verifySystemConnectivity = func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(dnsAddr4, "53"))
	}}
	ips, err := resolver.LookupIPAddr(ctx, "example.com")
	if err != nil {
		failure("health.virtual_dns", err, nil)
		return fmt.Errorf("Проверка DNS через туннель не прошла: %w", err)
	}
	event("health.virtual_dns.ok", map[string]any{"addresses": ips, "elapsed_ms": time.Since(start).Milliseconds()})
	// Use the same system resolver as an ordinary application as well.
	start = time.Now()
	ips, err = net.DefaultResolver.LookupIPAddr(ctx, "example.com")
	if err != nil {
		failure("health.system_dns", err, nil)
		return fmt.Errorf("Системный DNS после подключения не работает: %w", err)
	}
	event("health.system_dns.ok", map[string]any{"addresses": ips, "elapsed_ms": time.Since(start).Milliseconds()})
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	response, err := client.Do(request)
	if err != nil {
		failure("health.https", err, nil)
		return fmt.Errorf("Обычная HTTPS-страница через туннель не открылась: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("Проверка HTTPS: HTTP %d", response.StatusCode)
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil {
		return fmt.Errorf("Проверка HTTPS: %w", err)
	}
	event("health.https.ok", map[string]any{"status": response.StatusCode, "elapsed_ms": time.Since(start).Milliseconds()})
	return nil
}

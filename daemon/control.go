package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const serviceVersion = 11

var createSystemDevice = tun.Open
var lookupSystemInterface = net.InterfaceByName

func socketPath(uid int) string { return "/var/run/macdpi-" + strconv.Itoa(uid) + ".sock" }

type systemState struct {
	Version      int            `json:"version"`
	Active       bool           `json:"active"`
	TargetOnly   bool           `json:"target_only"`
	Interface    string         `json:"interface,omitempty"`
	Strategy     string         `json:"strategy,omitempty"`
	Error        string         `json:"error,omitempty"`
	TCP          uint64         `json:"tcp"`
	UDP          uint64         `json:"udp"`
	QUIC         uint64         `json:"quic_blocked"`
	QUICFakes    uint64         `json:"quic_fakes"`
	Fakes        uint64         `json:"voice_fakes"`
	FlowErrors   uint64         `json:"flow_errors"`
	Checks       []serviceCheck `json:"checks,omitempty"`
	PacketEngine bool           `json:"packet_engine"`
	PacketError  string         `json:"packet_error,omitempty"`
	Profiles     profileStatus  `json:"profiles"`
}
type systemController struct {
	mu          sync.Mutex
	dev         device.Device
	stack       *stack.Stack
	relay       *systemRelay
	owner       int
	iface       string
	selected    string
	ipv6        bool
	lastError   string
	checks      []serviceCheck
	packet      *packetEngine
	packetError string
	targetOnly  bool
}

func (c *systemController) stopPacketEngine() {
	if c.packet != nil {
		activePacketEngine.CompareAndSwap(c.packet, nil)
		c.packet.close()
		c.packet = nil
	}
}

func (c *systemController) status() systemState {
	state := systemState{Checks: c.checks, Version: serviceVersion, Active: c.dev != nil, Interface: c.iface, Strategy: c.selected, Error: c.lastError}
	state.TargetOnly = c.targetOnly
	state.Profiles = profileService.status()
	state.PacketEngine = c.packet != nil
	state.PacketError = c.packetError
	if c.relay != nil {
		state.TargetOnly = c.relay.targetOnly
		state.TCP = c.relay.tcpCount.Load()
		state.UDP = c.relay.udpCount.Load()
		state.QUIC = c.relay.quicCount.Load()
		state.QUICFakes = c.relay.quicFakes.Load()
		state.Fakes = c.relay.fakeCount.Load()
		state.FlowErrors = c.relay.errors.Load()
	}
	return state
}
func (c *systemController) stop() error {
	event("system.stop.begin", map[string]any{"active": c.dev != nil})
	var err error
	if c.dev != nil {
		// Stop directing new traffic into utun, then restore DNS and close existing flows.
		removeSystemRoutes(c.dev.Name(), c.ipv6)
		err = recoverDNS()
		c.relay.close()
		c.dev.Close()
		c.stack.Close()
		c.stack.Wait()
		c.dev = nil
		c.stack = nil
		c.relay = nil
	} else {
		err = recoverDNS()
	}
	c.stopPacketEngine()
	event("system.stop.end", map[string]any{"error": fmt.Sprint(err)})
	c.iface = ""
	c.owner = 0
	if err != nil {
		c.lastError = err.Error()
	} else {
		c.lastError = ""
	}
	return err
}
func (c *systemController) start(owner int, strategy string, scope ...bool) error {
	targetOnly := len(scope) > 0 && scope[0]
	event("system.start.request", map[string]any{"owner": owner, "strategy": strategy, "target_only": len(scope) > 0 && scope[0]})
	routeSnapshot("before_start")
	if owner <= 1 || syscall.Kill(owner, 0) != nil {
		return errors.New("owning application is not running")
	}
	st, ok := findPreset(strategy)
	if strategy == "auto" {
		st, _ = findPreset("tlsrec-split")
		ok = true
	}
	if !ok {
		return errors.New("unknown strategy")
	}
	if c.dev != nil {
		return nil
	}
	c.lastError = ""
	if err := recoverDNS(); err != nil {
		return fmt.Errorf("restore previous DNS: %w", err)
	}
	name, err := defaultIface(false)
	if err != nil {
		return err
	}
	ifc, err := lookupSystemInterface(name)
	if err != nil {
		return err
	}
	if err = configureBoundInterface(ifc); err != nil {
		return err
	}
	c.ipv6 = physicalIPv6Available(name)
	if strategy == "auto" || st.PacketMode != "" {
		c.packetError = ""
		engine, packetErr := openPacketEngine(name, boundSources.Load().IPv4)
		if packetErr != nil {
			c.packetError = packetErr.Error()
			failure("packet.setup", packetErr, nil)
			if st.PacketMode != "" {
				return packetErr
			}
		} else {
			c.packet = engine
			activePacketEngine.Store(engine)
		}
		defer func() {
			if c.dev == nil {
				c.stopPacketEngine()
			}
		}()
	}
	profileService.activate()
	if strategy == "auto" {
		st, c.checks = chooseStrategy()
	} else {
		st, _ = findPreset(strategy)
		c.checks = nil
	}
	if err = disableLegacyProxy(name); err != nil {
		return err
	}
	event("system.strategy", map[string]any{"selected": st.Name, "checks": c.checks})
	relay := newSystemRelay(st)
	relay.adaptive = strategy == "auto"
	relay.targetOnly = targetOnly
	if targetOnly {
		relay.systemResolvers, err = captureSystemResolvers(name)
		if err != nil {
			return err
		}
	}
	relay.policy.seed(c.checks)
	dev, err := createSystemDevice("utun", 1500)
	if err != nil {
		return err
	}
	ipStack, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: relay})
	if err != nil {
		dev.Close()
		return err
	}
	c.dev = dev
	c.stack = ipStack
	c.relay = relay
	c.iface = name
	c.owner = owner
	c.selected = st.Name
	c.targetOnly = targetOnly
	if err = configureSystemTun(dev.Name(), c.ipv6); err == nil {
		err = switchDNS(name)
	}
	if err == nil {
		routeSnapshot("after_routes")
		if transport, ok := dohClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		event("system.check.begin", map[string]any{"ipv6": c.ipv6})
		err = verifySystemConnectivity()
	}
	if err != nil {
		failure("system.start", err, nil)
		routeSnapshot("before_rollback")
		cleanup := c.stop()
		event("system.rollback", map[string]any{"cause": err.Error(), "cleanup_error": fmt.Sprint(cleanup)})
		return errors.Join(err, cleanup)
	}
	event("system.started", map[string]any{"interface": c.iface, "tun": c.dev.Name(), "strategy": c.selected})
	return nil
}
func (c *systemController) monitor() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		if c.dev != nil {
			if syscall.Kill(c.owner, 0) != nil {
				c.stop()
			} else if name, err := defaultIface(false); err == nil {
				if ifc, e := lookupSystemInterface(name); e == nil {
					previousBinding := boundSources.Load()
					if e = configureBoundInterface(ifc); e != nil {
						failure("network.interface_refresh", e, nil)
						c.mu.Unlock()
						continue
					}
					if previousBinding == boundSources.Load() {
						c.mu.Unlock()
						continue
					}
					event("system.interface_changed", map[string]any{"old": c.iface, "new": name})
					c.relay.reset()
					if c.packet != nil {
						c.stopPacketEngine()
						if engine, packetErr := openPacketEngine(name, boundSources.Load().IPv4); packetErr == nil {
							c.packet = engine
							activePacketEngine.Store(engine)
						} else {
							failure("packet.interface_refresh", packetErr, nil)
						}
					}
					if transport, ok := dohClient.Transport.(*http.Transport); ok {
						transport.CloseIdleConnections()
					}
					c.iface = name
					if c.relay.targetOnly {
						if servers, err := captureSystemResolvers(name); err == nil {
							c.relay.setSystemResolvers(servers)
						} else {
							c.stop()
							c.lastError = err.Error()
							c.mu.Unlock()
							continue
						}
					}
					if e = switchDNS(name); e != nil {
						c.lastError = e.Error()
					}
				}
			}
		}
		c.mu.Unlock()
	}
}
func runService(uid int) error {
	if os.Geteuid() != 0 {
		return errors.New("system helper must run as root")
	}
	if uid < 501 {
		return errors.New("invalid owner UID")
	}
	if err := openDiagnostics(); err != nil {
		return fmt.Errorf("open diagnostics: %w", err)
	}
	profileService.activate()
	profileCtx, profileCancel := context.WithCancel(context.Background())
	defer profileCancel()
	go profileService.monitor(profileCtx)
	c := &systemController{}
	if err := recoverDNS(); err != nil {
		c.lastError = err.Error()
	}
	path := socketPath(uid)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("control path is not a socket")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	if err = os.Chown(path, uid, -1); err != nil {
		return err
	}
	go c.monitor()
	mux := http.NewServeMux()
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		c.mu.Lock()
		state := c.status()
		c.mu.Unlock()
		event("report.export", nil)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, diagnosticReport(state))
	})
	mux.HandleFunc("/update-profiles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		profileService.check(r.Context())
		c.mu.Lock()
		defer c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.status())
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.status())
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var config struct {
			Owner      int    `json:"owner"`
			Strategy   string `json:"strategy"`
			TargetOnly bool   `json:"target_only"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&config); err != nil {
			http.Error(w, "invalid config", 400)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.start(config.Owner, config.Strategy, config.TargetOnly); err != nil {
			c.lastError = err.Error()
			failure("control.start", err, nil)
			w.WriteHeader(500)
		}
		json.NewEncoder(w).Encode(c.status())
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.stop(); err != nil {
			w.WriteHeader(500)
		}
		json.NewEncoder(w).Encode(c.status())
	})
	secured := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed, _ := r.Context().Value(peerKey{}).(bool); !allowed {
			http.Error(w, "forbidden", 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
	server := &http.Server{ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, peerKey{}, peerIs(c, uint32(uid)) || peerIs(c, 0))
	}, Handler: secured, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 10 * time.Second}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; c.mu.Lock(); c.stop(); c.mu.Unlock(); server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func controlRequest(uid int, action string, owner int, strategy string, scope ...bool) ([]byte, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath(uid))
		if err != nil {
			return nil, err
		}
		if !peerIs(connection, 0) {
			connection.Close()
			return nil, errors.New("control server is not root")
		}
		return connection, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	method := "GET"
	var body io.Reader
	if action == "start" || action == "stop" || action == "update-profiles" {
		method = "POST"
		raw, _ := json.Marshal(map[string]any{"owner": owner, "strategy": strategy, "target_only": len(scope) > 0 && scope[0]})
		body = bytes.NewReader(raw)
	} else if action != "status" && action != "diagnostics" {
		return nil, errors.New("invalid control command")
	}
	req, err := http.NewRequest(method, "http://macdpi/"+action, body)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := int64(64 * 1024)
	if action == "diagnostics" {
		limit = 2 * 1024 * 1024
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return raw, fmt.Errorf("helper HTTP %d", resp.StatusCode)
	}
	return raw, nil
}
func peerIs(connection net.Conn, uid uint32) bool {
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		valid = e == nil && cred.Uid == uid
	})
	return err == nil && valid
}

type peerKey struct{}

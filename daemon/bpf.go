package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var activePacketEngine atomic.Pointer[packetEngine]
var errPacketUnavailable = errors.New("packet engine unavailable: BPF access and Ethernet/IPv4 are required")

type timedHandshake struct {
	wireHandshake
	updated time.Time
}
type packetEngine struct {
	fdMu       sync.Mutex
	fd         int
	mu         sync.Mutex
	handshakes map[wireTuple]timedHandshake
	source     net.IP
	cancel     context.CancelFunc
	done       chan struct{}
	observed   atomic.Uint64
	injected   atomic.Uint64
}

func bpfIoctl(fd int, request uint, data unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(data))
	if errno != 0 {
		return errno
	}
	return nil
}

func openPacketEngine(iface string, source net.IP) (*packetEngine, error) {
	if len(iface) == 0 || len(iface) >= 16 || source.To4() == nil {
		return nil, errPacketUnavailable
	}
	fd := -1
	for i := 0; i < 256; i++ {
		candidate, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err == nil {
			fd = candidate
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("open BPF: %w", err)
		}
	}
	if fd < 0 {
		return nil, errPacketUnavailable
	}
	success := false
	defer func() {
		if !success {
			unix.Close(fd)
		}
	}()
	// Darwin struct ifreq: 16-byte name followed by 16-byte union.
	var ifreq [32]byte
	copy(ifreq[:16], iface)
	if err := bpfIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifreq[0])); err != nil {
		return nil, err
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil || dlt != unix.DLT_EN10MB {
		return nil, fmt.Errorf("BPF Ethernet required (DLT=%d): %w", dlt, errPacketUnavailable)
	}
	for _, option := range []uint{unix.BIOCIMMEDIATE, unix.BIOCSHDRCMPLT, unix.BIOCSSEESENT} {
		if err = unix.IoctlSetPointerInt(fd, option, 1); err != nil {
			return nil, err
		}
	}
	// Accept only IPv4 TCP SYN/SYNACK. No ClientHello, HTTP or voice is captured.
	instructions, err := bpf.Assemble(packetCaptureProgram())
	if err != nil {
		return nil, err
	}
	insns := make([]unix.BpfInsn, len(instructions))
	for i, in := range instructions {
		insns[i] = unix.BpfInsn{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	program := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	if err = bpfIoctl(fd, unix.BIOCSETF, unsafe.Pointer(&program)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(insns)
	size, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil || size < 134 || size > 4*1024*1024 {
		return nil, errPacketUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &packetEngine{fd: fd, source: append(net.IP(nil), source.To4()...), handshakes: map[wireTuple]timedHandshake{}, cancel: cancel, done: make(chan struct{})}
	success = true
	go e.read(ctx, size)
	event("packet.engine_ready", map[string]any{"interface": iface, "dlt": dlt, "capture": "IPv4 TCP SYN headers only"})
	return e, nil
}

func packetCaptureProgram() []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 13},
		bpf.LoadAbsolute{Off: 23, Size: 1}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 11},
		bpf.LoadAbsolute{Off: 20, Size: 2}, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipTrue: 9},
		bpf.LoadMemShift{Off: 14}, bpf.LoadIndirect{Off: 27, Size: 1}, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 2, SkipFalse: 6},
		bpf.LoadIndirect{Off: 26, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0}, bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2},
		bpf.ALUOpX{Op: bpf.ALUOpAdd}, bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 14}, bpf.RetA{}, bpf.RetConstant{Val: 0},
	}
}

func (e *packetEngine) close() {
	e.cancel()
	e.fdMu.Lock()
	if e.fd >= 0 {
		unix.Close(e.fd)
		e.fd = -1
	}
	e.fdMu.Unlock()
	<-e.done
}

func (e *packetEngine) observe(frame []byte) {
	h, outgoing, ok := parseWireSYN(frame, e.source)
	if !ok {
		return
	}
	e.observed.Add(1)
	e.mu.Lock()
	defer e.mu.Unlock()
	if outgoing {
		if len(e.handshakes) >= 1024 {
			for key, value := range e.handshakes {
				if time.Since(value.updated) > 30*time.Second {
					delete(e.handshakes, key)
				}
			}
		}
		if len(e.handshakes) >= 1024 {
			return
		}
		e.handshakes[h.key] = timedHandshake{h, time.Now()}
	} else if initial, exists := e.handshakes[h.key]; exists && initial.seq == h.seq {
		initial.ack = h.ack
		initial.peerTimestamp = h.peerTimestamp
		initial.hasTimestamp = initial.hasTimestamp && h.hasTimestamp
		initial.ready = true
		initial.updated = time.Now()
		e.handshakes[h.key] = initial
	}
}

func (e *packetEngine) read(ctx context.Context, size int) {
	defer close(e.done)
	buf := make([]byte, size)
	for ctx.Err() == nil {
		e.fdMu.Lock()
		fd := e.fd
		var n int
		var err error
		if fd >= 0 {
			n, err = unix.Read(fd, buf)
		} else {
			err = os.ErrClosed
		}
		e.fdMu.Unlock()
		if n > 0 {
			walkBPFRecords(buf[:n], e.observe)
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			if ctx.Err() == nil {
				failure("packet.capture", err, nil)
			}
			return
		}
		if n <= 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}
}

func walkBPFRecords(data []byte, visit func([]byte)) {
	for len(data) >= 18 {
		caplen := uint64(binary.LittleEndian.Uint32(data[8:12]))
		hdrlen := uint64(binary.LittleEndian.Uint16(data[16:18]))
		end := hdrlen + caplen
		if hdrlen < 18 || end > uint64(len(data)) {
			return
		}
		visit(data[hdrlen:end])
		aligned := (end + 3) &^ 3
		if aligned > uint64(len(data)) {
			return
		}
		data = data[aligned:]
	}
}

func (e *packetEngine) inject(c *net.TCPConn, first []byte, mode string) error {
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP.To4() == nil {
		return errPacketUnavailable
	}
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.To4() == nil {
		return errPacketUnavailable
	}
	var key wireTuple
	copy(key.local[:], local.IP.To4())
	copy(key.remote[:], remote.IP.To4())
	key.localPort = uint16(local.Port)
	key.remotePort = uint16(remote.Port)
	until := time.Now().Add(250 * time.Millisecond)
	var h timedHandshake
	for {
		e.mu.Lock()
		h = e.handshakes[key]
		e.mu.Unlock()
		if h.ready && time.Since(h.updated) < 10*time.Second {
			break
		}
		if time.Now().After(until) {
			return fmt.Errorf("BPF handshake not observed for %s: %w", remote.String(), errPacketUnavailable)
		}
		time.Sleep(2 * time.Millisecond)
	}
	frames, err := makeDesyncFrames(h.wireHandshake, first, mode)
	if err != nil {
		return err
	}
	for _, frame := range frames {
		e.fdMu.Lock()
		fd := e.fd
		n := 0
		if fd >= 0 {
			n, err = unix.Write(fd, frame)
		} else {
			err = os.ErrClosed
		}
		e.fdMu.Unlock()
		if err != nil {
			return fmt.Errorf("BPF packet write: %w", err)
		}
		if n != len(frame) {
			return errors.New("short BPF packet write")
		}
		e.injected.Add(1)
	}
	event("packet.injected", map[string]any{"mode": mode, "destination": remote.String(), "packets": len(frames)})
	return nil
}

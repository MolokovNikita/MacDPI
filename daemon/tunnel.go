package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tunnelServer terminates HTTP CONNECT only. TLS stays encrypted end to end.
// Each relay uses bounded buffers, deadlines and TCP half closes.
type tunnelServer struct {
	strategy    Strategy
	dns         string
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	stopping    bool
	wg          sync.WaitGroup
	slots       chan struct{}
}

func (s *tunnelServer) serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	if s.stopping {
		s.mu.Unlock()
		l.Close()
		return net.ErrClosed
	}
	s.connections = make(map[net.Conn]struct{})
	s.slots = make(chan struct{}, 256)
	s.mu.Unlock()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			c.Close()
			return net.ErrClosed
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.connections[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer func() {
				c.Close()
				s.mu.Lock()
				delete(s.connections, c)
				s.mu.Unlock()
				<-s.slots
				s.wg.Done()
			}()
			s.handle(c)
		}()
	}
}
func (s *tunnelServer) close() {
	s.mu.Lock()
	s.stopping = true
	if s.listener != nil {
		s.listener.Close()
	}
	for c := range s.connections {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func proxyError(c net.Conn, code int) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
}
func (s *tunnelServer) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReaderSize(c, 16*1024)
	// Read the header with a strict size bound; ReadRequest alone has no such bound.
	var header []byte
	for {
		line, err := r.ReadSlice('\n')
		header = append(header, line...)
		if len(header) > 16*1024 || err != nil {
			proxyError(c, 431)
			return
		}
		if string(line) == "\r\n" {
			break
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(header))))
	if err != nil {
		proxyError(c, 400)
		return
	}
	if req.Method != http.MethodConnect {
		proxyError(c, 405)
		return
	}
	if req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
		proxyError(c, 400)
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil || host == "" {
		proxyError(c, 400)
		return
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		proxyError(c, 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	address := req.Host
	if s.dns == "doh" {
		ip, e := lookupIP4(ctx, host)
		if e != nil {
			proxyError(c, 502)
			log.Printf("DNS: %v", e)
			return
		}
		address = net.JoinHostPort(ip.String(), port)
	}
	// Reject direct loops into this listener. Hostname aliases are checked after dialing, too.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() && port == strconv.Itoa(s.listener.Addr().(*net.TCPAddr).Port) {
		proxyError(c, 403)
		return
	}
	upstream, err := dialBound(ctx, "tcp", address)
	if err != nil {
		proxyError(c, 502)
		return
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		upstream.Close()
		return
	}
	s.connections[upstream] = struct{}{}
	s.mu.Unlock()
	defer func() { upstream.Close(); s.mu.Lock(); delete(s.connections, upstream); s.mu.Unlock() }()
	if upstream.RemoteAddr().String() == s.listener.Addr().String() {
		proxyError(c, 403)
		return
	}
	tcp, ok := upstream.(*net.TCPConn)
	if !ok {
		proxyError(c, 502)
		return
	}
	if _, err = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, err := copyIdle(c, upstream, upstream)
		if t, ok := c.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- err
	}()
	first, err := readFirst(r, c)
	if err == nil && len(first) > 0 {
		upstream.SetWriteDeadline(time.Now().Add(15 * time.Second))
		err = s.strategy.SendFirst(tcp, first)
		if err == nil {
			_, err = copyIdle(upstream, r, c)
		}
	}
	tcp.CloseWrite()
	if err != nil && !errors.Is(err, io.EOF) {
		c.Close()
		upstream.Close()
	}
	// Wake the other direction on shutdown and bound a peer that never closes.
	c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	upstream.SetReadDeadline(time.Now().Add(2 * time.Minute))
	<-done
}
func copyIdle(dst io.Writer, src io.Reader, readConn net.Conn) (int64, error) {
	b := make([]byte, 32*1024)
	var total int64
	for {
		readConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := src.Read(b)
		if n > 0 {
			if c, ok := dst.(net.Conn); ok {
				c.SetWriteDeadline(time.Now().Add(15 * time.Second))
			}
			w, e := dst.Write(b[:n])
			total += int64(w)
			if e != nil {
				return total, e
			}
			if w != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return total, err
		}
	}
}

// Assemble a complete first TLS record even when it arrives in many TCP reads.
// For non-TLS data, forward immediately; this also supports generic CONNECT.
func readFirst(r *bufio.Reader, c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if b != 0x16 {
		return []byte{b}, nil
	}
	head := make([]byte, 5)
	head[0] = b
	if _, err = io.ReadFull(r, head[1:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(head[3:]))
	if head[1] != 3 || size < 1 || size > 18432 {
		return head, nil
	}
	data := make([]byte, 5+size)
	copy(data, head)
	_, err = io.ReadFull(r, data[5:])
	return data, err
}

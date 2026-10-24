package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "local CONNECT proxy address")
	preset := flag.String("strategy", "tlsrec-split", "tlsrec-split, tlsrec, multisplit, none; other presets are experimental")
	dns := flag.String("dns", "system", "system or doh (strict, no unencrypted fallback)")
	iface := flag.String("interface", "", "optional physical interface, e.g. en0")
	parent := flag.Int("parent-pid", 0, "stop when the owning application exits")
	service := flag.Bool("service", false, "run installed privileged system helper")
	uid := flag.Int("uid", os.Getuid(), "owner UID for system control")
	control := flag.String("control", "", "system control: start, stop, status")
	owner := flag.Int("owner", os.Getppid(), "owning application PID")
	installer := flag.Bool("install-script", false, "print privileged helper installation script")
	packetProbe := flag.Bool("packet-probe", false, "probe packet strategies on --interface without changing routes or DNS (root)")
	flag.Parse()
	if *packetProbe {
		if err := runPacketProbe(*iface, flag.Args()); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *installer {
		script, err := installationScript(*uid)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(script)
		return
	}
	if *service {
		if err := runService(*uid); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *control != "" {
		raw, err := controlRequest(*uid, *control, *owner, *preset)
		if len(raw) > 0 {
			fmt.Print(string(raw))
		}
		if err != nil {
			if len(raw) == 0 {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(1)
		}
		return
	}
	st, ok := findPreset(*preset)
	if *preset == "none" {
		st = noStrategy
		ok = true
	}
	if !ok {
		log.Fatal("unknown strategy")
	}
	if *dns != "system" && *dns != "doh" {
		log.Fatal("unknown DNS mode")
	}
	if *iface != "" {
		i, err := net.InterfaceByName(*iface)
		if err != nil {
			log.Fatal(err)
		}
		if err = configureBoundInterface(i); err != nil {
			log.Fatal(err)
		}
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		log.Fatal("listener must use a numeric loopback address")
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	server := &tunnelServer{strategy: st, dns: *dns}
	if *parent > 0 {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if os.Getppid() != *parent {
					server.close()
					return
				}
			}
		}()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; server.close() }()
	fmt.Printf("READY %s strategy=%s dns=%s\n", l.Addr(), st.Name, *dns)
	if err = server.serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}

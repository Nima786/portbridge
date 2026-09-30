// PortBridge links a port on one server to a service on another.
//
// Two roles, which never change with mode:
//
//	edge   - faces the users. Holds a pool of ready spare connections and tells
//	         the origin when a user turns up.
//	origin - sits next to the service being published, dials it only once a real
//	         user is waiting, and confirms once connected.
//
// Two modes, which decide only who opens the cross-border connection:
//
//	direct  - the edge dials the origin.
//	reverse - the origin dials the edge, so the origin needs no open ports. Use
//	          this when the edge cannot reach the origin but the origin can still
//	          reach the edge.
//
// One process runs one tunnel, described by one config file, so several tunnels
// can run side by side without interfering with each other.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is stamped at build time by the release workflow.
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "teardown":
		cmdTeardown(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `PortBridge %s

Usage:
  portbridge run      -config <file>   Run the tunnel described by the config file
  portbridge check    -config <file>   Check a config file and print what it means
  portbridge teardown -config <file>   Teardown remote tunnel and delete local files
  portbridge version                   Print the version

Tunnels are normally created and managed with the menu:
  portbridge-menu
`, version)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("config", "", "Path to the tunnel config file")
	_ = fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "run: -config is required")
		os.Exit(2)
	}

	cfg, err := LoadConfig(*path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config %s: %v", *path, err)
	}
	if err := cfg.LoadSecret(); err != nil {
		log.Fatalf("config %s: %v", *path, err)
	}

	log.SetPrefix("[" + cfg.Name + "] ")
	log.Printf("PortBridge %s starting. %s", version, cfg.Summary())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st := newStatus(cfg)
	go st.publish(ctx)

	switch cfg.Role {
	case RoleEdge:
		err = runEdge(ctx, cfg, st)
	case RoleOrigin:
		err = runOrigin(ctx, cfg, st)
	}
	if err != nil {
		log.Fatalf("stopped with an error: %v", err)
	}
	log.Printf("stopped cleanly")
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("config", "", "Path to the tunnel config file")
	_ = fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "check: -config is required")
		os.Exit(2)
	}

	cfg, err := LoadConfig(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PROBLEM: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "PROBLEM: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.LoadSecret(); err != nil {
		fmt.Fprintf(os.Stderr, "PROBLEM: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK:", cfg.Summary())
}

// waitTimeout waits for a wait group, giving up after d.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	if d <= 0 {
		return false
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func cmdTeardown(args []string) {
	fs := flag.NewFlagSet("teardown", flag.ExitOnError)
	path := fs.String("config", "", "Path to the tunnel config file")
	_ = fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "teardown: -config is required")
		os.Exit(2)
	}

	cfg, err := LoadConfig(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", *path, err)
		os.Exit(1)
	}
	if err := cfg.LoadSecret(); err != nil {
		fmt.Fprintf(os.Stderr, "config %s: %v\n", *path, err)
		os.Exit(1)
	}

	if cfg.Role == RoleOrigin {
		o := &origin{cfg: cfg}
		o.selfDelete()
		fmt.Printf("[%s] origin tunnel deleted.\n", cfg.Name)
		return
	}

	if err := teardownFromEdge(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "teardown error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] remote teardown succeeded.\n", cfg.Name)
}

func teardownFromEdge(cfg *Config) error {
	// 1. Try local control socket if daemon is running
	sockPath := cfg.ControlSocketPath()
	if c, err := net.DialTimeout("unix", sockPath, 1*time.Second); err == nil {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintln(c, "teardown"); err == nil {
			buf := make([]byte, 256)
			n, err := c.Read(buf)
			if err == nil {
				res := strings.TrimSpace(string(buf[:n]))
				if res == "ok" {
					return nil
				}
				if strings.HasPrefix(res, "err: ") {
					return errors.New(strings.TrimPrefix(res, "err: "))
				}
			}
		}
	}

	// 2. Control socket not running or failed; fall back to standalone remote teardown
	return teardownDirectStandalone(cfg)
}

func teardownDirectStandalone(cfg *Config) error {
	if cfg.Mode == ModeDirect {
		routes := newRouter(cfg)
		raw, claim, err := routes.dial(5 * time.Second)
		if err != nil {
			return fmt.Errorf("dialing %s: %w", cfg.TunnelAddr, err)
		}
		defer raw.Close()
		tuneSocket(raw)
		c, err := wrapDial(raw, cfg.withClaimedName(claim))
		if err != nil {
			return fmt.Errorf("wrapping dial: %w", err)
		}
		defer c.Close()
		if err := sendAuth(c, cfg.secret); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		if cfg.Mux {
			cs := newCarrierSet(1, nil, nil)
			if !cs.add(c) {
				return errors.New("cannot create mux link")
			}
			defer cs.closeAll()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := cs.open(ctx.Done())
			if err != nil {
				return fmt.Errorf("opening mux stream: %w", err)
			}
			defer stream.Close()
			return sendTeardown(stream)
		}
		return sendTeardown(c)
	}

	// ModeReverse: edge listens, origin dials in
	ln, err := net.Listen("tcp", cfg.TunnelAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.TunnelAddr, err)
	}
	defer ln.Close()

	var cert *tls.Certificate
	if cfg.Transport != TransportPlain {
		c, err := ensureCert(cfg.CertFile, cfg.KeyFile, cfg.effectiveServerName())
		if err != nil {
			return err
		}
		cert = &c
	}
	cfg.prepareTLS(cert)

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		ch <- res{c: raw}
	}()

	var raw net.Conn
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		raw = r.c
	case <-time.After(8 * time.Second):
		return errors.New("timed out waiting for origin to connect")
	}
	defer raw.Close()

	tuneSocket(raw)
	c, err := wrapAccept(raw, cfg, cert)
	if err != nil {
		return fmt.Errorf("wrapping accept: %w", err)
	}
	defer c.Close()

	guard := newReplayGuard(context.Background())
	if err := recvAuth(c, cfg.secret, guard); err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}

	if cfg.Mux {
		cs := newCarrierSet(1, nil, nil)
		if !cs.add(c) {
			return errors.New("cannot create mux link")
		}
		defer cs.closeAll()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := cs.open(ctx.Done())
		if err != nil {
			return fmt.Errorf("opening mux stream: %w", err)
		}
		defer stream.Close()
		return sendTeardown(stream)
	}
	return sendTeardown(c)
}

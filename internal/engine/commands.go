// Package engine is PortBridge's tunnel itself: the settings, both halves (the
// edge, which faces the users, and the origin, next to the service), the link
// disguises, shared connections, routes and their health checks, the status
// file and the in-tunnel speed test. The program's commands that run a tunnel
// are here too; cmd/portbridge only chooses between them.
package engine

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

func CmdRun(args []string) {
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
	log.Printf("PortBridge %s starting. %s", Version, cfg.Summary())

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

func CmdCheck(args []string) {
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

func CmdTeardown(args []string) {
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
		told := true
		if err := teardownFromOrigin(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "teardown warning: %v\n", err)
			told = false
		} else {
			fmt.Printf("[%s] remote teardown succeeded.\n", cfg.Name)
		}
		o := &origin{cfg: cfg}
		o.selfDelete()
		if !told {
			// This side is removed, but the other side was not told. The exit
			// status says so, so a caller does not report it as fully done.
			os.Exit(3)
		}
		return
	}

	if err := teardownFromEdge(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "teardown error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] remote teardown succeeded.\n", cfg.Name)
}

func teardownFromOrigin(cfg *Config) error {
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
				return fmt.Errorf("unexpected reply from the running tunnel: %q", res)
			}
			return fmt.Errorf("no reply from the running tunnel: %w", err)
		}
		return errors.New("could not talk to the running tunnel")
	}
	// Reporting success here used to tell someone the other server had been
	// cleaned up when nothing had been sent to it at all.
	return errors.New("the tunnel is not running on this server, so the other server could not be told; " +
		"it still has its side and must be removed there")
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
			}
		}
	}

	// 2. Control socket not running or failed; fall back to standalone remote teardown
	return teardownDirectStandalone(cfg)
}

func tryTeardownConn(raw net.Conn, claim string, cfg *Config) error {
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return cs.Teardown(ctx)
	}
	return sendTeardown(c)
}

func teardownDirectStandalone(cfg *Config) error {
	if cfg.Mode == ModeDirect {
		routes := newRouter(cfg)
		raw, claim, err := routes.dial(5 * time.Second)
		if err == nil {
			if err := tryTeardownConn(raw, claim, cfg); err == nil {
				return nil
			}
		}
		// If routed dial failed or was closed by CDN, and PeerIP is known, connect directly to foreign server IP
		directAddr := cfg.TunnelAddr
		if cfg.PeerIP != "" {
			_, port, splitErr := net.SplitHostPort(cfg.TunnelAddr)
			if splitErr == nil {
				directAddr = net.JoinHostPort(cfg.PeerIP, port)
			}
		}
		if directAddr != "" && directAddr != cfg.dialTarget() {
			d := net.Dialer{Timeout: 5 * time.Second}
			if directRaw, dErr := d.Dial("tcp", directAddr); dErr == nil {
				claim := cfg.EffectiveServerName()
				if cfg.CDN {
					// Direct connection bypassing CDN must not claim the CDN domain,
					// which DPI blocks on foreign IPs. Claim a benign ordinary site.
					claim = "www.bing.com"
					if cfg.AltServerName != "" {
						claim = cfg.AltServerName
					}
				}
				if err := tryTeardownConn(directRaw, claim, cfg); err == nil {
					return nil
				}
			}
		}
		if err != nil {
			return fmt.Errorf("dialing %s: %w", cfg.TunnelAddr, err)
		}
		return errors.New("remote teardown failed")
	}

	// ModeReverse: edge listens, origin dials in
	ln, err := net.Listen("tcp", cfg.TunnelAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.TunnelAddr, err)
	}
	defer ln.Close()

	var cert *tls.Certificate
	if cfg.Transport != TransportPlain {
		c, err := EnsureCert(cfg.CertFile, cfg.KeyFile, cfg.EffectiveServerName())
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return cs.Teardown(ctx)
	}
	return sendTeardown(c)
}

// Version is this build's release, set by cmd/portbridge from the number the
// release workflow stamps into it.
var Version = "dev"

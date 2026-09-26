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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
  portbridge run   -config <file>   Run the tunnel described by the config file
  portbridge check -config <file>   Check a config file and print what it means
  portbridge version                Print the version

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

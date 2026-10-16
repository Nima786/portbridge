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
//
// This is only the starting point. The tunnel itself is in internal/engine, the
// management agent and pairing codes in internal/agent, and the real-address
// header in internal/proxyproto.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
	"github.com/Nima786/portbridge/internal/panel"
)

// version is stamped at build time by the release workflow, and handed to the
// engine, which reports it in its log, its status and the agent's answers.
var version = "dev"

func main() {
	engine.Version = version
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		engine.CmdRun(os.Args[2:])
	case "check":
		engine.CmdCheck(os.Args[2:])
	case "teardown":
		engine.CmdTeardown(os.Args[2:])
	case "speedtest":
		engine.CmdSpeedtest(os.Args[2:])
	case "agent":
		if err := agent.CmdAgent(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
			os.Exit(1)
		}
	case "join":
		if err := agent.CmdJoin(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "join error: %v\n", err)
			os.Exit(1)
		}
	case "addresses":
		agent.CmdAddresses()
	case "ports":
		if err := agent.CmdPorts(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ports error: %v\n", err)
			os.Exit(1)
		}
	case "panel":
		if err := panel.CmdPanel(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "panel: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println(engine.Version)
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
  portbridge run       -config <file>               Run the tunnel described by the config file
  portbridge check     -config <file>               Check a config file and print what it means
  portbridge teardown  -config <file>               Teardown remote tunnel and delete local files
  portbridge speedtest [name|-config <file>]        Run an in-tunnel latency and throughput test
  portbridge agent     [-config <file>]             Run the management agent daemon
  portbridge join      <code>                       Join and configure tunnel from pairing code
  portbridge ports     [port,port,...]              Which ports can this server give a tunnel?
  portbridge addresses                              This server's public IPv4 and IPv6 addresses
  portbridge panel     run|setup|status|...         The web panel (see: portbridge panel help)
  portbridge version                                Print the version

Tunnels are normally created and managed with the menu:
  portbridge-menu
`, engine.Version)
}

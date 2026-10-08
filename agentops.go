package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Everything the management agent does to the machine, gathered in one place so
// it can be replaced.
//
// Why it is replaceable
//
// Applying a pairing code is not only writing files. It opens a firewall port,
// enables a system service and starts it. Those are exactly the parts that must
// never happen as a side effect of running the tests: a test run by the
// administrator on a real server used to create real services that then sat in a
// crash loop for days. So the real actions happen only for the real
// configuration directory, and anything else, including every test, gets a host
// that does nothing.

// defaultTunnelsDir is where a real server keeps its tunnel settings.
const defaultTunnelsDir = "/etc/portbridge/tunnels"

// tunnelNameRe is what a tunnel may be called. The name ends up in file names,
// service names and firewall rules, so anything that could escape a directory or
// break a command is refused outright.
var tunnelNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

func validTunnelName(name string) error {
	if !tunnelNameRe.MatchString(name) {
		return fmt.Errorf("tunnel name %q is not allowed: use 1 to 40 letters, digits, dashes or underscores", name)
	}
	return nil
}

// agentOpMu serialises deploying and deleting, so two requests for the same name
// cannot interleave their file writes and service commands.
var agentOpMu sync.Mutex

// agentHost is what the agent does to the machine beyond the settings files.
type agentHost interface {
	// PortFree reports whether the tunnel port can be listened on.
	PortFree(transport Transport, port int) error
	FirewallApply(name string) error
	FirewallRemove(name string) error
	// FirewallSweep removes what is left in the firewall by tunnels that no
	// longer exist.
	FirewallSweep() error
	Reload() error
	// Enable turns the service on and starts it.
	Enable(name string) error
	// Disable stops the service and turns it off.
	Disable(name string) error
	// Active reports whether the service is running, with a note on why not.
	Active(name string) (bool, string)
	RemoveRuntime(name string)
	// Restart stops and starts the service again on its current settings.
	Restart(name string) error
	// Listening reports whether something on this machine answers on the port.
	Listening(port int) bool
	// ListenOwner names the program listening on the port, or says nothing if
	// the machine will not tell.
	ListenOwner(port int) string
}

// agentHostOverride replaces the host for tests that want to watch what would be
// done.
var agentHostOverride agentHost

// hostFor picks the host for a settings directory: the real one only for the real
// directory.
func hostFor(confDir string) agentHost {
	if agentHostOverride != nil {
		return agentHostOverride
	}
	if filepath.ToSlash(filepath.Clean(confDir)) == defaultTunnelsDir {
		return systemHost{}
	}
	return noHost{}
}

// noHost does nothing, successfully.
type noHost struct{}

func (noHost) PortFree(Transport, int) error { return nil }
func (noHost) FirewallApply(string) error    { return nil }
func (noHost) FirewallRemove(string) error   { return nil }
func (noHost) FirewallSweep() error          { return nil }
func (noHost) Reload() error                 { return nil }
func (noHost) Enable(string) error           { return nil }
func (noHost) Disable(string) error          { return nil }
func (noHost) Active(string) (bool, string)  { return true, "" }
func (noHost) RemoveRuntime(string)          {}

// errNoSystemd is returned where there is no service manager to start anything
// with. The settings are still written; the caller says the service was not
// started instead of claiming it was.
var errNoSystemd = errors.New("this machine has no systemd, so the service was not started")

// systemHost is the real thing.
type systemHost struct{}

const hostCmdTimeout = 30 * time.Second

func hostRun(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hostCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func haveSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("the agent must run as root to change services and firewall rules")
	}
	return nil
}

func (systemHost) PortFree(t Transport, port int) error {
	addr := ":" + strconv.Itoa(port)
	if t == TransportKCP {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("UDP port %d is already in use on this server: %w", port, err)
		}
		return pc.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %d is already in use on this server: %w", port, err)
	}
	return ln.Close()
}

const firewallHelper = "/usr/local/bin/portbridge-firewall"

func (systemHost) FirewallApply(name string) error {
	if _, err := os.Stat(firewallHelper); err != nil {
		return nil
	}
	if out, err := hostRun(firewallHelper, "apply", name); err != nil {
		return fmt.Errorf("firewall: %s: %w", out, err)
	}
	return nil
}

func (systemHost) FirewallRemove(name string) error {
	if _, err := os.Stat(firewallHelper); err != nil {
		return nil
	}
	if out, err := hostRun(firewallHelper, "remove", name); err != nil {
		return fmt.Errorf("firewall: %s: %w", out, err)
	}
	return nil
}

// FirewallSweep clears away whatever is left in the firewall, and any GRE link,
// for tunnels whose settings no longer exist. It is run after a tunnel's files
// are removed, when nothing of its can be mistaken for something wanted.
func (systemHost) FirewallSweep() error {
	if _, err := os.Stat(firewallHelper); err != nil {
		return nil
	}
	if out, err := hostRun(firewallHelper, "sweep", "quiet"); err != nil {
		return fmt.Errorf("firewall sweep: %s: %w", out, err)
	}
	return nil
}

func (systemHost) Reload() error {
	if !haveSystemd() {
		return nil
	}
	_, err := hostRun("systemctl", "daemon-reload")
	return err
}

func (systemHost) Enable(name string) error {
	if !haveSystemd() {
		return errNoSystemd
	}
	if err := needRoot(); err != nil {
		return err
	}
	if out, err := hostRun("systemctl", "enable", "--now", "portbridge@"+name); err != nil {
		return fmt.Errorf("starting the service: %s: %w", out, err)
	}
	return nil
}

func (systemHost) Disable(name string) error {
	if !haveSystemd() {
		return nil
	}
	if err := needRoot(); err != nil {
		return err
	}
	_, err := hostRun("systemctl", "disable", "--now", "portbridge@"+name)
	return err
}

func (systemHost) Active(name string) (bool, string) {
	out, _ := hostRun("systemctl", "is-active", "portbridge@"+name)
	if out == "active" {
		return true, ""
	}
	logs, _ := hostRun("journalctl", "-u", "portbridge@"+name, "-n", "5", "--no-pager", "-o", "cat")
	return false, fmt.Sprintf("service is %q; recent log: %s", out, logs)
}

func (systemHost) Restart(name string) error {
	if !haveSystemd() {
		return errNoSystemd
	}
	if err := needRoot(); err != nil {
		return err
	}
	if out, err := hostRun("systemctl", "restart", "portbridge@"+name); err != nil {
		return fmt.Errorf("restarting the service: %s: %w", out, err)
	}
	return nil
}

func (systemHost) Listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (systemHost) RemoveRuntime(name string) {
	_ = os.Remove(filepath.Join("/run/portbridge", name+".json"))
	_ = os.Remove(filepath.Join("/run/portbridge", name+".sock"))
}

// serviceStartSettle is how long a freshly started service is watched. A tunnel
// that cannot start does not fail at the moment of starting: it starts, exits, and
// is restarted, so "enable --now" reports success for one that will never work.
// Two looks a few seconds apart tell a running service from one that is cycling.
var serviceStartSettle = 2500 * time.Millisecond

// confirmRunning checks that the service really stays up.
func confirmRunning(host agentHost, name string) error {
	if _, nothing := host.(noHost); nothing {
		return nil
	}
	for i := 0; i < 2; i++ {
		time.Sleep(serviceStartSettle)
		if ok, why := host.Active(name); !ok {
			return fmt.Errorf("the tunnel did not stay running: %s", why)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Checking what a pairing code asks for
// ---------------------------------------------------------------------------

var (
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	wsPathRe   = regexp.MustCompile(`^/[A-Za-z0-9/_.~%-]{0,200}$`)
)

func portOK(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil && n >= 1 && n <= 65535
}

// validatePairing refuses a code that would write something the tunnel cannot
// use, or something that does not belong in a settings file.
func validatePairing(p *PairingData) error {
	// Anything left out takes its usual value, whether the data came from a code
	// or was built by hand.
	for _, d := range []struct {
		field *string
		value string
	}{
		{&p.Transport, "plain"}, {&p.Pool, "25"}, {&p.Mux, "off"}, {&p.MuxLinks, "4"}, {&p.CDN, "off"},
	} {
		if *d.field == "" {
			*d.field = d.value
		}
	}
	if err := validTunnelName(p.Name); err != nil {
		return err
	}
	if p.Mode != "direct" && p.Mode != "reverse" {
		return fmt.Errorf("mode %q is not direct or reverse", p.Mode)
	}
	if _, ok := portOK(p.TunnelPort); !ok {
		return fmt.Errorf("tunnel port %q is not a port number", p.TunnelPort)
	}
	if p.Mode == "reverse" || p.RelayIP != "" {
		if net.ParseIP(p.RelayIP) == nil {
			return fmt.Errorf("relay address %q is not an IP address", p.RelayIP)
		}
	}
	if p.ServerIP != "" && net.ParseIP(p.ServerIP) == nil {
		return fmt.Errorf("server address %q is not an IP address", p.ServerIP)
	}
	for _, ip := range strings.Split(p.InboundPort, ",") {
		if strings.TrimSpace(ip) == "" {
			continue
		}
		if _, ok := portOK(ip); !ok {
			return fmt.Errorf("service port %q is not a port number", ip)
		}
	}
	if n, err := strconv.Atoi(p.Pool); err != nil || n < 0 || n > 10000 {
		return fmt.Errorf("pool size %q is not a sensible number", p.Pool)
	}
	if !validTransport(Transport(p.Transport)) {
		return fmt.Errorf("transport %q is not one I know", p.Transport)
	}
	for _, f := range []struct{ name, val string }{
		{"cdn", p.CDN}, {"mux", p.Mux}, {"utls", p.UTLS}, {"tls_fragment", p.TLSFragment},
		{"http_header", p.HTTPHeader}, {"gre", p.GRE},
	} {
		if f.val != "" && f.val != "on" && f.val != "off" {
			return fmt.Errorf("%s must be on or off, got %q", f.name, f.val)
		}
	}
	if n, err := strconv.Atoi(p.MuxLinks); err != nil || n < 1 || n > 64 {
		return fmt.Errorf("mux links %q is not a sensible number", p.MuxLinks)
	}
	if p.HTTPHeader == "on" && p.Transport != "plain" {
		return errors.New("the web header only applies to a plain link")
	}
	if p.GRE == "on" {
		if p.Transport != "plain" {
			return errors.New("a GRE link carries the plain link only")
		}
		if p.CDN == "on" || p.AltHost != "" {
			return errors.New("a GRE link cannot be combined with a CDN")
		}
		if _, _, err := greAddrs(p.ServerIP, p.RelayIP); err != nil {
			return fmt.Errorf("a GRE tunnel needs both servers' public IPv4 addresses in its code: %w", err)
		}
	}
	if p.HTTPHost != "" && !hostnameRe.MatchString(p.HTTPHost) {
		return fmt.Errorf("web header name %q is not a hostname", p.HTTPHost)
	}
	if p.ServerName != "" && !hostnameRe.MatchString(p.ServerName) {
		return fmt.Errorf("server name %q is not a hostname", p.ServerName)
	}
	if p.AltHost != "" && !hostnameRe.MatchString(p.AltHost) {
		return fmt.Errorf("backup host %q is not a hostname", p.AltHost)
	}
	if p.WSPath != "" && !wsPathRe.MatchString(p.WSPath) {
		return fmt.Errorf("websocket path %q is not a plain path", p.WSPath)
	}
	for _, ip := range strings.Split(p.CleanIPs, ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if err := checkCleanIP(ip); err != nil {
			return fmt.Errorf("clean addresses: %w", err)
		}
	}
	if len(p.Secret) < 16 || len(p.Secret) > 512 || strings.ContainsAny(p.Secret, " \t\r\n\x00") {
		return errors.New("the secret in the pairing code is too short or contains spaces")
	}
	return nil
}

func (noHost) Restart(string) error { return nil }
func (noHost) Listening(int) bool   { return true }

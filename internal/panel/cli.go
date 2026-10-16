package panel

// "portbridge panel ...": running the panel, and setting it up from the menu.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const panelUnit = "portbridge-panel.service"

// Ports tried in turn for a new panel. They are ones Cloudflare forwards, so the
// panel can later sit behind it, and the agent tries the same ones the other way
// round, so the two rarely want the same one.
var panelPortCandidates = []int{2096, 8443, 2053, 2087, 2083}

// CmdPanel handles "portbridge panel".
func CmdPanel(args []string) error {
	if len(args) == 0 {
		panelUsage()
		return errors.New("say what to do")
	}
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("panel run", flag.ExitOnError)
		dir := fs.String("dir", DefaultDir, "where the panel keeps its settings")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return Run(*dir)
	case "setup":
		return cmdSetup(args[1:])
	case "reset-password":
		return cmdResetPassword(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "help", "-h", "--help":
		panelUsage()
		return nil
	}
	panelUsage()
	return fmt.Errorf("unknown panel command %q", args[0])
}

func panelUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  portbridge panel run                     Run the web panel (its service does this)
  portbridge panel setup [options]         Set up the panel, or change its settings
  portbridge panel reset-password -user U  Change the login; the password is read from standard input
  portbridge panel status [-get key]       Say how the panel is set up

The menu does all of this for you: portbridge-menu -> Web panel
`)
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func panelActive() bool {
	out, _ := systemctl("is-active", panelUnit)
	return out == "active"
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func needRootAndSystemd() error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("this server does not use systemd, which the panel's service needs")
	}
	return nil
}

// readPassword reads one line from r, the whole of it except the line ending.
func readPassword(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func portOf(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func validDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	return ok && local != "" && len(e) <= 254 && !strings.ContainsAny(e, " \t\r\n<>,;\"") && validDomain(domain)
}

func checkPublicURL(u string) error {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" || pu.Hostname() == "" || (pu.Path != "" && pu.Path != "/") ||
		pu.RawQuery != "" || pu.User != nil {
		return errors.New("the public address must look like https://203.0.113.5:2096 or https://panel.example.com:2096")
	}
	return nil
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("panel setup", flag.ExitOnError)
	dir := fs.String("dir", DefaultDir, "where the panel keeps its settings")
	user := fs.String("user", "", "the username to log in with (default: keep the current one)")
	pwStdin := fs.Bool("password-stdin", false, "read a new password from standard input")
	port := fs.Int("port", 0, "the port to serve on (default: keep the current one, or pick a free one)")
	domain := fs.String("domain", "", "a domain name pointing at this server, for a real certificate (\"off\" to stop using one)")
	email := fs.String("email", "", "an email address for the certificate's notices (\"off\" to remove it)")
	group := fs.String("group", "", "the group this server is in: relay, foreign or none")
	publicURL := fs.String("public-url", "", "the address servers that call the panel use (\"auto\" to work it out)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := needRootAndSystemd(); err != nil {
		return err
	}

	cfg, err := readConfig(*dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading the panel's settings: %w", err)
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	cur := st.get()
	oldURL := ""
	if cfg.Listen != "" {
		oldURL = publicURLFor(cfg)
	}

	// The login.
	newUser := strings.TrimSpace(*user)
	if newUser == "" {
		newUser = cur.Admin.User
	}
	pw := ""
	if *pwStdin {
		if pw, err = readPassword(os.Stdin); err != nil {
			return err
		}
	}
	if cur.Admin.Hash == "" && (newUser == "" || pw == "") {
		return errors.New("the first setup needs a username (-user) and a password (-password-stdin)")
	}
	hash := cur.Admin.Hash
	if pw != "" {
		if err := checkNewCredentials(newUser, pw); err != nil {
			return err
		}
		if hash, err = hashPassword(pw); err != nil {
			return err
		}
	} else if err := checkUsername(newUser); err != nil {
		return err
	}

	thisGroup := cur.ThisGroup
	switch *group {
	case "":
	case "none":
		thisGroup = ""
	case GroupRelay, GroupForeign:
		thisGroup = *group
	default:
		return errors.New("the group must be relay, foreign or none")
	}

	switch d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*domain)), "."); d {
	case "":
	case "off":
		cfg.Domain = ""
	default:
		if !validDomain(d) {
			return fmt.Errorf("%q is not a domain name like panel.example.com", *domain)
		}
		cfg.Domain = d
	}
	switch e := strings.TrimSpace(*email); e {
	case "":
	case "off":
		cfg.Email = ""
	default:
		if !validEmail(e) {
			return fmt.Errorf("%q is not an email address", e)
		}
		cfg.Email = e
	}
	switch u := strings.TrimRight(strings.TrimSpace(*publicURL), "/"); u {
	case "":
	case "auto":
		cfg.PublicURL = ""
	default:
		if err := checkPublicURL(u); err != nil {
			return err
		}
		cfg.PublicURL = u
	}

	// Stopped first, so its own port counts as free, and so it cannot write
	// over the settings while they change.
	wasActive := panelActive()
	_, _ = systemctl("stop", panelUnit)
	restore := func() {
		if wasActive {
			_, _ = systemctl("start", panelUnit)
		}
	}
	curPort := portOf(cfg.Listen)
	switch {
	case *port > 0:
		if *port > 65535 {
			restore()
			return errors.New("a port is a number from 1 to 65535")
		}
		if !portFree(*port) {
			restore()
			return fmt.Errorf("port %d is already used by something else on this server", *port)
		}
	case curPort > 0 && portFree(curPort):
		*port = curPort
	default:
		for _, c := range panelPortCandidates {
			if portFree(c) {
				*port = c
				break
			}
		}
		if *port == 0 {
			restore()
			return errors.New("none of the usual panel ports (2096, 8443, 2053, 2087, 2083) is free here; give one with -port")
		}
	}
	cfg.Listen = ":" + strconv.Itoa(*port)

	p := &Panel{dir: *dir}
	if err := p.loadSelfCert(); err != nil {
		restore()
		return fmt.Errorf("making the panel's certificate: %w", err)
	}
	if err := writeConfig(*dir, cfg); err != nil {
		restore()
		return err
	}
	if err := st.update(func(s *State) error {
		s.Admin = Admin{User: newUser, Hash: hash}
		s.ThisGroup = thisGroup
		return nil
	}); err != nil {
		restore()
		return err
	}

	_, _ = systemctl("daemon-reload")
	if out, err := systemctl("enable", panelUnit); err != nil {
		return fmt.Errorf("turning the panel's service on failed (%s); update PortBridge with its installer, "+
			"which adds that service", out)
	}
	if out, err := systemctl("restart", panelUnit); err != nil {
		return fmt.Errorf("starting the panel failed: %s", out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !(panelActive() && !portFree(*port)) {
		if time.Now().After(deadline) {
			logs, _ := exec.Command("journalctl", "-u", panelUnit, "-n", "8", "--no-pager", "-o", "cat").CombinedOutput()
			return fmt.Errorf("the panel did not start on port %d:\n%s", *port, strings.TrimSpace(string(logs)))
		}
		time.Sleep(300 * time.Millisecond)
	}

	fmt.Println("The web panel is running.")
	fmt.Println()
	for i, a := range addressesFor(cfg) {
		label := "  Open it at:   "
		if i > 0 {
			label = "           or:  "
		}
		fmt.Println(label + a)
	}
	fmt.Printf("  Log in as:    %s\n", newUser)
	fmt.Println()
	if cfg.Domain != "" {
		fmt.Printf("  It is getting a certificate for %s now. Until it has one, and at its\n", cfg.Domain)
		fmt.Println("  address by number, the browser warns that the connection is not private.")
	} else {
		fmt.Println("  The browser warns that the connection is not private, because the panel")
		fmt.Println("  made its own certificate.")
	}
	fmt.Println("  That is expected. To be sure it is your panel, check the certificate's")
	fmt.Println("  SHA-256 fingerprint in the browser matches this one, then continue:")
	fmt.Printf("    %s\n", p.selfFP)

	if newURL := publicURLFor(cfg); oldURL != "" && newURL != oldURL {
		n := 0
		for _, s := range cur.Servers {
			if s.CallsPanel {
				n++
			}
		}
		if n > 0 {
			fmt.Println()
			fmt.Printf("  Note: %d server(s) call the panel at its old address, %s, and will\n", n, oldURL)
			fmt.Println("  lose touch with it. Remove them in the panel and add them again.")
		}
	}
	return nil
}

func cmdResetPassword(args []string) error {
	fs := flag.NewFlagSet("panel reset-password", flag.ExitOnError)
	dir := fs.String("dir", DefaultDir, "where the panel keeps its settings")
	user := fs.String("user", "", "the username (default: keep the current one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("run this as root")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	u := strings.TrimSpace(*user)
	if u == "" {
		u = st.get().Admin.User
	}
	pw, err := readPassword(os.Stdin)
	if err != nil {
		return err
	}
	if err := checkNewCredentials(u, pw); err != nil {
		return err
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return err
	}
	// The running panel holds its own copy of the settings and would write the
	// old login back, so it is stopped while this changes.
	wasActive := panelActive()
	if wasActive {
		_, _ = systemctl("stop", panelUnit)
	}
	err = st.update(func(s *State) error {
		s.Admin = Admin{User: u, Hash: hash}
		return nil
	})
	if wasActive {
		_, _ = systemctl("start", panelUnit)
	}
	if err != nil {
		return err
	}
	fmt.Printf("The login is now %s, with the new password. Anyone logged in to the panel has been logged out.\n", u)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("panel status", flag.ExitOnError)
	dir := fs.String("dir", DefaultDir, "where the panel keeps its settings")
	get := fs.String("get", "", "print only this: state, port, domain, email, group, user, public_url, fingerprint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := readConfig(*dir)
	setUp := err == nil
	var st State
	if setUp {
		if s, err := openStore(*dir); err == nil {
			st = s.get()
		}
	}
	state := "not set up"
	if setUp {
		state = "stopped"
		if panelActive() {
			state = "running"
		}
	}
	fp := ""
	if setUp {
		p := &Panel{dir: *dir}
		if p.loadSelfCert() == nil {
			fp = p.selfFP
		}
	}
	if *get != "" {
		v := map[string]string{
			"state":       state,
			"port":        strconv.Itoa(portOf(cfg.Listen)),
			"domain":      cfg.Domain,
			"email":       cfg.Email,
			"group":       st.ThisGroup,
			"user":        st.Admin.User,
			"public_url":  cfg.PublicURL,
			"fingerprint": fp,
		}
		val, ok := v[*get]
		if !ok {
			return fmt.Errorf("unknown key %q", *get)
		}
		if val == "0" && !setUp {
			val = ""
		}
		fmt.Println(val)
		return nil
	}
	if !setUp {
		fmt.Println("Web panel:    not set up on this server")
		return nil
	}
	fmt.Printf("Web panel:    %s\n", state)
	for i, a := range addressesFor(cfg) {
		if i == 0 {
			fmt.Printf("Address:      %s\n", a)
		} else {
			fmt.Printf("              %s\n", a)
		}
	}
	fmt.Printf("Login:        %s\n", st.Admin.User)
	group := "none"
	switch st.ThisGroup {
	case GroupRelay:
		group = "relay (Iran)"
	case GroupForeign:
		group = "foreign"
	}
	fmt.Printf("This server:  %s\n", group)
	fmt.Printf("Servers:      %d added\n", len(st.Servers))
	if cfg.Domain != "" {
		if c := cachedCert(*dir, cfg.Domain); c != nil {
			fmt.Printf("Certificate:  for %s, from %s, valid until %s\n", cfg.Domain, issuerName(c), c.NotAfter.Format("2 Jan 2006"))
		} else {
			fmt.Printf("Certificate:  none yet for %s (see: journalctl -u %s)\n", cfg.Domain, panelUnit)
		}
	} else {
		fmt.Println("Certificate:  the panel's own (no domain name set)")
	}
	if fp != "" {
		fmt.Printf("Fingerprint:  %s\n", fp)
	}
	return nil
}

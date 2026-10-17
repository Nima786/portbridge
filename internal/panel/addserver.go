package panel

// Adding a server.
//
// The panel logs in over SSH with what it was given (a password, a private key,
// or a key file), puts PortBridge on the server if it is missing or older,
// switches its agent on, and then proves it can reach that agent without SSH:
// first directly, and if that fails, by having the agent call the panel. Only
// when one of those works is the server saved. The SSH password or key is held
// in memory for the length of the job and never written anywhere.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

// addRequest is what the "Add server" form sends.
type addRequest struct {
	Name        string `json:"name"`
	Group       string `json:"group"`
	Address     string `json:"address"`
	SSHPort     int    `json:"ssh_port"`
	User        string `json:"user"`
	Password    string `json:"password"`
	PrivateKey  string `json:"private_key"`
	Passphrase  string `json:"passphrase"`
	AllowUpdate bool   `json:"allow_update"`
}

// job is one server being added, with what has happened so far.
type job struct {
	mu       sync.Mutex
	lines    []string
	done     bool
	err      string
	serverID string
	started  time.Time
}

func (j *job) say(format string, args ...any) {
	j.mu.Lock()
	j.lines = append(j.lines, fmt.Sprintf(format, args...))
	j.mu.Unlock()
}

func (j *job) finish(serverID string, err error) {
	j.mu.Lock()
	j.done = true
	j.serverID = serverID
	if err != nil {
		j.err = err.Error()
	}
	j.mu.Unlock()
}

type jobView struct {
	Lines    []string `json:"lines"`
	Done     bool     `json:"done"`
	Error    string   `json:"error,omitempty"`
	ServerID string   `json:"server_id,omitempty"`
}

func (j *job) view() jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobView{Lines: append([]string(nil), j.lines...), Done: j.done, Error: j.err, ServerID: j.serverID}
}

// checkAddRequest refuses what cannot work before anything is attempted.
func (p *Panel) checkAddRequest(r *addRequest) error {
	r.Address = strings.TrimSpace(r.Address)
	r.Name = strings.TrimSpace(r.Name)
	r.User = strings.TrimSpace(r.User)
	if r.User == "" {
		r.User = "root"
	}
	if r.SSHPort == 0 {
		r.SSHPort = 22
	}
	if !validGroup(r.Group) {
		return errors.New("choose whether this is a relay (Iran) or a foreign server")
	}
	if r.Address == "" || strings.ContainsAny(r.Address, " /\\@") || len(r.Address) > 253 {
		return errors.New("give the server's address: an IP address or a host name")
	}
	if r.SSHPort < 1 || r.SSHPort > 65535 {
		return errors.New("the SSH port must be from 1 to 65535")
	}
	if r.Password == "" && strings.TrimSpace(r.PrivateKey) == "" {
		return errors.New("give the server's password, or its private key")
	}
	if len(r.Name) > 64 {
		return errors.New("the name can be at most 64 characters")
	}
	ov := agent.LocalOverview(p.tunnelsDir)
	for _, a := range append(ov.IPv4, ov.IPv6...) {
		if a == r.Address {
			return errors.New("that is the panel's own server; it is already shown as \"This server\"")
		}
	}
	for _, s := range p.store.get().Servers {
		if strings.EqualFold(s.Address, r.Address) {
			return fmt.Errorf("%s is already in the panel, as %q", r.Address, s.Name)
		}
	}
	return nil
}

func (p *Panel) startAdd(r addRequest) (string, error) {
	if err := p.checkAddRequest(&r); err != nil {
		return "", err
	}
	id := newID(9)
	j := &job{started: time.Now()}
	p.jobsMu.Lock()
	p.jobs[id] = j
	// Old finished jobs are forgotten.
	for k, o := range p.jobs {
		if o.view().Done && time.Since(o.started) > time.Hour {
			delete(p.jobs, k)
		}
	}
	p.jobsMu.Unlock()
	go func() {
		// The reason it failed is shown as the job's result, not again here.
		srvID, err := p.addServer(j, r)
		if err != nil {
			logf("adding %s failed: %v", r.Address, err)
		}
		j.finish(srvID, err)
	}()
	return id, nil
}

// sshAuth turns the form's password or key into ways to log in.
func sshAuth(r addRequest) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if key := strings.TrimSpace(r.PrivateKey); key != "" {
		signer, err := parseAnyPrivateKey(key, r.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if r.Password != "" {
		pw := r.Password
		methods = append(methods, ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range qs {
					ans[i] = pw
				}
				return ans, nil
			}))
	}
	return methods, nil
}

// remote is an SSH connection to a server being added.
type remote struct {
	c *ssh.Client
}

func (rm *remote) run(cmd string, stdin []byte, timeout time.Duration) (string, error) {
	sess, err := rm.c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err := <-done:
		return strings.TrimSpace(out.String()), err
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		return strings.TrimSpace(out.String()), fmt.Errorf("%q took longer than %s", cmd, timeout)
	}
}

func (p *Panel) addServer(j *job, r addRequest) (string, error) {
	methods, err := sshAuth(r)
	if err != nil {
		return "", err
	}
	var hostKey string
	cfg := &ssh.ClientConfig{
		User: r.User,
		Auth: methods,
		// The key is recorded rather than checked: this is the first time the
		// panel sees this server, as with a first ssh to it by hand.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = ssh.FingerprintSHA256(key)
			return nil
		},
		Timeout: 20 * time.Second,
	}
	addr := net.JoinHostPort(r.Address, strconv.Itoa(r.SSHPort))
	j.say("Connecting to %s over SSH...", addr)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", plainSSHError(err)
	}
	defer client.Close()
	rm := &remote{c: client}
	j.say("Connected (host key %s).", hostKey)

	// What the server is, asked in one go. Each answer is labelled and on its
	// own line, so a login banner, or a stray warning that some servers print
	// on the connection, cannot be read as one of the answers. A real root
	// login whose first line of output was such a line was once reported as
	// "not root"; now anything that is not a labelled answer is ignored.
	const lookCmd = "echo pb_uid=$(id -u); echo pb_arch=$(uname -m); " +
		"echo pb_systemd=$(test -d /run/systemd/system && echo yes); " +
		"echo pb_version=$(/usr/local/bin/portbridge version 2>/dev/null)"
	facts, err := rm.run(lookCmd, nil, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("could not look at the server: %v %s", err, lastLines(facts, 5))
	}
	f := parseFacts(facts)
	uid, answered := f["pb_uid"]
	if !answered {
		return "", fmt.Errorf("the panel could not read the server when it looked at it; its answer was: %s", lastLines(facts, 5))
	}
	if uid != "0" {
		return "", errors.New("the account given is not root; PortBridge needs root to manage services and the firewall")
	}
	arch := archName(f["pb_arch"])
	if arch == "" {
		return "", fmt.Errorf("its processor type (%s) is not one PortBridge is built for", f["pb_arch"])
	}
	if f["pb_systemd"] != "yes" {
		return "", errors.New("it does not use systemd, which PortBridge needs")
	}
	installed := ""
	if strings.HasPrefix(f["pb_version"], "v") {
		installed = f["pb_version"]
	}

	switch c := compareVersions(installed, engine.Version); {
	case installed == "":
		j.say("PortBridge is not on it yet; installing %s.", engine.Version)
		if err := p.install(j, rm, arch); err != nil {
			return "", err
		}
	case c == 0:
		j.say("It already has PortBridge %s, the same as the panel.", installed)
	case c < 0 && !r.AllowUpdate:
		return "", fmt.Errorf("it has PortBridge %s, older than the panel's %s. Tick \"update it\" to update it "+
			"(its tunnels restart for a few seconds), or update it yourself and add it again", installed, engine.Version)
	case c < 0:
		j.say("It has PortBridge %s; updating it to %s (its tunnels restart for a few seconds).", installed, engine.Version)
		if err := p.install(j, rm, arch); err != nil {
			return "", err
		}
	default:
		j.say("It has PortBridge %s, newer than the panel's %s. Leaving it as it is.", installed, engine.Version)
	}

	// It starts out not calling any panel. Whether it needs to is found out
	// next, and it is switched to calling this one only if so.
	// Updates from the panel are allowed on a server added to it, so it can be
	// kept up to date with one click. A PortBridge from before one-click updates
	// does not know the setting, and could not use it anyway.
	setupArgs := "-panel-url off"
	if now := installedAfter(installed, r.AllowUpdate); compareVersions(now, firstOneClickVersion) >= 0 {
		setupArgs += " -allow-updates on"
	}
	j.say("Switching its management agent on...")
	res, err := remoteAgentSetup(rm, setupArgs)
	if err != nil {
		return "", err
	}
	j.say("Its agent is on, port %d.", res.Port)

	srv := Server{
		ID:          newID(9),
		Name:        r.Name,
		Group:       r.Group,
		Address:     r.Address,
		AgentURL:    "https://" + net.JoinHostPort(r.Address, strconv.Itoa(res.Port)),
		Fingerprint: res.Fingerprint,
		HostKey:     hostKey,
		Added:       time.Now().UTC(),
	}
	if srv.TokenEnc, err = p.store.seal(res.Token); err != nil {
		return "", err
	}

	j.say("Checking the panel can reach it without SSH...")
	ov, derr := p.tryDirect(srv)
	if derr == nil {
		j.say("Reached it directly.")
	} else {
		j.say("Could not reach it directly (%s). Asking it to call the panel instead...", plainAgentError(derr))
		panelURL := p.publicURL()
		if panelURL == "" {
			return "", errors.New("the panel does not know its own public address for servers to call; " +
				"set it in the menu (Web panel). Nothing was saved")
		}
		p.addPending(srv.ID, res.Token)
		defer p.dropPending(srv.ID)
		if _, err := remoteAgentSetup(rm, "-panel-url "+shellQuote(panelURL)+
			" -panel-fingerprint "+shellQuote(p.ownFingerprint())); err != nil {
			return "", err
		}
		srv.CallsPanel = true
		if ov, err = p.waitForCall(srv); err != nil {
			// Put the agent back as it was, so it does not keep calling a panel
			// that has no record of it.
			_, _ = remoteAgentSetup(rm, "-panel-url off")
			return "", fmt.Errorf("could not reach it directly, and it could not call the panel either (%v). "+
				"Check that one of the two can reach the other on the ports involved. Nothing was saved", err)
		}
		j.say("It is calling the panel.")
	}
	if srv.Name == "" {
		srv.Name = ov.Hostname
	}
	if srv.Name == "" {
		srv.Name = r.Address
	}
	if err := p.store.update(func(st *State) error {
		st.Servers = append(st.Servers, srv)
		return nil
	}); err != nil {
		return "", err
	}
	p.fleet.refresh(srv)
	j.say("Added %q, with %d tunnel(s). The SSH login was not kept.", srv.Name, len(ov.Tunnels))
	return srv.ID, nil
}

// installedAfter is the version a server has once adding it has done its part:
// the panel's own if it was installed or updated, otherwise the one it had.
func installedAfter(installed string, allowUpdate bool) string {
	c := compareVersions(installed, engine.Version)
	if installed == "" || (c < 0 && allowUpdate) {
		return engine.Version
	}
	return installed
}

func (p *Panel) tryDirect(srv Server) (*agent.Overview, error) {
	var last error
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		ov, err := p.fleet.overview(ctx, srv)
		cancel()
		if err == nil {
			return ov, nil
		}
		last = err
		time.Sleep(time.Second)
	}
	return nil, last
}

// waitForCall waits for a newly set up agent to call the panel, then asks it for
// its overview through that call.
func (p *Panel) waitForCall(srv Server) (*agent.Overview, error) {
	deadline := time.Now().Add(45 * time.Second)
	for !p.hub.connected(srv.ID) {
		if time.Now().After(deadline) {
			return nil, errors.New("it did not call within 45 seconds")
		}
		time.Sleep(500 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentTimeout)
	defer cancel()
	return p.fleet.overview(ctx, srv)
}

func remoteAgentSetup(rm *remote, extra string) (agent.AgentSetupResult, error) {
	var res agent.AgentSetupResult
	out, err := rm.run("/usr/local/bin/portbridge agent setup -json "+extra, nil, time.Minute)
	// The JSON is the last line; anything before it is the service manager talking.
	last := out
	if i := strings.LastIndex(out, "\n"); i >= 0 {
		last = out[i+1:]
	}
	if jerr := json.Unmarshal([]byte(last), &res); jerr != nil {
		if err != nil {
			return res, fmt.Errorf("switching the agent on failed: %v: %s", err, out)
		}
		return res, fmt.Errorf("the agent setup said something unexpected: %s", out)
	}
	if !res.OK {
		return res, fmt.Errorf("switching the agent on failed: %s", res.Error)
	}
	return res, nil
}

// packArchive turns a release's files into a release archive.
func packArchive(files []pkgFile) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "./" + f.name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// archiveFor is this panel's own release, as an archive, for a processor type.
func (p *Panel) archiveFor(arch string) ([]byte, error) {
	files, err := p.packageFor(arch)
	if err != nil {
		return nil, err
	}
	return packArchive(files)
}

// install carries PortBridge across and runs its installer there.
func (p *Panel) install(j *job, rm *remote, arch string) error {
	archive, err := p.archiveFor(arch)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(archive)
	dir := "/tmp/portbridge-install-" + strings.ToLower(newID(6))
	dir = strings.Map(func(r rune) rune {
		if r == '-' || r == '/' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return 'x'
	}, dir)
	j.say("Copying PortBridge across (%d KB)...", buf.Len()/1024)
	if out, err := rm.run("mkdir -p "+dir+" && tar -xzf - -C "+dir, buf.Bytes(), 3*time.Minute); err != nil {
		return fmt.Errorf("copying PortBridge across failed: %v %s", err, out)
	}
	j.say("Installing...")
	out, err := rm.run("bash "+dir+"/install.sh --from-dir "+dir+" --no-menu; rc=$?; rm -rf "+dir+"; exit $rc", nil, 5*time.Minute)
	if err != nil {
		return fmt.Errorf("the installer failed: %v\n%s", err, lastLines(out, 12))
	}
	j.say("Installed.")
	return nil
}

type pkgFile struct {
	name string
	mode int64
	data []byte
}

// Where an installed PortBridge keeps what a release contains.
var installedFiles = []struct{ path, name string }{
	{"/usr/local/bin/portbridge-menu", "scripts/portbridge-menu"},
	{"/usr/local/bin/portbridge-firewall", "scripts/portbridge-firewall"},
	{"/usr/local/bin/portbridge-tune", "scripts/portbridge-tune"},
	{"/etc/systemd/system/portbridge@.service", "packaging/portbridge@.service"},
	{"/etc/systemd/system/portbridge-agent.service", "packaging/portbridge-agent.service"},
	{"/etc/systemd/system/portbridge-panel.service", "packaging/portbridge-panel.service"},
	{"/usr/local/share/portbridge/install.sh", "install.sh"},
}

// packageFor gathers this release for a server of the given processor type: from
// this server's own copy when it is the same type, so a server that cannot reach
// GitHub (common in Iran) still gets it, or from the release on GitHub when not.
func (p *Panel) packageFor(arch string) ([]pkgFile, error) {
	if arch == runtime.GOARCH {
		exe, err := os.Executable()
		if err == nil {
			if bin, err := os.ReadFile(exe); err == nil {
				files := []pkgFile{{"portbridge", 0o755, bin}}
				complete := true
				for _, f := range installedFiles {
					b, err := os.ReadFile(f.path)
					if err != nil {
						if strings.HasSuffix(f.name, "panel.service") {
							continue
						}
						complete = false
						break
					}
					files = append(files, pkgFile{f.name, 0o755, b})
				}
				if complete {
					return files, nil
				}
			}
		}
	}
	return downloadRelease(engine.Version, arch)
}

// downloadRelease fetches a release archive from GitHub and checks it against the
// checksums published with it before anything in it is used.
func downloadRelease(version, arch string) ([]pkgFile, error) {
	if !agent.IsReleaseVersion(version) {
		return nil, fmt.Errorf("this panel (%s) is not a release, so it cannot fetch a copy for a %s server", version, arch)
	}
	archive, err := agent.FetchRelease(version, arch)
	if err != nil {
		return nil, fmt.Errorf("%v; this server may not reach GitHub", err)
	}
	return unpackArchive(archive)
}

// unpackArchive reads a release archive into its files.
func unpackArchive(archive []byte) ([]pkgFile, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var files []pkgFile
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		n := strings.TrimPrefix(filepath.ToSlash(h.Name), "./")
		if strings.Contains(n, "..") {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return nil, err
		}
		files = append(files, pkgFile{n, 0o755, b})
	}
	return files, nil
}

// parseFacts reads the "pb_key=value" lines the look-at-the-server command
// prints, and ignores every other line, so anything the server says on the
// connection of its own accord (a login banner, a warning) is never mistaken
// for an answer.
func parseFacts(out string) map[string]string {
	f := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.HasPrefix(k, "pb_") {
			f[k] = strings.TrimSpace(v)
		}
	}
	return f
}

func archName(uname string) string {
	switch uname {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return ""
}

// compareVersions compares "v1.2.3" style versions: -1, 0 or 1. Anything that is
// not a plain release compares equal only to itself, and older than a release.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v, ok := strings.CutPrefix(v, "v")
	if !ok {
		return out, false
	}
	core, _, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func plainSSHError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"):
		return errors.New("the server did not accept that password or key")
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline"):
		return errors.New("the server did not answer on its SSH port; check the address and port")
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return errors.New("nothing answers on that SSH port; check the address and port")
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"):
		return errors.New("that address cannot be reached from the panel's server")
	case strings.Contains(msg, "no such host"):
		return errors.New("that host name does not exist")
	}
	return fmt.Errorf("could not log in over SSH: %v", err)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

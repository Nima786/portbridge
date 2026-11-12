package panel

// Multi-path server reachability, peer jump proxying, and 1-line join tickets.
//
// When adding or managing a hard-to-reach foreign server whose direct IPv4 route
// from the panel is blocked or throttled:
//  1. SSH host-key verification and SSH setup can hop TCP end-to-end through an
//     already-online server's authenticated /api/net/* proxy. The SSH handshake
//     and host-key check still run inside the panel process, so the jump server
//     only sees encrypted SSH ciphertext and never sees any password or key.
//  2. Agent HTTPS control falls back across Direct IPv4, Direct IPv6, Stealth
//     Chrome uTLS + fragmented ClientHello, Reverse Hub (/hub/poll), and
//     end-to-end pinned TLS jumped through an online peer server.
//  3. When SSH itself is completely unreachable or disabled, the panel can issue
//     a short-lived single-use 1-line join command that installs/pairs the server
//     outbound to /hub/register without needing SSH from the panel.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Nima786/portbridge/internal/agent"
)

type noJumpCtxKey struct{}

func withNoJump(ctx context.Context) context.Context {
	return context.WithValue(ctx, noJumpCtxKey{}, true)
}

func isNoJump(ctx context.Context) bool {
	v, _ := ctx.Value(noJumpCtxKey{}).(bool)
	return v
}

type proxyNetAddr struct {
	network string
	addr    string
}

func (a proxyNetAddr) Network() string { return a.network }
func (a proxyNetAddr) String() string  { return a.addr }

// agentProxyConn adapts an authenticated /api/net/* TCP session on a managed
// server into a standard net.Conn so ssh.NewClientConn and pinned TLS clients
// can run end-to-end from the panel through that jump server.
type agentProxyConn struct {
	p          *Panel
	jump       Server
	id         string
	localAddr  net.Addr
	remoteAddr net.Addr

	readMu  sync.Mutex
	readBuf []byte
	eof     bool

	writeMu sync.Mutex

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closed atomic.Bool
}

func dialViaAgent(ctx context.Context, p *Panel, jump Server, target string, timeout time.Duration) (*agentProxyConn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dctx, cancel := context.WithTimeout(withNoJump(ctx), timeout+6*time.Second)
	defer cancel()

	reqBody, err := json.Marshal(agent.NetProxyDialReq{
		Addr:      target,
		TimeoutMs: int(timeout.Milliseconds()),
	})
	if err != nil {
		return nil, err
	}
	status, raw, err := p.fleet.callLimit(dctx, jump, http.MethodPost, "/api/net/dial", reqBody, 64<<10)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("%s is running an older PortBridge without jump support", jump.Name)
	}
	var rep agent.NetProxyDialReply
	if jerr := json.Unmarshal(raw, &rep); jerr != nil {
		return nil, fmt.Errorf("jump server %s sent an invalid dial response (HTTP %d)", jump.Name, status)
	}
	if status != http.StatusOK || !rep.OK || rep.ID == "" {
		if rep.Error != "" {
			return nil, errors.New(rep.Error)
		}
		return nil, fmt.Errorf("jump dial via %s failed (HTTP %d)", jump.Name, status)
	}
	rem := target
	if rep.RemoteAddr != "" {
		rem = rep.RemoteAddr
	}
	return &agentProxyConn{
		p:          p,
		jump:       jump,
		id:         rep.ID,
		localAddr:  proxyNetAddr{"tcp", "jump:" + jump.ID},
		remoteAddr: proxyNetAddr{"tcp", rem},
	}, nil
}

func (c *agentProxyConn) getReadDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}

func (c *agentProxyConn) getWriteDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func (c *agentProxyConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		if c.eof {
			return 0, io.EOF
		}
		if c.closed.Load() {
			return 0, net.ErrClosed
		}

		waitMs := 8000
		rd := c.getReadDeadline()
		if !rd.IsZero() {
			rem := time.Until(rd)
			if rem <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			if int(rem.Milliseconds()) < waitMs {
				waitMs = int(rem.Milliseconds())
				if waitMs < 50 {
					waitMs = 50
				}
			}
		}

		maxChunk := len(b)
		if maxChunk < 32*1024 {
			maxChunk = 32 * 1024
		}
		if maxChunk > 256*1024 {
			maxChunk = 256 * 1024
		}

		reqBody, _ := json.Marshal(agent.NetProxyReadReq{
			ID:     c.id,
			Max:    maxChunk,
			WaitMs: waitMs,
		})
		callTimeout := time.Duration(waitMs)*time.Millisecond + 10*time.Second
		rctx, cancel := context.WithTimeout(withNoJump(context.Background()), callTimeout)
		status, raw, err := c.p.fleet.callLimit(rctx, c.jump, http.MethodPost, "/api/net/read", reqBody, 2<<20)
		cancel()
		if err != nil {
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			if !rd.IsZero() && time.Now().After(rd) {
				return 0, os.ErrDeadlineExceeded
			}
			return 0, err
		}

		var rep agent.NetProxyIOReply
		if jerr := json.Unmarshal(raw, &rep); jerr != nil {
			return 0, fmt.Errorf("jump read decode failed (HTTP %d): %w", status, jerr)
		}
		if rep.Data != "" {
			decoded, derr := base64.StdEncoding.DecodeString(rep.Data)
			if derr != nil {
				return 0, derr
			}
			c.readBuf = append(c.readBuf, decoded...)
		}
		if rep.EOF {
			c.eof = true
		}
		if !rep.OK && rep.Error != "" {
			if len(c.readBuf) > 0 {
				c.eof = true
				continue
			}
			return 0, errors.New(rep.Error)
		}
	}
}

func (c *agentProxyConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxChunk = 512 * 1024
	total := 0
	for len(b) > 0 {
		if c.closed.Load() {
			return total, net.ErrClosed
		}
		chunk := b
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		b = b[len(chunk):]

		wd := c.getWriteDeadline()
		var wctx context.Context
		var cancel context.CancelFunc
		if !wd.IsZero() {
			if time.Now().After(wd) {
				return total, os.ErrDeadlineExceeded
			}
			wctx, cancel = context.WithDeadline(withNoJump(context.Background()), wd)
		} else {
			wctx, cancel = context.WithTimeout(withNoJump(context.Background()), 60*time.Second)
		}

		reqBody, _ := json.Marshal(agent.NetProxyWriteReq{
			ID:   c.id,
			Data: base64.StdEncoding.EncodeToString(chunk),
		})
		status, raw, err := c.p.fleet.callLimit(wctx, c.jump, http.MethodPost, "/api/net/write", reqBody, 64<<10)
		cancel()
		if err != nil {
			if !wd.IsZero() && time.Now().After(wd) {
				return total, os.ErrDeadlineExceeded
			}
			return total, err
		}
		var rep agent.NetProxyIOReply
		if jerr := json.Unmarshal(raw, &rep); jerr != nil {
			return total, fmt.Errorf("jump write decode failed (HTTP %d): %w", status, jerr)
		}
		total += rep.N
		if status != http.StatusOK || !rep.OK {
			if rep.Error != "" {
				return total, errors.New(rep.Error)
			}
			return total, fmt.Errorf("jump write failed (HTTP %d)", status)
		}
	}
	return total, nil
}

func (c *agentProxyConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	go func() {
		ctx, cancel := context.WithTimeout(withNoJump(context.Background()), 5*time.Second)
		defer cancel()
		reqBody, _ := json.Marshal(map[string]string{"id": c.id})
		_, _, _ = c.p.fleet.callLimit(ctx, c.jump, http.MethodPost, "/api/net/close", reqBody, 16<<10)
	}()
	return nil
}

func (c *agentProxyConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *agentProxyConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *agentProxyConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *agentProxyConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *agentProxyConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

// jumpCandidates lists online servers eligible to relay outbound TCP to targetHost.
// When explicitID names a specific server, only that server is returned.
func (p *Panel) jumpCandidates(targetHost, preferGroup, explicitID string) []Server {
	st := p.store.get()
	explicitID = strings.TrimSpace(explicitID)
	if explicitID == "direct" {
		return nil
	}
	if explicitID != "" && explicitID != "auto" {
		for _, s := range st.Servers {
			if s.ID == explicitID && !strings.EqualFold(s.Address, targetHost) {
				return []Server{s}
			}
		}
		return nil
	}

	p.fleet.mu.Lock()
	onlineMap := make(map[string]bool, len(st.Servers))
	for _, s := range st.Servers {
		if h := p.fleet.by[s.ID]; h != nil && h.err == nil && time.Since(h.at) < 3*refreshEvery {
			onlineMap[s.ID] = true
		} else if p.hub.connected(s.ID) {
			onlineMap[s.ID] = true
		}
	}
	p.fleet.mu.Unlock()

	var cands []Server
	for _, s := range st.Servers {
		if strings.EqualFold(s.Address, targetHost) {
			continue
		}
		if onlineMap[s.ID] {
			cands = append(cands, s)
		}
	}
	wantGroup := preferGroup
	if wantGroup == "" {
		wantGroup = GroupForeign
	}
	sort.SliceStable(cands, func(i, j int) bool {
		gi := cands[i].Group == wantGroup
		gj := cands[j].Group == wantGroup
		return gi && !gj
	})
	return cands
}

func (p *Panel) dialTargetTCP(ctx context.Context, j *job, address string, port int, preferGroup, viaID string) (net.Conn, string, error) {
	addr := net.JoinHostPort(address, strconv.Itoa(port))
	viaID = strings.TrimSpace(viaID)

	// Explicit server jump requested by the user.
	if viaID != "" && viaID != "auto" && viaID != "direct" {
		cands := p.jumpCandidates(address, preferGroup, viaID)
		if len(cands) == 0 {
			return nil, "", errors.New("the selected jump server is not in the panel")
		}
		cand := cands[0]
		if j != nil {
			j.say("Connecting to %s over SSH via %s...", addr, cand.Name)
		}
		conn, err := dialViaAgent(ctx, p, cand, addr, 12*time.Second)
		if err != nil {
			return nil, "", err
		}
		return conn, cand.Name, nil
	}

	cands := p.jumpCandidates(address, preferGroup, viaID)
	directTimeout := 15 * time.Second
	if len(cands) > 0 {
		directTimeout = 8 * time.Second
	}
	if j != nil {
		j.say("Connecting to %s over SSH...", addr)
	}
	d := &net.Dialer{Timeout: directTimeout}
	conn, derr := d.DialContext(ctx, "tcp", addr)
	if derr == nil {
		return conn, "", nil
	}
	if viaID == "direct" || len(cands) == 0 {
		return nil, "", derr
	}

	// Direct TCP (IPv4/IPv6) failed; try hopping through up to 3 online servers.
	if len(cands) > 3 {
		cands = cands[:3]
	}
	var lastJumpErr error
	for _, cand := range cands {
		if j != nil {
			j.say("Direct SSH did not answer (%v); trying jump route via %s...", plainSSHError(derr), cand.Name)
		}
		jconn, jerr := dialViaAgent(ctx, p, cand, addr, 10*time.Second)
		if jerr == nil {
			return jconn, cand.Name, nil
		}
		lastJumpErr = jerr
	}
	if lastJumpErr != nil && j != nil {
		j.say("Jump route also failed: %v", lastJumpErr)
	}
	return nil, "", derr
}

func sshClientOverConn(conn net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Clear the handshake deadline so long-running install sessions only obey
	// their own per-command session timeouts.
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// fetchHostKeyMultiPath reads a server's SSH host key over direct IPv4/IPv6 or,
// if blocked, through an online jump server without sending any credentials.
func (p *Panel) fetchHostKeyMultiPath(ctx context.Context, address string, port int, preferGroup, viaID string) (string, string, error) {
	if port == 0 {
		port = 22
	}
	if address == "" || strings.ContainsAny(address, " /\\@") || len(address) > 253 {
		return "", "", errors.New("give the server's address: an IP address or a host name")
	}
	if port < 1 || port > 65535 {
		return "", "", errors.New("the SSH port must be from 1 to 65535")
	}
	conn, viaName, err := p.dialTargetTCP(ctx, nil, address, port, preferGroup, viaID)
	if err != nil {
		return "", "", plainSSHError(err)
	}
	defer conn.Close()

	var seen string
	cfg := &ssh.ClientConfig{
		User: "root",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			return errHostKeySeen
		},
		Timeout: 15 * time.Second,
	}
	_, err = sshClientOverConn(conn, net.JoinHostPort(address, strconv.Itoa(port)), cfg)
	if seen != "" {
		return seen, viaName, nil
	}
	if err == nil {
		err = errors.New("no host key was offered")
	}
	return "", "", plainSSHError(err)
}

func (p *Panel) dialSSHClient(ctx context.Context, j *job, address string, port int, cfg *ssh.ClientConfig, preferGroup, viaID string) (*ssh.Client, string, error) {
	conn, viaName, err := p.dialTargetTCP(ctx, j, address, port, preferGroup, viaID)
	if err != nil {
		return nil, "", plainSSHError(err)
	}
	client, err := sshClientOverConn(conn, net.JoinHostPort(address, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, "", plainSSHError(err)
	}
	return client, viaName, nil
}

func agentTargetAddrs(srv Server) []string {
	var out []string
	seen := map[string]bool{}
	add := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return
		}
		if !seen[u.Host] {
			seen[u.Host] = true
			out = append(out, u.Host)
		}
	}
	add(srv.AgentURL)
	if port := agentURLPort(srv.AgentURL); port != "" {
		for _, ip := range srv.IPv6 {
			h := net.JoinHostPort(ip, port)
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// callAgentViaJump sends one pinned HTTPS request to srv by tunneling the TCP
// connection through jump's /api/net/* proxy. End-to-end TLS certificate
// pinning against srv.Fingerprint is enforced inside the panel.
func (p *Panel) callAgentViaJump(ctx context.Context, srv, jump Server, token, method, path string, body []byte, limit int64, dialTimeout time.Duration) (int, []byte, error) {
	targets := agentTargetAddrs(srv)
	if len(targets) == 0 {
		return 0, nil, errors.New("server has no agent URL")
	}
	var lastErr error
	for _, target := range targets {
		baseDial := func(dctx context.Context, _, _ string) (net.Conn, error) {
			return dialViaAgent(dctx, p, jump, target, dialTimeout)
		}
		req, err := http.NewRequestWithContext(withNoJump(ctx), method, "https://"+target+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		client := agent.NewPinnedClientOpts(srv.Fingerprint, "https://"+target, 2*time.Minute, baseDial, false)
		resp, err := client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "does not match the saved fingerprint") {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, limit))
		_ = resp.Body.Close()
		return resp.StatusCode, b, rerr
	}
	if lastErr == nil {
		lastErr = errors.New("could not reach agent via jump")
	}
	return 0, nil, lastErr
}

// tryJumpOverview verifies during server setup that the panel can reach srv's
// pinned HTTPS agent via an online peer server when direct & hub paths are blocked.
func (p *Panel) tryJumpOverview(srv Server, preferViaID string) (*agent.Overview, string, error) {
	token, err := p.store.open(srv.TokenEnc)
	if err != nil {
		return nil, "", err
	}
	var cands []Server
	if preferViaID != "" && preferViaID != "auto" && preferViaID != "direct" {
		cands = append(cands, p.jumpCandidates(srv.Address, srv.Group, preferViaID)...)
	}
	for _, c := range p.jumpCandidates(srv.Address, srv.Group, "") {
		dup := false
		for _, ex := range cands {
			if ex.ID == c.ID {
				dup = true
				break
			}
		}
		if !dup {
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 {
		return nil, "", errors.New("no online jump servers available")
	}
	if len(cands) > 3 {
		cands = cands[:3]
	}
	var lastErr error
	for _, cand := range cands {
		ctx, cancel := context.WithTimeout(withNoJump(context.Background()), 14*time.Second)
		status, raw, err := p.callAgentViaJump(ctx, srv, cand, token, http.MethodGet, "/api/overview", nil, overviewLimit, 8*time.Second)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if status != http.StatusOK {
			lastErr = fmt.Errorf("agent answered HTTP %d", status)
			continue
		}
		var ov agent.Overview
		if err := json.Unmarshal(raw, &ov); err != nil {
			lastErr = err
			continue
		}
		p.fleet.recordJump(srv.ID, cand.ID)
		return &ov, cand.Name, nil
	}
	if lastErr == nil {
		lastErr = errors.New("jump overview failed")
	}
	return nil, "", lastErr
}

// ---------------------------------------------------------------------------
// 1-Line Join Tickets (Zero-SSH Server Pairing)
// ---------------------------------------------------------------------------

const joinTicketTTL = 15 * time.Minute

type joinTicket struct {
	id         string
	secret     string
	group      string
	name       string
	expires    time.Time
	claiming   bool
	done       bool
	serverID   string
	serverName string
}

func (p *Panel) pruneTicketsLocked() {
	now := time.Now()
	for id, t := range p.tickets {
		if !t.done && now.After(t.expires) {
			delete(p.tickets, id)
		} else if t.done && now.After(t.expires.Add(30*time.Minute)) {
			delete(p.tickets, id)
		}
	}
}

func (p *Panel) sameArchArchiveSHA256() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return ""
	}
	files := []pkgFile{{"portbridge", 0o755, bin}}
	for _, f := range installedFiles {
		b, err := os.ReadFile(f.path)
		if err != nil {
			if strings.HasSuffix(f.name, "panel.service") {
				continue
			}
			return ""
		}
		files = append(files, pkgFile{f.name, 0o755, b})
	}
	arc, err := packArchive(files)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(arc)
	return hex.EncodeToString(sum[:])
}

func (p *Panel) handleCreateJoinTicket(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Group string `json:"group"`
		Name  string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Group = strings.TrimSpace(req.Group)
	req.Name = strings.TrimSpace(req.Name)
	if !validGroup(req.Group) {
		writeErr(w, http.StatusBadRequest, "Choose whether this is a relay (Iran) or a foreign server.")
		return
	}
	if len(req.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "The name can be at most 64 characters.")
		return
	}
	cbURLs := p.allCallbackURLs()
	if cbURLs == "" {
		cbURLs = p.publicURL()
	}
	fp := p.ownFingerprint()
	if cbURLs == "" || fp == "" {
		writeErr(w, http.StatusBadRequest, "The panel does not know its own public address yet; set Public URL or Domain in portbridge-menu -> Web panel.")
		return
	}

	t := &joinTicket{
		id:      newID(8),
		secret:  randomToken(),
		group:   req.Group,
		name:    req.Name,
		expires: time.Now().Add(joinTicketTTL),
	}
	p.ticketsMu.Lock()
	if p.tickets == nil {
		p.tickets = map[string]*joinTicket{}
	}
	p.pruneTicketsLocked()
	p.tickets[t.id] = t
	p.ticketsMu.Unlock()

	pairCmd := fmt.Sprintf("/usr/local/bin/portbridge agent pair-panel -panel-url %s -panel-fingerprint %s -ticket %s",
		shellQuote(cbURLs), shellQuote(fp), shellQuote(t.secret))
	githubCmd := "curl -fsSL https://raw.githubusercontent.com/Nima786/portbridge/main/install.sh | sudo bash -s -- --no-menu && sudo " + pairCmd

	var panelBootstrapCmd string
	firstURL := strings.Split(cbURLs, ",")[0]
	if sha := p.sameArchArchiveSHA256(); sha != "" && firstURL != "" {
		bootURL := strings.TrimRight(firstURL, "/") + "/hub/bootstrap/" + t.secret + "?arch=" + runtime.GOARCH
		panelBootstrapCmd = fmt.Sprintf(
			"sudo bash -c 'set -e; d=$(mktemp -d); trap \"rm -rf $d\" EXIT; curl -fsSLk %s -o \"$d/pb.tgz\"; echo \"%s  $d/pb.tgz\" | sha256sum -c -; tar -xzf \"$d/pb.tgz\" -C \"$d\"; bash \"$d/install.sh\" --from-dir \"$d\" --no-menu' && sudo %s",
			shellQuote(bootURL), sha, pairCmd,
		)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ticket_id":     t.id,
		"expires_in":    int(joinTicketTTL / time.Second),
		"command":       githubCmd,
		"panel_command": panelBootstrapCmd,
		"panel_arch":    runtime.GOARCH,
		"callback_urls": cbURLs,
	})
}

func (p *Panel) handleGetJoinTicket(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	p.ticketsMu.Lock()
	p.pruneTicketsLocked()
	t := p.tickets[id]
	if t == nil {
		p.ticketsMu.Unlock()
		writeErr(w, http.StatusNotFound, "That join command has expired; generate a new one.")
		return
	}
	resp := map[string]any{
		"done":        t.done,
		"server_id":   t.serverID,
		"server_name": t.serverName,
		"expires_in":  max(0, int(time.Until(t.expires)/time.Second)),
	}
	p.ticketsMu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (p *Panel) handleHubBootstrap(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimSpace(r.PathValue("ticket"))
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	p.ticketsMu.Lock()
	p.pruneTicketsLocked()
	valid := false
	for _, t := range p.tickets {
		if !t.done && subtle.ConstantTimeCompare([]byte(t.secret), []byte(secret)) == 1 {
			valid = true
		}
	}
	p.ticketsMu.Unlock()
	if !valid {
		http.Error(w, "invalid or expired bootstrap ticket", http.StatusUnauthorized)
		return
	}

	arch := archName(r.URL.Query().Get("arch"))
	if arch == "" {
		arch = runtime.GOARCH
	}
	agent.ExtendDeadlines(w, 5*time.Minute)
	arc, err := p.archiveFor(arch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(arc)
}

func (p *Panel) handleHubRegister(w http.ResponseWriter, r *http.Request) {
	var req agent.HubRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, agent.HubRegisterReply{OK: false, Error: "invalid registration JSON"})
		return
	}
	secret := strings.TrimSpace(req.Ticket)
	if secret == "" || strings.TrimSpace(req.Token) == "" || strings.TrimSpace(req.Fingerprint) == "" || req.Port < 1 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, agent.HubRegisterReply{OK: false, Error: "missing ticket, token, fingerprint, or valid agent port"})
		return
	}

	p.ticketsMu.Lock()
	p.pruneTicketsLocked()
	var matched *joinTicket
	for _, t := range p.tickets {
		if !t.done && !t.claiming && subtle.ConstantTimeCompare([]byte(t.secret), []byte(secret)) == 1 {
			matched = t
		}
	}
	if matched == nil {
		p.ticketsMu.Unlock()
		writeJSON(w, http.StatusUnauthorized, agent.HubRegisterReply{OK: false, Error: "join ticket is invalid, expired, or already used"})
		return
	}
	matched.claiming = true
	group := matched.group
	wantName := matched.name
	p.ticketsMu.Unlock()

	releaseClaim := func() {
		p.ticketsMu.Lock()
		if !matched.done {
			matched.claiming = false
		}
		p.ticketsMu.Unlock()
	}

	addr := ""
	if len(req.IPv4) > 0 && strings.TrimSpace(req.IPv4[0]) != "" {
		addr = strings.TrimSpace(req.IPv4[0])
	} else if len(req.IPv6) > 0 && strings.TrimSpace(req.IPv6[0]) != "" {
		addr = strings.TrimSpace(req.IPv6[0])
	} else if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		addr = host
	}
	if addr == "" {
		releaseClaim()
		writeJSON(w, http.StatusBadRequest, agent.HubRegisterReply{OK: false, Error: "could not determine server address"})
		return
	}

	for _, s := range p.store.get().Servers {
		if strings.EqualFold(s.Address, addr) {
			releaseClaim()
			writeJSON(w, http.StatusConflict, agent.HubRegisterReply{
				OK:    false,
				Error: fmt.Sprintf("%s is already in the panel as %q", addr, s.Name),
			})
			return
		}
	}

	tokEnc, err := p.store.seal(strings.TrimSpace(req.Token))
	if err != nil {
		releaseClaim()
		writeJSON(w, http.StatusInternalServerError, agent.HubRegisterReply{OK: false, Error: "could not seal agent token"})
		return
	}

	name := wantName
	if name == "" {
		name = strings.TrimSpace(req.Hostname)
	}
	if name == "" {
		name = addr
	}

	srv := Server{
		ID:          newID(9),
		Name:        name,
		Group:       group,
		Address:     addr,
		IPv6:        append([]string(nil), req.IPv6...),
		AgentURL:    "https://" + net.JoinHostPort(addr, strconv.Itoa(req.Port)),
		Fingerprint: strings.TrimSpace(req.Fingerprint),
		TokenEnc:    tokEnc,
		CallsPanel:  true,
		StandbyHub:  true,
		Added:       time.Now().UTC(),
	}

	if err := p.store.update(func(st *State) error {
		st.Servers = append(st.Servers, srv)
		return nil
	}); err != nil {
		releaseClaim()
		writeJSON(w, http.StatusInternalServerError, agent.HubRegisterReply{OK: false, Error: err.Error()})
		return
	}

	p.ticketsMu.Lock()
	matched.done = true
	matched.claiming = false
	matched.serverID = srv.ID
	matched.serverName = srv.Name
	p.ticketsMu.Unlock()

	logf("paired server %q (%s) via 1-line join ticket", srv.Name, srv.Address)

	go func(s Server) {
		p.fleet.refresh(s)
		for i := 0; i < 12; i++ {
			if p.hub.connected(s.ID) {
				p.fleet.refresh(s)
				return
			}
			time.Sleep(time.Second)
		}
		p.fleet.refresh(s)
	}(srv)

	writeJSON(w, http.StatusOK, agent.HubRegisterReply{
		OK:       true,
		ServerID: srv.ID,
		Name:     srv.Name,
	})
}

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sniHandoffMagic      = "PBSH\x01"
	sniHandoffModeFD     = 1
	sniHandoffModeStream = 2
	maxRoutingPeekBytes  = 16 * 1024
	sniManifestMaxAgeSec = 25
	sniCacheTTL          = 250 * time.Millisecond
)

type sniPeerEntry struct {
	Version     int      `json:"version"`
	Tunnel      string   `json:"tunnel"`
	Port        int      `json:"port"`
	Hosts       []string `json:"hosts,omitempty"`
	WebsiteWWW  bool     `json:"website_www,omitempty"`
	Default     bool     `json:"default,omitempty"`
	Network     string   `json:"network"`
	Address     string   `json:"address"`
	Token       string   `json:"token"`
	PID         int      `json:"pid"`
	UpdatedUnix int64    `json:"updated_unix"`
}

type sniPortCache struct {
	fetchedAt time.Time
	entries   []sniPeerEntry
}

type sniRouter struct {
	e          *edge
	dir        string
	ports      []int
	hosts      []string
	websiteWWW bool
	isDefault  bool

	ln         net.Listener
	network    string
	address    string
	cleanupLn  func()
	tokenBytes [32]byte
	tokenHex   string

	peekSem chan struct{}

	mu    sync.Mutex
	cache map[int]sniPortCache

	closeOnce sync.Once
}

type handoffAddrConn struct {
	net.Conn
	raddr net.Addr
	laddr net.Addr
}

func (h *handoffAddrConn) RemoteAddr() net.Addr {
	if h.raddr != nil {
		return h.raddr
	}
	return h.Conn.RemoteAddr()
}

func (h *handoffAddrConn) LocalAddr() net.Addr {
	if h.laddr != nil {
		return h.laddr
	}
	return h.Conn.LocalAddr()
}

func (h *handoffAddrConn) CloseWrite() error {
	if cw, ok := h.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func listenUserTCP(addr string, shared bool) (net.Listener, error) {
	if shared {
		return listenSharedTCP(addr)
	}
	return net.Listen("tcp", addr)
}

func newSNIRouter(ctx context.Context, e *edge, ports []int) (*sniRouter, error) {
	dir := e.cfg.SharedRouteDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("preparing shared route directory %s: %w", dir, err)
	}

	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, fmt.Errorf("generating shared route token: %w", err)
	}
	tokHex := hex.EncodeToString(tok[:])
	shortID := tokHex[:8]

	sweepOrphanHandoffSockets(dir, e.cfg.Name)

	ln, network, address, cleanupLn, err := openHandoffListener(dir, e.cfg.Name, shortID)
	if err != nil {
		return nil, fmt.Errorf("opening local SNI handoff listener: %w", err)
	}

	dedupPorts := make([]int, 0, len(ports))
	seenP := make(map[int]bool, len(ports))
	for _, p := range ports {
		if p > 0 && !seenP[p] {
			seenP[p] = true
			dedupPorts = append(dedupPorts, p)
		}
	}

	hosts := e.cfg.EffectiveRouteHosts()
	websiteWWW := e.cfg.WebsiteBridge && strings.TrimSpace(e.cfg.RouteHosts) == ""

	r := &sniRouter{
		e:          e,
		dir:        dir,
		ports:      dedupPorts,
		hosts:      hosts,
		websiteWWW: websiteWWW,
		isDefault:  e.cfg.RouteDefault,
		ln:         ln,
		network:    network,
		address:    address,
		cleanupLn:  cleanupLn,
		tokenBytes: tok,
		tokenHex:   tokHex,
		peekSem:    make(chan struct{}, 512),
		cache:      make(map[int]sniPortCache),
	}

	if err := r.writeManifests(); err != nil {
		cleanupLn()
		return nil, err
	}

	go r.acceptHandoffs(ctx)
	go r.heartbeatLoop(ctx)
	return r, nil
}

func sweepOrphanHandoffSockets(dir, tunnelName string) {
	pattern := filepath.Join(dir, fmt.Sprintf("sni-h-%s-*.sock", tunnelName))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, m := range matches {
		c, err := net.DialTimeout("unix", m, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			continue
		}
		_ = os.Remove(m)
	}
}

func (r *sniRouter) manifestPath(port int) string {
	return filepath.Join(r.dir, fmt.Sprintf("sni-port-%d-%s.json", port, r.e.cfg.Name))
}

func (r *sniRouter) selfEntry(port int, nowUnix int64) sniPeerEntry {
	return sniPeerEntry{
		Version:     1,
		Tunnel:      r.e.cfg.Name,
		Port:        port,
		Hosts:       r.hosts,
		WebsiteWWW:  r.websiteWWW,
		Default:     r.isDefault,
		Network:     r.network,
		Address:     r.address,
		Token:       r.tokenHex,
		PID:         os.Getpid(),
		UpdatedUnix: nowUnix,
	}
}

func (r *sniRouter) writeManifests() error {
	now := time.Now().Unix()
	for _, port := range r.ports {
		entry := r.selfEntry(port, now)
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		dst := r.manifestPath(port)
		tmp := fmt.Sprintf("%s.tmp.%d.%s", dst, os.Getpid(), r.tokenHex[:8])
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			return fmt.Errorf("writing shared route manifest %s: %w", dst, err)
		}
		_ = os.Chmod(tmp, 0o600)
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("publishing shared route manifest %s: %w", dst, err)
		}
	}
	return nil
}

func (r *sniRouter) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.writeManifests()
		}
	}
}

func (r *sniRouter) Close() {
	r.closeOnce.Do(func() {
		if r.cleanupLn != nil {
			r.cleanupLn()
		}
		for _, port := range r.ports {
			p := r.manifestPath(port)
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var cur sniPeerEntry
			if json.Unmarshal(raw, &cur) == nil && cur.Token == r.tokenHex {
				_ = os.Remove(p)
			}
		}
	})
}

func (r *sniRouter) loadPeersForPort(port int, force bool) []sniPeerEntry {
	now := time.Now()
	r.mu.Lock()
	if !force {
		if c, ok := r.cache[port]; ok && now.Sub(c.fetchedAt) < sniCacheTTL {
			out := make([]sniPeerEntry, len(c.entries))
			copy(out, c.entries)
			r.mu.Unlock()
			return out
		}
	}
	r.mu.Unlock()

	pattern := filepath.Join(r.dir, fmt.Sprintf("sni-port-%d-*.json", port))
	files, _ := filepath.Glob(pattern)
	nowUnix := now.Unix()
	byTunnel := make(map[string]sniPeerEntry, len(files)+1)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var e sniPeerEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		if e.Port != port || e.Tunnel == "" || e.Address == "" || len(e.Token) != 64 {
			continue
		}
		if nowUnix-e.UpdatedUnix > sniManifestMaxAgeSec {
			continue
		}
		byTunnel[e.Tunnel] = e
	}
	byTunnel[r.e.cfg.Name] = r.selfEntry(port, nowUnix)

	entries := make([]sniPeerEntry, 0, len(byTunnel))
	for _, e := range byTunnel {
		entries = append(entries, e)
	}

	r.mu.Lock()
	r.cache[port] = sniPortCache{
		fetchedAt: now,
		entries:   entries,
	}
	out := make([]sniPeerEntry, len(entries))
	copy(out, entries)
	r.mu.Unlock()
	return out
}

type scoredPeer struct {
	entry sniPeerEntry
	score int
}

func (r *sniRouter) candidatesFor(port int, host string, forceReload bool) ([]sniPeerEntry, bool) {
	peers := r.loadPeersForPort(port, forceReload)
	var hostMatches []scoredPeer
	var defaults []scoredPeer
	hasDefault := false

	for _, p := range peers {
		if p.Default {
			hasDefault = true
			defaults = append(defaults, scoredPeer{entry: p, score: 1})
		}
		if host != "" && len(p.Hosts) > 0 {
			if ok, sc := MatchRouteHost(host, p.Hosts, p.WebsiteWWW); ok {
				hostMatches = append(hostMatches, scoredPeer{entry: p, score: sc})
			}
		}
	}

	sortScored := func(list []scoredPeer) {
		sort.Slice(list, func(i, j int) bool {
			if list[i].score != list[j].score {
				return list[i].score > list[j].score
			}
			iSelf := list[i].entry.Tunnel == r.e.cfg.Name
			jSelf := list[j].entry.Tunnel == r.e.cfg.Name
			if iSelf != jSelf {
				return iSelf
			}
			return list[i].entry.Tunnel < list[j].entry.Tunnel
		})
	}

	sortScored(hostMatches)
	sortScored(defaults)

	var out []sniPeerEntry
	seen := make(map[string]bool, len(hostMatches)+len(defaults))
	for _, m := range hostMatches {
		seen[m.entry.Tunnel] = true
		out = append(out, m.entry)
	}
	// Only fall back to default route when no specific host pattern matched.
	if len(out) == 0 {
		for _, d := range defaults {
			if !seen[d.entry.Tunnel] {
				seen[d.entry.Tunnel] = true
				out = append(out, d.entry)
			}
		}
	}
	return out, hasDefault
}

func (r *sniRouter) handleAcceptedConn(ctx context.Context, user net.Conn, listenPort int) {
	select {
	case r.peekSem <- struct{}{}:
		go func() {
			defer func() { <-r.peekSem }()
			r.routeIncoming(ctx, user, listenPort)
		}()
	default:
		_ = user.Close()
		atomic.AddInt64(&r.e.st.droppedSessions, 1)
	}
}

func (r *sniRouter) routeIncoming(ctx context.Context, user net.Conn, listenPort int) {
	head, host, _, err := peekRoutingPayload(user, headWaitTimeout)
	if err != nil {
		_ = user.Close()
		if errors.Is(err, errUserWentAway) {
			atomic.AddInt64(&r.e.st.emptyConnections, 1)
		}
		return
	}

	candidates, hasDefault := r.candidatesFor(listenPort, host, false)
	if len(candidates) == 0 && len(head) == 0 && !hasDefault {
		// Slow mobile TLS/HTTP client on a port without a default catch-all:
		// give it one more beat to send its ClientHello / Host header.
		head, host, _, err = peekRoutingPayload(user, 2*time.Second)
		if err != nil || len(head) == 0 {
			_ = user.Close()
			atomic.AddInt64(&r.e.st.emptyConnections, 1)
			return
		}
		candidates, _ = r.candidatesFor(listenPort, host, false)
	}

	if len(candidates) == 0 {
		// Force one manifest reload in case a new sibling tunnel was created
		// within the last 250ms cache window.
		candidates, _ = r.candidatesFor(listenPort, host, true)
	}
	if len(candidates) == 0 {
		_ = user.Close()
		atomic.AddInt64(&r.e.st.emptyConnections, 1)
		return
	}

	reloaded := false
	for i := 0; i < len(candidates); i++ {
		cand := candidates[i]
		if cand.Tunnel == r.e.cfg.Name {
			targetPort := r.e.cfg.TargetPortFor(strconv.Itoa(listenPort))
			r.e.admitAndServeUser(ctx, user, true, head, targetPort)
			return
		}
		if err := r.handoffToPeer(cand, user, uint16(listenPort), head); err == nil {
			return
		}
		if !reloaded {
			reloaded = true
			fresh, _ := r.candidatesFor(listenPort, host, true)
			for _, f := range fresh {
				if f.Tunnel == cand.Tunnel && (f.Address != cand.Address || f.Token != cand.Token) {
					if err := r.handoffToPeer(f, user, uint16(listenPort), head); err == nil {
						return
					}
				}
			}
		}
	}

	_ = user.Close()
	atomic.AddInt64(&r.e.st.failedSessions, 1)
}

func (r *sniRouter) handoffToPeer(peer sniPeerEntry, user net.Conn, listenPort uint16, head []byte) error {
	tokBytes, err := hex.DecodeString(peer.Token)
	if err != nil || len(tokBytes) != 32 {
		return errors.New("invalid peer token")
	}
	hc, err := net.DialTimeout(peer.Network, peer.Address, 750*time.Millisecond)
	if err != nil {
		return err
	}

	_ = hc.SetDeadline(time.Now().Add(3 * time.Second))
	uc, rights, useFD := prepareConnFDRights(hc, user)
	mode := byte(sniHandoffModeStream)
	if useFD {
		mode = sniHandoffModeFD
	}

	raddrStr := ""
	laddrStr := ""
	if mode == sniHandoffModeStream {
		if user.RemoteAddr() != nil {
			raddrStr = user.RemoteAddr().String()
		}
		if user.LocalAddr() != nil {
			laddrStr = user.LocalAddr().String()
		}
	}

	bufSize := 5 + 32 + 2 + 1 + 4 + len(head)
	if mode == sniHandoffModeStream {
		bufSize += 2 + len(raddrStr) + 2 + len(laddrStr)
	}
	buf := make([]byte, 0, bufSize)
	buf = append(buf, sniHandoffMagic...)
	buf = append(buf, tokBytes...)
	var p2 [2]byte
	binary.BigEndian.PutUint16(p2[:], listenPort)
	buf = append(buf, p2[:]...)
	buf = append(buf, mode)
	var h4 [4]byte
	binary.BigEndian.PutUint32(h4[:], uint32(len(head)))
	buf = append(buf, h4[:]...)
	buf = append(buf, head...)

	if mode == sniHandoffModeStream {
		binary.BigEndian.PutUint16(p2[:], uint16(len(raddrStr)))
		buf = append(buf, p2[:]...)
		buf = append(buf, raddrStr...)
		binary.BigEndian.PutUint16(p2[:], uint16(len(laddrStr)))
		buf = append(buf, p2[:]...)
		buf = append(buf, laddrStr...)
	}

	if err := writeAll(hc, buf); err != nil {
		_ = hc.Close()
		return err
	}

	if mode == sniHandoffModeFD {
		if err := sendPreparedConnFD(uc, rights); err != nil {
			_ = hc.Close()
			return err
		}
	}

	var ack [1]byte
	if _, err := io.ReadFull(hc, ack[:]); err != nil || ack[0] != 0x01 {
		_ = hc.Close()
		if err != nil {
			return err
		}
		return errors.New("peer rejected SNI handoff")
	}
	_ = hc.SetDeadline(time.Time{})

	if mode == sniHandoffModeFD {
		_ = hc.Close()
		_ = user.Close()
		return nil
	}

	go func() {
		_ = relay(user, hc)
	}()
	return nil
}

func (r *sniRouter) acceptHandoffs(ctx context.Context) {
	for {
		hc, err := r.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(25 * time.Millisecond)
			continue
		}
		go r.serveHandoff(ctx, hc)
	}
}

func (r *sniRouter) serveHandoff(ctx context.Context, hc net.Conn) {
	_ = hc.SetDeadline(time.Now().Add(3 * time.Second))
	var hdr [44]byte // 5 magic + 32 token + 2 port + 1 mode + 4 headLen
	if _, err := io.ReadFull(hc, hdr[:]); err != nil {
		_ = hc.Close()
		return
	}
	if string(hdr[:5]) != sniHandoffMagic {
		_ = hc.Close()
		return
	}
	if subtle.ConstantTimeCompare(hdr[5:37], r.tokenBytes[:]) != 1 {
		_ = hc.Close()
		return
	}

	listenPort := binary.BigEndian.Uint16(hdr[37:39])
	mode := hdr[39]
	headLen := binary.BigEndian.Uint32(hdr[40:44])
	if headLen > maxRoutingPeekBytes {
		_ = hc.Close()
		return
	}

	var head []byte
	if headLen > 0 {
		head = make([]byte, headLen)
		if _, err := io.ReadFull(hc, head); err != nil {
			_ = hc.Close()
			return
		}
	}

	targetPort := r.e.cfg.TargetPortFor(strconv.Itoa(int(listenPort)))

	switch mode {
	case sniHandoffModeFD:
		userConn, err := recvConnFD(hc)
		if err != nil {
			_ = hc.Close()
			return
		}
		_, _ = hc.Write([]byte{0x01})
		_ = hc.Close()
		r.e.admitAndServeUser(ctx, userConn, true, head, targetPort)

	case sniHandoffModeStream:
		raddrStr, ok := readLenPrefixedAddr(hc)
		if !ok {
			_ = hc.Close()
			return
		}
		laddrStr, ok := readLenPrefixedAddr(hc)
		if !ok {
			_ = hc.Close()
			return
		}
		if _, err := hc.Write([]byte{0x01}); err != nil {
			_ = hc.Close()
			return
		}
		_ = hc.SetDeadline(time.Time{})
		wrapped := &handoffAddrConn{
			Conn:  hc,
			raddr: parseTCPAddrOrNil(raddrStr),
			laddr: parseTCPAddrOrNil(laddrStr),
		}
		r.e.admitAndServeUser(ctx, wrapped, true, head, targetPort)

	default:
		_ = hc.Close()
	}
}

func readLenPrefixedAddr(r io.Reader) (string, bool) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n == 0 {
		return "", true
	}
	if n > 256 {
		return "", false
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", false
	}
	return string(b), true
}

func parseTCPAddrOrNil(s string) net.Addr {
	if s == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil
	}
	return &net.TCPAddr{IP: ip, Port: p}
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// peekRoutingPayload reads the opening bytes from user, reassembling fragmented
// TLS ClientHello records or HTTP request headers up to maxRoutingPeekBytes so
// SNI or Host extraction succeeds even when clients enable TCP/TLS fragmentation.
func peekRoutingPayload(user net.Conn, initialTimeout time.Duration) (head []byte, host string, isRecognized bool, err error) {
	scratch := headPool.Get().(*[]byte)
	defer headPool.Put(scratch)

	_ = user.SetReadDeadline(time.Now().Add(initialTimeout))
	n, readErr := user.Read(*scratch)
	_ = user.SetReadDeadline(time.Time{})

	if n == 0 {
		if readErr != nil && !isTimeout(readErr) {
			return nil, "", false, fmt.Errorf("%w: %v", errUserWentAway, readErr)
		}
		return nil, "", false, nil
	}

	head = make([]byte, n)
	copy(head, (*scratch)[:n])

	// Reassemble fragmented TLS Handshake (ClientHello) bytes if needed.
	if head[0] == 0x16 && (len(head) < 2 || head[1] == 0x03) {
		deadline := time.Now().Add(1500 * time.Millisecond)
		for len(head) < maxRoutingPeekBytes && !tlsClientHelloComplete(head) {
			_ = user.SetReadDeadline(deadline)
			m, moreErr := user.Read(*scratch)
			if m > 0 {
				limit := maxRoutingPeekBytes - len(head)
				if m > limit {
					m = limit
				}
				head = append(head, (*scratch)[:m]...)
			}
			if moreErr != nil {
				break
			}
		}
		_ = user.SetReadDeadline(time.Time{})
		if sni, isTLS := extractTLSClientHelloSNI(head); isTLS {
			return head, sni, true, nil
		}
		return head, "", false, nil
	}

	// Reassemble fragmented HTTP request headers if needed.
	if looksLikeHTTPStart(head) {
		deadline := time.Now().Add(1500 * time.Millisecond)
		for len(head) < maxRoutingPeekBytes && !httpHeadersComplete(head) {
			_ = user.SetReadDeadline(deadline)
			m, moreErr := user.Read(*scratch)
			if m > 0 {
				limit := maxRoutingPeekBytes - len(head)
				if m > limit {
					m = limit
				}
				head = append(head, (*scratch)[:m]...)
			}
			if moreErr != nil {
				break
			}
		}
		_ = user.SetReadDeadline(time.Time{})
		if h, isHTTP := extractHTTPHostHeader(head); isHTTP {
			return head, normalizeWebsiteHost(h), true, nil
		}
	}

	return head, "", false, nil
}

func tlsClientHelloComplete(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0] != 0x16 || b[1] != 0x03 {
		return true
	}
	var hsLen int
	msgLen := -1
	pos := 0
	for pos < len(b) {
		if b[pos] != 0x16 {
			return true
		}
		if pos+5 > len(b) {
			return false
		}
		if b[pos+1] != 0x03 {
			return true
		}
		recLen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		if recLen > 16384+2048 {
			return true
		}
		if pos+5+recLen > len(b) {
			return false
		}
		hsLen += recLen
		pos += 5 + recLen
		if msgLen < 0 && hsLen >= 4 {
			var hdr [4]byte
			copied := 0
			p2 := 0
			for p2+5 <= pos && copied < 4 {
				rl := int(binary.BigEndian.Uint16(b[p2+3 : p2+5]))
				chunk := b[p2+5 : p2+5+rl]
				copied += copy(hdr[copied:], chunk)
				p2 += 5 + rl
			}
			if hdr[0] != 0x01 {
				return true
			}
			msgLen = int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			if msgLen > maxRoutingPeekBytes {
				return true
			}
		}
		if msgLen >= 0 && hsLen >= 4+msgLen {
			return true
		}
	}
	return false
}

func looksLikeHTTPStart(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := len(b)
	if n > 12 {
		n = 12
	}
	up := strings.ToUpper(string(b[:n]))
	for _, m := range httpMethodPrefixes {
		if len(up) < len(m) {
			if strings.HasPrefix(m, up) {
				return true
			}
		} else if strings.HasPrefix(up, m) {
			return true
		}
	}
	return false
}

func httpHeadersComplete(b []byte) bool {
	return bytes.Contains(b, []byte("\r\n\r\n")) || bytes.Contains(b, []byte("\n\n"))
}

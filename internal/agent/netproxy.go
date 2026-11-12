package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	netProxyMaxConns   = 12
	netProxyIdleExpire = 90 * time.Second
	netProxyMaxChunk   = 1 << 20 // 1 MB
)

var allowLoopbackNetProxy atomic.Bool

// SetAllowLoopbackNetProxyForTest permits loopback dials in unit tests only.
func SetAllowLoopbackNetProxyForTest(v bool) {
	allowLoopbackNetProxy.Store(v)
}

type netProxySession struct {
	id         string
	conn       net.Conn
	remoteAddr string
	lastUsed   atomic.Int64
}

func (s *netProxySession) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

var netProxyPool = struct {
	mu       sync.Mutex
	sessions map[string]*netProxySession
}{
	sessions: map[string]*netProxySession{},
}

func reapIdleNetProxyLocked() {
	cutoff := time.Now().Add(-netProxyIdleExpire).UnixNano()
	for id, s := range netProxyPool.sessions {
		if s.lastUsed.Load() < cutoff {
			_ = s.conn.Close()
			delete(netProxyPool.sessions, id)
		}
	}
}

// isAllowedNetProxyAddr blocks loopback, RFC1918 private, link-local, CGNAT,
// ULA, multicast, and unspecified addresses so the panel's jump proxy can only
// connect to public servers on the internet.
func isAllowedNetProxyAddr(ip net.IP) bool {
	if len(ip) == 0 {
		return false
	}
	if ip.IsLoopback() {
		return allowLoopbackNetProxy.Load()
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		addr = addr.Unmap()
		// Block RFC 6598 CGNAT (100.64.0.0/10) and Benchmarking (198.18.0.0/15).
		if addr.Is4() {
			b := addr.As4()
			if b[0] == 100 && (b[1]&0xc0) == 64 {
				return false
			}
			if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
				return false
			}
		}
	}
	return true
}

func dialPublicTCP(ctx context.Context, address string, timeout time.Duration) (net.Conn, string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, "", errors.New("invalid host:port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, "", errors.New("port must be between 1 and 65535")
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var ips []net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []net.IP{parsed}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, "", fmt.Errorf("could not resolve %q: %v", host, err)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}

	var allowed []net.IP
	for _, ip := range ips {
		if isAllowedNetProxyAddr(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, "", errors.New("refusing to dial private, loopback, or local address")
	}

	var lastErr error
	perTry := timeout
	if len(allowed) > 1 && perTry > 8*time.Second {
		perTry = timeout / 2
	}
	for _, ip := range allowed {
		target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		d := net.Dialer{Timeout: perTry, KeepAlive: 25 * time.Second}
		c, err := d.DialContext(rctx, "tcp", target)
		if err == nil {
			return c, c.RemoteAddr().String(), nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

func newNetProxyID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NetProxyDialReq opens an outbound TCP stream on the agent for panel jump routing.
type NetProxyDialReq struct {
	Addr      string `json:"addr"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

// NetProxyDialReply returns the opened session id.
type NetProxyDialReply struct {
	OK         bool   `json:"ok"`
	ID         string `json:"id,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NetProxyWriteReq writes bytes to an open proxy TCP stream.
type NetProxyWriteReq struct {
	ID   string `json:"id"`
	Data string `json:"data"` // base64
}

// NetProxyReadReq reads up to Max bytes from an open proxy TCP stream.
type NetProxyReadReq struct {
	ID     string `json:"id"`
	Max    int    `json:"max,omitempty"`
	WaitMs int    `json:"wait_ms,omitempty"`
}

// NetProxyIOReply answers read/write/close operations.
type NetProxyIOReply struct {
	OK    bool   `json:"ok"`
	N     int    `json:"n,omitempty"`
	Data  string `json:"data,omitempty"` // base64
	EOF   bool   `json:"eof,omitempty"`
	Error string `json:"error,omitempty"`
}

func registerNetProxyHandlers(mux *http.ServeMux, token string) {
	mux.HandleFunc("/api/net/dial", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req NetProxyDialReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || strings.TrimSpace(req.Addr) == "" {
			writeJSONReply(w, http.StatusBadRequest, NetProxyDialReply{Error: "addr is required"})
			return
		}
		timeout := time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout <= 0 || timeout > 25*time.Second {
			timeout = 12 * time.Second
		}

		netProxyPool.mu.Lock()
		reapIdleNetProxyLocked()
		busy := len(netProxyPool.sessions) >= netProxyMaxConns
		netProxyPool.mu.Unlock()
		if busy {
			writeJSONReply(w, http.StatusTooManyRequests, NetProxyDialReply{Error: "too many concurrent jump connections on this server"})
			return
		}

		conn, remote, err := dialPublicTCP(r.Context(), req.Addr, timeout)
		if err != nil {
			writeJSONReply(w, http.StatusBadGateway, NetProxyDialReply{Error: err.Error()})
			return
		}
		id, err := newNetProxyID()
		if err != nil {
			_ = conn.Close()
			writeJSONReply(w, http.StatusInternalServerError, NetProxyDialReply{Error: err.Error()})
			return
		}
		sess := &netProxySession{id: id, conn: conn, remoteAddr: remote}
		sess.touch()

		netProxyPool.mu.Lock()
		reapIdleNetProxyLocked()
		if len(netProxyPool.sessions) >= netProxyMaxConns {
			netProxyPool.mu.Unlock()
			_ = conn.Close()
			writeJSONReply(w, http.StatusTooManyRequests, NetProxyDialReply{Error: "too many concurrent jump connections on this server"})
			return
		}
		netProxyPool.sessions[id] = sess
		netProxyPool.mu.Unlock()

		writeJSONReply(w, http.StatusOK, NetProxyDialReply{OK: true, ID: id, RemoteAddr: remote})
	})

	mux.HandleFunc("/api/net/write", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req NetProxyWriteReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil || req.ID == "" {
			writeJSONReply(w, http.StatusBadRequest, NetProxyIOReply{Error: "invalid write request"})
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil || len(raw) > netProxyMaxChunk {
			writeJSONReply(w, http.StatusBadRequest, NetProxyIOReply{Error: "invalid write payload"})
			return
		}
		netProxyPool.mu.Lock()
		sess := netProxyPool.sessions[req.ID]
		netProxyPool.mu.Unlock()
		if sess == nil {
			writeJSONReply(w, http.StatusNotFound, NetProxyIOReply{Error: "connection closed"})
			return
		}
		sess.touch()
		_ = sess.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
		n, err := sess.conn.Write(raw)
		if err != nil {
			netProxyPool.mu.Lock()
			delete(netProxyPool.sessions, req.ID)
			netProxyPool.mu.Unlock()
			_ = sess.conn.Close()
			writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: false, N: n, Error: err.Error()})
			return
		}
		sess.touch()
		writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: true, N: n})
	})

	mux.HandleFunc("/api/net/read", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req NetProxyReadReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.ID == "" {
			writeJSONReply(w, http.StatusBadRequest, NetProxyIOReply{Error: "invalid read request"})
			return
		}
		maxN := req.Max
		if maxN <= 0 || maxN > 256*1024 {
			maxN = 64 * 1024
		}
		wait := time.Duration(req.WaitMs) * time.Millisecond
		if wait <= 0 {
			wait = 8 * time.Second
		} else if wait > 15*time.Second {
			wait = 15 * time.Second
		}

		netProxyPool.mu.Lock()
		sess := netProxyPool.sessions[req.ID]
		netProxyPool.mu.Unlock()
		if sess == nil {
			writeJSONReply(w, http.StatusNotFound, NetProxyIOReply{EOF: true, Error: "connection closed"})
			return
		}
		sess.touch()
		buf := make([]byte, maxN)
		_ = sess.conn.SetReadDeadline(time.Now().Add(wait))
		n, err := sess.conn.Read(buf)
		sess.touch()
		var dataStr string
		if n > 0 {
			dataStr = base64.StdEncoding.EncodeToString(buf[:n])
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: true, N: n, Data: dataStr})
				return
			}
			netProxyPool.mu.Lock()
			delete(netProxyPool.sessions, req.ID)
			netProxyPool.mu.Unlock()
			_ = sess.conn.Close()
			if errors.Is(err, io.EOF) {
				writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: true, N: n, Data: dataStr, EOF: true})
				return
			}
			writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: n > 0, N: n, Data: dataStr, EOF: true, Error: err.Error()})
			return
		}
		writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: true, N: n, Data: dataStr})
	})

	mux.HandleFunc("/api/net/close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
		if req.ID != "" {
			netProxyPool.mu.Lock()
			sess := netProxyPool.sessions[req.ID]
			delete(netProxyPool.sessions, req.ID)
			netProxyPool.mu.Unlock()
			if sess != nil {
				_ = sess.conn.Close()
			}
		}
		writeJSONReply(w, http.StatusOK, NetProxyIOReply{OK: true})
	})
}

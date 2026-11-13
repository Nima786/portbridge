//go:build !linux

package engine

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// Off Linux (for example in Windows/macOS test runs), SO_REUSEPORT with kernel
// load-balancing does not exist on TCP sockets. sharedTCPHubs provides an
// in-process equivalent so multi-tunnel shared-port tests exercise the exact
// same SNI/Host discovery and peer handoff code paths.
var (
	sharedTCPMu   sync.Mutex
	sharedTCPHubs = make(map[string]*sharedTCPHub)
)

type sharedTCPHub struct {
	key    string
	rawLn  net.Listener
	mu     sync.Mutex
	peers  []*sharedTCPPeerLn
	rr     uint64
	closed bool
}

type sharedTCPPeerLn struct {
	hub       *sharedTCPHub
	ch        chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func normalizeSharedBindKey(addr string) string {
	h, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr)
	}
	if h == "" || h == "0.0.0.0" {
		h = "0.0.0.0"
	} else if h == "::" {
		h = "::"
	}
	return net.JoinHostPort(strings.ToLower(h), p)
}

func listenSharedTCP(addr string) (net.Listener, error) {
	reqKey := normalizeSharedBindKey(addr)

	sharedTCPMu.Lock()
	defer sharedTCPMu.Unlock()

	hub := sharedTCPHubs[reqKey]
	if hub == nil {
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		actualKey := normalizeSharedBindKey(rawLn.Addr().String())
		if existing := sharedTCPHubs[actualKey]; existing != nil {
			_ = rawLn.Close()
			hub = existing
		} else {
			hub = &sharedTCPHub{
				key:   actualKey,
				rawLn: rawLn,
			}
			sharedTCPHubs[actualKey] = hub
			go hub.acceptLoop()
		}
	}

	peer := &sharedTCPPeerLn{
		hub:  hub,
		ch:   make(chan net.Conn, 128),
		done: make(chan struct{}),
	}
	hub.mu.Lock()
	hub.peers = append(hub.peers, peer)
	hub.mu.Unlock()
	return peer, nil
}

func (h *sharedTCPHub) acceptLoop() {
	for {
		c, err := h.rawLn.Accept()
		if err != nil {
			h.mu.Lock()
			closed := h.closed
			h.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		h.mu.Lock()
		n := len(h.peers)
		var target *sharedTCPPeerLn
		if n > 0 {
			idx := int(atomic.AddUint64(&h.rr, 1)-1) % n
			target = h.peers[idx]
		}
		h.mu.Unlock()

		if target == nil {
			_ = c.Close()
			continue
		}
		select {
		case target.ch <- c:
		case <-target.done:
			_ = c.Close()
		default:
			_ = c.Close()
		}
	}
}

func (p *sharedTCPPeerLn) Accept() (net.Conn, error) {
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case c, ok := <-p.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	}
}

func (p *sharedTCPPeerLn) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)

		sharedTCPMu.Lock()
		h := p.hub
		h.mu.Lock()
		for i, cur := range h.peers {
			if cur == p {
				h.peers = append(h.peers[:i], h.peers[i+1:]...)
				break
			}
		}
		empty := len(h.peers) == 0 && !h.closed
		if empty {
			h.closed = true
			delete(sharedTCPHubs, h.key)
		}
		h.mu.Unlock()
		sharedTCPMu.Unlock()

		for {
			select {
			case c := <-p.ch:
				if c != nil {
					_ = c.Close()
				}
			default:
				if empty {
					_ = h.rawLn.Close()
				}
				return
			}
		}
	})
	return nil
}

func (p *sharedTCPPeerLn) Addr() net.Addr {
	return p.hub.rawLn.Addr()
}

func openHandoffListener(_, _, _ string) (net.Listener, string, string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", nil, err
	}
	cleanup := func() {
		_ = ln.Close()
	}
	return ln, "tcp", ln.Addr().String(), cleanup, nil
}

func prepareConnFDRights(net.Conn, net.Conn) (*net.UnixConn, []byte, bool) {
	return nil, nil, false
}

func sendPreparedConnFD(*net.UnixConn, []byte) error {
	return errors.New("fd passing unsupported on this platform")
}

func recvConnFD(net.Conn) (net.Conn, error) {
	return nil, errors.New("fd passing unsupported on this platform")
}

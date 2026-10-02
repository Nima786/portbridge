package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// How long we wait for a user's opening bytes before activating a spare
	// without them. VLESS, Trojan, VMess and Shadowsocks all speak first, so in
	// practice this returns immediately. A protocol where the server speaks
	// first would pay this once per connection.
	headWaitTimeout = 1500 * time.Millisecond
	headBufferSize  = 16 * 1024

	activateWriteTimeout = 5 * time.Second

	// How long to wait for the other server to confirm it reached the service.
	//
	// Kept short on purpose. Confirmation needs one round trip plus a local
	// connection, so under a second on any working path. The old value of twenty
	// seconds meant a single silently broken spare cost the user twenty seconds
	// before anything was retried, which is far longer than any client waits, so
	// the retry never got a chance to help. Observed on a real network where
	// data could reach a server but not come back: every user gave up while the
	// tunnel was still patiently waiting.
	ackWaitTimeout = 4 * time.Second

	// Attempts, including the first, to find a spare that actually works. Higher
	// than it looks necessary because on a partly broken path a good number of
	// spares can be unusable, and each attempt discards one.
	maxActivateTries = 6

	// How long a user waits in reverse mode for the origin to supply a spare.
	reverseWaitForSpare = 5 * time.Second
)

var (
	errBadAck = errors.New("unexpected handshake reply from the other server")

	// errUserWentAway means someone connected and disconnected without sending
	// anything. That is what a port scanner looks like, and the port users
	// connect to is public, so this happens constantly and is not worth a log
	// line.
	errUserWentAway = errors.New("user disconnected before sending anything")
)

// headPool lends out room to read a user's opening bytes into. Reused rather
// than allocated per user, because on a public port most connections that reach
// here are port scans that send nothing at all.
var headPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, headBufferSize)
		return &b
	},
}

// edge faces the users. It holds the pool of ready connections and tells the
// origin when a user turns up. Its behaviour is the same in both modes; only the
// way the pool gets filled differs.
type edge struct {
	cfg  *Config
	pool *pool
	st   *status

	// links is set instead of pool when sessions share a few long-lived
	// connections. Only one of the two is ever in use.
	links *carrierSet

	active  chan struct{}
	pending chan struct{}
	wg      sync.WaitGroup

	guard *replayGuard
	cert  *tls.Certificate

	logAccept   *throttled
	logCapacity *throttled
	logSession  *throttled
	logAuth     *throttled
	logRelay    *throttled

	cancel       context.CancelFunc
	teardownOnce sync.Once
}

func runEdge(ctx context.Context, cfg *Config, st *status) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	e := &edge{
		cfg:         cfg,
		st:          st,
		cancel:      cancel,
		active:      make(chan struct{}, cfg.MaxConn),
		pending:     make(chan struct{}, cfg.MaxPending),
		guard:       newReplayGuard(ctx),
		logAccept:   newThrottled(),
		logCapacity: newThrottled(),
		logSession:  newThrottled(),
		logAuth:     newThrottled(),
		logRelay:    newThrottled(),
	}

	// In reverse mode this side accepts, so it needs a certificate before the
	// disguise can be prepared. Both are set up together, once, because a
	// connection that has to build its own is the most expensive kind.
	if cfg.Transport != TransportPlain && cfg.Transport != TransportKCP && cfg.Mode == ModeReverse {
		cert, err := ensureCert(cfg.CertFile, cfg.KeyFile, cfg.effectiveServerName())
		if err != nil {
			return fmt.Errorf("preparing the disguise: %w", err)
		}
		e.cert = &cert
	}
	cfg.prepareTLS(e.cert)

	// Direct mode: we dial the origin ourselves, so connections can be built on
	// demand. Reverse mode: we cannot dial anywhere, so we wait to be called.
	var dial func() (net.Conn, error)
	if cfg.Mode == ModeDirect {
		routes := newRouter(cfg)
		st.routes = routes
		log.Printf("reaching the other server at %s", routes.describe())
		dial = func() (net.Conn, error) {
			raw, claim, err := routes.dial(5 * time.Second)
			if err != nil {
				return nil, err
			}
			tuneSocket(raw)
			// Apply the disguise before anything of ours is sent, so the first
			// thing on the wire is whatever the transport expects. The name comes
			// from the route, because a fallback route may have to claim a
			// different one.
			c, err := wrapDial(raw, cfg.withClaimedName(claim))
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			if err := sendAuth(c, cfg.secret); err != nil {
				_ = c.Close()
				return nil, err
			}
			return c, nil
		}
	}

	if cfg.Mux {
		// The edge is always the side that starts sessions, whichever side
		// dialled, so it never needs a handler for incoming ones.
		e.links = newCarrierSet(cfg.MuxLinks, dial, nil)
		e.links.SetOnTeardown(e.triggerTeardown)
		st.links = e.links
		go e.links.maintain(ctx.Done())
	} else {
		e.pool = newPool(cfg.PoolSize, cfg.SpareTTL, reverseWaitForSpare, dial)
		st.pool = e.pool
		go e.pool.maintain(ctx)
	}

	ctrl, err := startControlServer(ctx, cfg, e)
	if err != nil {
		log.Printf("warning: could not start local control socket: %v", err)
	} else if ctrl != nil {
		defer ctrl.Close()
	}

	// In reverse mode we also listen for the origin's incoming connections.
	if cfg.Mode == ModeReverse {
		var tunnelLn net.Listener
		if cfg.Transport == TransportKCP {
			tunnelLn, err = kcpListen(cfg.TunnelAddr, cfg)
		} else {
			tunnelLn, err = net.Listen("tcp", cfg.TunnelAddr)
		}
		if err != nil {
			return err
		}
		go func() {
			<-ctx.Done()
			_ = tunnelLn.Close()
		}()
		go e.acceptTunnel(ctx, tunnelLn)
		log.Printf("waiting for the origin to connect in on %s", cfg.TunnelAddr)
	}

	var userLns []net.Listener
	for _, addr := range cfg.UserListens {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, prev := range userLns {
				_ = prev.Close()
			}
			return fmt.Errorf("listening for users on %s: %w", addr, err)
		}
		userLns = append(userLns, ln)
	}
	go func() {
		<-ctx.Done()
		for _, ln := range userLns {
			_ = ln.Close()
		}
	}()

	var listenerWg sync.WaitGroup
	for _, ln := range userLns {
		listenerWg.Add(1)
		go func(ln net.Listener) {
			defer listenerWg.Done()
			e.acceptUsers(ctx, ln, st)
		}(ln)
	}

	listenerWg.Wait()

	log.Printf("shutting down; letting live sessions finish for up to %s", e.cfg.Drain)
	if e.pool != nil {
		e.pool.closeAll()
	}
	if !waitTimeout(&e.wg, e.cfg.Drain) {
		log.Printf("drain time ran out; exiting with sessions still open")
	}
	// Shared links are closed last, after live sessions have had their chance to
	// finish inside them.
	if e.links != nil {
		e.links.closeAll()
	}
	return nil
}

// acceptTunnel takes the origin's incoming connections in reverse mode, checks
// their credentials and parks them.
func (e *edge) acceptTunnel(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			e.logAccept.printf("accepting a tunnel connection failed: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case e.pending <- struct{}{}:
			go func(raw net.Conn) {
				defer func() { <-e.pending }()
				tuneSocket(raw)
				c, err := wrapAccept(raw, e.cfg, e.cert, e.guard)
				if err != nil {
					e.logAuth.printf("refused a tunnel connection from %s: %v", raw.RemoteAddr(), err)
					_ = raw.Close()
					return
				}
				purpose, err := recvAuthPurpose(c, e.cfg.secret, e.guard)
				if err != nil {
					e.logAuth.printf("refused a tunnel connection from %s: %v", c.RemoteAddr(), err)
					_ = c.Close()
					return
				}
				if purpose == authPurposeSpeedtest {
					go runSpeedtestServer(c)
					return
				}
				if e.links != nil {
					// This one connection will carry every session that comes,
					// so it is kept rather than parked.
					if !e.links.add(c) {
						_ = c.Close()
					}
					return
				}
				if !e.pool.offer(c) {
					// More spares than we asked for; the origin will notice and
					// slow down.
					_ = c.Close()
				}
			}(c)
		default:
			e.logCapacity.printf("too many unestablished tunnel connections (%d); dropping one", e.cfg.MaxPending)
			_ = c.Close()
		}
	}
}

func (e *edge) acceptUsers(ctx context.Context, ln net.Listener, st *status) {
	listenAddr := ln.Addr().String()
	targetPort := e.cfg.TargetPortFor(listenAddr)

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			// Most often the open-file limit. Logged, throttled, so the cause is
			// visible without flooding the journal.
			e.logAccept.printf("accepting a user failed (check the open-file limit): %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case e.active <- struct{}{}:
			e.wg.Add(1)
			atomic.AddInt64(&st.activeSessions, 1)
			go func(user net.Conn) {
				defer e.wg.Done()
				defer func() {
					atomic.AddInt64(&st.activeSessions, -1)
					<-e.active
				}()
				if err := e.serve(ctx, user, targetPort); err != nil {
					_ = user.Close()
					if errors.Is(err, errUserWentAway) {
						// Background noise on a public port. Counted, not logged.
						atomic.AddInt64(&st.emptyConnections, 1)
						return
					}
					atomic.AddInt64(&st.failedSessions, 1)
					e.logSession.printf("could not put a user on the tunnel: %v", err)
				}
			}(c)
		default:
			atomic.AddInt64(&st.droppedSessions, 1)
			e.logCapacity.printf("at capacity (%d sessions); dropping a user", e.cfg.MaxConn)
			_ = c.Close()
		}
	}
}

// serve moves one user across the tunnel, quietly retrying on a fresh connection
// if a spare turns out to be dead.
func (e *edge) serve(ctx context.Context, user net.Conn, targetPort uint16) error {
	// Capture the opening bytes so they can be replayed if the first attempt
	// fails. Every protocol used here speaks first, so this returns at once.
	//
	// The read uses a borrowed buffer and only what arrived is kept. Those
	// opening bytes have to be held for as long as the session might need a
	// retry, and every protocol involved opens with tens of bytes, so holding a
	// whole 16 KB buffer per session to keep sixty bytes would waste tens of
	// megabytes at capacity for nothing.
	scratch := headPool.Get().(*[]byte)
	_ = user.SetReadDeadline(time.Now().Add(headWaitTimeout))
	n, err := user.Read(*scratch)
	_ = user.SetReadDeadline(time.Time{})
	var head []byte
	if n > 0 {
		head = make([]byte, n)
		copy(head, (*scratch)[:n])
	}
	headPool.Put(scratch)
	if n == 0 && err != nil && !isTimeout(err) {
		// Connected then vanished without a word: almost always a port scan.
		// Do not spend a tunnel connection on it, and do not log it.
		return fmt.Errorf("%w: %v", errUserWentAway, err)
	}

	var lastErr error
	for attempt := 1; attempt <= maxActivateTries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		tunnel, err := e.takeTunnel(ctx, targetPort)
		if err != nil {
			lastErr = err
			// Nothing to retry against in reverse mode with the origin away.
			if errors.Is(err, errNoSpare) {
				break
			}
			continue
		}
		if err := activate(tunnel, head, targetPort); err != nil {
			_ = tunnel.Close()
			lastErr = err
			atomic.AddInt64(&e.st.retries, 1)
			continue
		}
		if err := relay(user, tunnel); err != nil {
			// The user has already been served as far as it got, so this is a
			// report rather than a failure: their download was cut short by the
			// tunnel rather than by them.
			e.logRelay.printf("a session was cut short bringing data back: %v", err)
		}
		return nil
	}
	return lastErr
}

// takeTunnel produces something to carry one user across the border: either a
// ready spare connection, or a new session inside a shared link. Both behave the
// same from here on, which is why the rest of this file does not care which.
func (e *edge) takeTunnel(ctx context.Context, targetPort uint16) (net.Conn, error) {
	if e.links != nil {
		return e.links.open(ctx.Done(), targetPort)
	}
	return e.pool.take(ctx)
}

// activate wakes a parked connection, pushes the user's opening bytes in the
// same write, and waits for confirmation that the origin reached the service.
//
// Sending the opening bytes before waiting is what makes the confirmation free:
// the user is already waiting a round trip for the service to reply, so the
// acknowledgement rides along inside that wait. And because those bytes are
// still held locally, the connection stays safe to throw away if no
// acknowledgement arrives.
func activate(tunnel net.Conn, head []byte, targetPort uint16) error {
	opening := make([]byte, 0, 3+len(head))
	if targetPort > 0 {
		opening = append(opening, msgActivatePort, byte(targetPort>>8), byte(targetPort))
	} else {
		opening = append(opening, msgActivate)
	}
	opening = append(opening, head...)

	if err := tunnel.SetWriteDeadline(time.Now().Add(activateWriteTimeout)); err != nil {
		return err
	}
	if _, err := tunnel.Write(opening); err != nil {
		return err
	}
	if err := tunnel.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}

	if err := tunnel.SetReadDeadline(time.Now().Add(ackWaitTimeout)); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(tunnel, ack[:]); err != nil {
		return err
	}
	if err := tunnel.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	if ack[0] != msgAck {
		switch ack[0] {
		case rejClockSkew, rejReplay:
			return describeRejection(ack[0])
		default:
			return errBadAck
		}
	}
	return nil
}

// TeardownRemote contacts the origin to delete its half of the tunnel.
func (e *edge) TeardownRemote(ctx context.Context) error {
	if e.links != nil {
		return e.links.Teardown(ctx)
	}
	if e.pool != nil {
		var lastErr error
		for attempt := 1; attempt <= maxActivateTries; attempt++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			conn, err := e.pool.take(ctx)
			if err != nil {
				lastErr = fmt.Errorf("obtaining tunnel connection: %w", err)
				continue
			}
			if err := sendTeardown(conn); err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
			_ = conn.Close()
			return nil
		}
		return lastErr
	}
	return errors.New("no active links or pool")
}

func (e *edge) triggerTeardown() {
	e.teardownOnce.Do(func() {
		log.Printf("remote teardown requested by origin; proceeding with self-deletion")
		go e.selfDelete()
	})
}

func (e *edge) selfDelete() {
	name := e.cfg.Name
	log.Printf("[%s] initiating remote teardown and self-cleanup", name)

	// 1. Remove firewall rules
	fwCmd := exec.Command("/usr/local/bin/portbridge-firewall", "remove", name)
	if out, err := fwCmd.CombinedOutput(); err != nil {
		log.Printf("[%s] firewall remove output: %s (err: %v)", name, string(out), err)
	}

	// 2. Remove configuration, secrets, certificates, and runtime files
	filesToRemove := []string{
		e.cfg.Path,
		e.cfg.SecretFile,
		e.cfg.StatusFile,
		e.cfg.ControlSocketPath(),
		e.cfg.CertFile,
		e.cfg.KeyFile,
		filepath.Join("/etc/portbridge/tunnels", name+".conf"),
		filepath.Join("/etc/portbridge/secrets", name+".key"),
		filepath.Join("/etc/portbridge/certs", name+".crt"),
		filepath.Join("/etc/portbridge/certs", name+".key"),
		filepath.Join("/run/portbridge", name+".json"),
		filepath.Join("/run/portbridge", name+".sock"),
	}

	for _, f := range filesToRemove {
		if f != "" {
			_ = os.Remove(f)
		}
	}

	// 3. Stop and disable systemd unit
	unit := fmt.Sprintf("portbridge@%s.service", name)
	_ = exec.Command("systemctl", "stop", "--no-block", unit).Run()
	_ = exec.Command("systemctl", "disable", unit).Run()
	_ = exec.Command("systemctl", "reset-failed", unit).Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()

	// 4. Cancel edge context so running loops exit
	if e.cancel != nil {
		e.cancel()
	}
}

func sendTeardown(tunnel net.Conn) error {
	if err := tunnel.SetWriteDeadline(time.Now().Add(activateWriteTimeout)); err != nil {
		return err
	}
	if _, err := tunnel.Write([]byte{msgTeardown}); err != nil {
		return fmt.Errorf("sending teardown: %w", err)
	}
	if err := tunnel.SetReadDeadline(time.Now().Add(ackWaitTimeout)); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(tunnel, ack[:]); err != nil {
		return fmt.Errorf("reading teardown ack: %w", err)
	}
	if ack[0] != msgTeardownAck {
		return fmt.Errorf("unexpected teardown reply: 0x%02x", ack[0])
	}
	return nil
}

func startControlServer(ctx context.Context, cfg *Config, e *edge) (io.Closer, error) {
	sockPath := cfg.ControlSocketPath()
	if sockPath == "" {
		return nil, nil
	}
	_ = os.Remove(sockPath)
	if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sockPath, 0600)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleControlConn(c, e)
		}
	}()

	return ln, nil
}

func handleControlConn(c net.Conn, e *edge) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	cmd := strings.TrimSpace(string(buf[:n]))
	switch cmd {
	case "teardown":
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := e.TeardownRemote(ctx); err != nil {
			_, _ = fmt.Fprintf(c, "err: %v\n", err)
			return
		}
		_, _ = fmt.Fprintln(c, "ok")
	case "speedtest":
		if e.cfg.Mode == ModeDirect {
			routes := newRouter(e.cfg)
			raw, claim, err := routes.dial(5 * time.Second)
			if err != nil {
				_, _ = fmt.Fprintf(c, "dial error: %v\n", err)
				return
			}
			defer raw.Close()
			tuneSocket(raw)
			tc, err := wrapDial(raw, e.cfg.withClaimedName(claim))
			if err != nil {
				_, _ = fmt.Fprintf(c, "securing link: %v\n", err)
				return
			}
			defer tc.Close()
			if err := sendAuthPurpose(tc, e.cfg.secret, authPurposeSpeedtest); err != nil {
				_, _ = fmt.Fprintf(c, "auth error: %v\n", err)
				return
			}
			_ = runSpeedtestClient(tc, e.cfg, c)
			return
		}
		_, _ = fmt.Fprintln(c, "speedtest must be initiated from the origin in reverse mode")
	default:
		_, _ = fmt.Fprintln(c, "unknown command")
	}
}

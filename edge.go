package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

// edge faces the users. It holds the pool of ready connections and tells the
// origin when a user turns up. Its behaviour is the same in both modes; only the
// way the pool gets filled differs.
type edge struct {
	cfg  *Config
	pool *pool
	st   *status

	active  chan struct{}
	pending chan struct{}
	wg      sync.WaitGroup

	guard *replayGuard

	logAccept   *throttled
	logCapacity *throttled
	logSession  *throttled
	logAuth     *throttled
}

func runEdge(ctx context.Context, cfg *Config, st *status) error {
	e := &edge{
		cfg:         cfg,
		st:          st,
		active:      make(chan struct{}, cfg.MaxConn),
		pending:     make(chan struct{}, cfg.MaxPending),
		guard:       newReplayGuard(ctx),
		logAccept:   newThrottled(),
		logCapacity: newThrottled(),
		logSession:  newThrottled(),
		logAuth:     newThrottled(),
	}

	// Direct mode: we dial the origin ourselves, so the pool can refill itself.
	// Reverse mode: we cannot dial anywhere, so the pool is fed by accepts.
	var dial func() (net.Conn, error)
	if cfg.Mode == ModeDirect {
		dial = func() (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			c, err := d.Dial("tcp", cfg.TunnelAddr)
			if err != nil {
				return nil, err
			}
			tuneSocket(c)
			if err := sendAuth(c, cfg.secret); err != nil {
				_ = c.Close()
				return nil, err
			}
			return c, nil
		}
	}
	e.pool = newPool(cfg.PoolSize, cfg.SpareTTL, reverseWaitForSpare, dial)
	st.pool = e.pool
	go e.pool.maintain(ctx)

	// In reverse mode we also listen for the origin's incoming connections.
	if cfg.Mode == ModeReverse {
		tunnelLn, err := net.Listen("tcp", cfg.TunnelAddr)
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

	userLn, err := net.Listen("tcp", cfg.UserListen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = userLn.Close()
	}()

	for {
		c, err := userLn.Accept()
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
				if err := e.serve(ctx, user); err != nil {
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

	log.Printf("shutting down; letting live sessions finish for up to %s", e.cfg.Drain)
	e.pool.closeAll()
	if !waitTimeout(&e.wg, e.cfg.Drain) {
		log.Printf("drain time ran out; exiting with sessions still open")
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
			go func(c net.Conn) {
				defer func() { <-e.pending }()
				tuneSocket(c)
				if err := recvAuth(c, e.cfg.secret, e.guard); err != nil {
					e.logAuth.printf("refused a tunnel connection from %s: %v", c.RemoteAddr(), err)
					_ = c.Close()
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

// serve moves one user across the tunnel, quietly retrying on a fresh connection
// if a spare turns out to be dead.
func (e *edge) serve(ctx context.Context, user net.Conn) error {
	tuneSocket(user)

	// Capture the opening bytes so they can be replayed if the first attempt
	// fails. Every protocol used here speaks first, so this returns at once.
	head := make([]byte, headBufferSize)
	_ = user.SetReadDeadline(time.Now().Add(headWaitTimeout))
	n, err := user.Read(head)
	_ = user.SetReadDeadline(time.Time{})
	if n == 0 && err != nil && !isTimeout(err) {
		// Connected then vanished without a word: almost always a port scan.
		// Do not spend a tunnel connection on it, and do not log it.
		return fmt.Errorf("%w: %v", errUserWentAway, err)
	}
	head = head[:n]

	var lastErr error
	for attempt := 1; attempt <= maxActivateTries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		tunnel, err := e.pool.take(ctx)
		if err != nil {
			lastErr = err
			// Nothing to retry against in reverse mode with the origin away.
			if errors.Is(err, errNoSpare) {
				break
			}
			continue
		}
		if err := activate(tunnel, head); err != nil {
			_ = tunnel.Close()
			lastErr = err
			atomic.AddInt64(&e.st.retries, 1)
			continue
		}
		relay(user, tunnel)
		return nil
	}
	return lastErr
}

// activate wakes a parked connection, pushes the user's opening bytes in the
// same write, and waits for confirmation that the origin reached the service.
//
// Sending the opening bytes before waiting is what makes the confirmation free:
// the user is already waiting a round trip for the service to reply, so the
// acknowledgement rides along inside that wait. And because those bytes are
// still held locally, the connection stays safe to throw away if no
// acknowledgement arrives.
func activate(tunnel net.Conn, head []byte) error {
	opening := make([]byte, 0, 1+len(head))
	opening = append(opening, msgActivate)
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

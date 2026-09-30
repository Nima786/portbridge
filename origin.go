package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// inboundDialTimeout bounds how long we spend connecting to the local service.
// It must stay comfortably below the other side's confirmation timeout, or a
// slow service would look like a broken tunnel connection.
const inboundDialTimeout = 3 * time.Second

// origin sits next to the service being published. It never touches that service
// until a real user is actually waiting, which is what stops idle spare
// connections from making the service log and time out connections that carry
// nothing.
type origin struct {
	cfg *Config
	st  *status

	// links is set instead of the one-connection-per-session machinery when
	// sessions share a few long-lived connections.
	links *carrierSet

	// routes is how to reach the edge, with a fallback if one was given. Only
	// used in reverse mode, where this side is the one that dials.
	routes *router

	active  chan struct{}
	pending chan struct{}
	wg      sync.WaitGroup

	guard *replayGuard
	cert  *tls.Certificate

	logAccept   *throttled
	logAuth     *throttled
	logCapacity *throttled
	logDial     *throttled
	logConnect  *throttled
	logRelay    *throttled

	cancel       context.CancelFunc
	teardownOnce sync.Once
}

func runOrigin(ctx context.Context, cfg *Config, st *status) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	o := &origin{
		cfg:         cfg,
		st:          st,
		cancel:      cancel,
		active:      make(chan struct{}, cfg.MaxConn),
		pending:     make(chan struct{}, cfg.MaxPending),
		guard:       newReplayGuard(ctx),
		logAccept:   newThrottled(),
		logAuth:     newThrottled(),
		logCapacity: newThrottled(),
		logDial:     newThrottled(),
		logConnect:  newThrottled(),
		logRelay:    newThrottled(),
	}

	if cfg.Mode == ModeReverse {
		// This side dials, so it needs no certificate, only the settings it will
		// present. Prepared once: see prepareTLS for why per-connection settings
		// were the single most expensive thing on a disguised link.
		cfg.prepareTLS(nil)
		o.routes = newRouter(cfg)
		st.routes = o.routes
		log.Printf("reaching the other server at %s", o.routes.describe())
		return o.runReverse(ctx)
	}
	return o.runDirect(ctx)
}

// serveStream handles one session that arrived inside a shared link. It is the
// same two steps as a parked connection being woken: wait to be told a user is
// there, then reach the service and confirm it.
func (o *origin) serveStream(tunnel net.Conn) {
	o.wg.Add(1)
	defer o.wg.Done()

	port, err := o.awaitActivation(tunnel, muxActivateWait)
	if err != nil {
		_ = tunnel.Close()
		return
	}
	if port == 0 {
		if pt, ok := tunnel.(interface{ TargetPort() uint16 }); ok {
			port = pt.TargetPort()
		}
	}
	o.handleActivated(tunnel, port)
}

// runDirect accepts tunnel connections from the edge.
func (o *origin) runDirect(ctx context.Context) error {
	if o.cfg.Transport != TransportPlain {
		cert, err := ensureCert(o.cfg.CertFile, o.cfg.KeyFile, o.cfg.effectiveServerName())
		if err != nil {
			return fmt.Errorf("preparing the disguise: %w", err)
		}
		o.cert = &cert
	}
	o.cfg.prepareTLS(o.cert)

	if o.cfg.Mux {
		// The edge starts the sessions, so this side only has to receive them.
		o.links = newCarrierSet(o.cfg.MuxLinks, nil, o.serveStream)
		o.links.SetOnTeardown(o.triggerTeardown)
		o.st.links = o.links
		go o.links.maintain(ctx.Done())
	}

	ln, err := net.Listen("tcp", o.cfg.TunnelAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			o.logAccept.printf("accepting a tunnel connection failed (check the open-file limit): %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case o.pending <- struct{}{}:
			o.wg.Add(1)
			go func(raw net.Conn) {
				defer o.wg.Done()
				released := false
				release := func() {
					if !released {
						released = true
						<-o.pending
					}
				}
				defer release()

				tuneSocket(raw)
				c, err := wrapAccept(raw, o.cfg, o.cert)
				if err != nil {
					o.logAuth.printf("refused a tunnel connection from %s: %v", raw.RemoteAddr(), err)
					_ = raw.Close()
					return
				}
				if err := recvAuth(c, o.cfg.secret, o.guard); err != nil {
					o.logAuth.printf("refused a tunnel connection from %s: %v", c.RemoteAddr(), err)
					_ = c.Close()
					return
				}
				if o.links != nil {
					// One connection, many sessions: hold it and let the
					// sessions arrive inside it.
					release()
					if !o.links.add(c) {
						_ = c.Close()
					}
					return
				}
				atomic.AddInt64(&o.st.parkedSpares, 1)
				targetPort, err := o.parkUntilActivated(ctx, c, o.cfg.ParkTimeout)
				atomic.AddInt64(&o.st.parkedSpares, -1)
				if err != nil {
					_ = c.Close()
					return
				}
				release()
				o.handleActivated(c, targetPort)
			}(c)
		default:
			o.logCapacity.printf("too many unestablished tunnel connections (%d); dropping one", o.cfg.MaxPending)
			_ = c.Close()
		}
	}

	log.Printf("shutting down; letting live sessions finish for up to %s", o.cfg.Drain)
	if !waitTimeout(&o.wg, o.cfg.Drain) {
		log.Printf("drain time ran out; exiting with sessions still open")
	}
	if o.links != nil {
		o.links.closeAll()
	}
	return nil
}

// runReverse keeps a fixed number of connections open into the edge.
//
// One worker owns one parked connection. When its connection is activated the
// worker hands the session to a separate goroutine and immediately opens a
// replacement, so the number of ready spares waiting at the edge stays constant
// instead of dropping for the length of every session.
func (o *origin) runReverse(ctx context.Context) error {
	if o.cfg.Mux {
		return o.runReverseMux(ctx)
	}

	workers := o.cfg.PoolSize
	if workers < 1 {
		workers = 1
	}
	log.Printf("opening %d connections into the edge at %s", workers, o.cfg.TunnelAddr)

	var workerWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func(n int) {
			defer workerWg.Done()
			o.reverseWorker(ctx, n)
		}(i)
	}

	<-ctx.Done()
	log.Printf("shutting down; letting live sessions finish for up to %s", o.cfg.Drain)

	// Workers abandon their parked connections immediately, so this returns
	// promptly. Bounded anyway, so a wedged worker can never hold up a restart.
	if !waitTimeout(&workerWg, 10*time.Second) {
		log.Printf("some tunnel connections did not close promptly")
	}
	if !waitTimeout(&o.wg, o.cfg.Drain) {
		log.Printf("drain time ran out; exiting with sessions still open")
	}
	return nil
}

// runReverseMux is the reversed direction with sessions shared over a few links:
// this side dials them and keeps them up, and the sessions arrive inside.
func (o *origin) runReverseMux(ctx context.Context) error {
	log.Printf("opening %d shared connections into the edge at %s",
		o.cfg.MuxLinks, o.cfg.TunnelAddr)

	o.links = newCarrierSet(o.cfg.MuxLinks, o.dialEdge, o.serveStream)
	o.links.SetOnTeardown(o.triggerTeardown)
	o.st.links = o.links
	go o.links.maintain(ctx.Done())

	<-ctx.Done()
	log.Printf("shutting down; letting live sessions finish for up to %s", o.cfg.Drain)
	if !waitTimeout(&o.wg, o.cfg.Drain) {
		log.Printf("drain time ran out; exiting with sessions still open")
	}
	o.links.closeAll()
	return nil
}

func (o *origin) reverseWorker(ctx context.Context, n int) {
	backoff := time.Duration(0)

	for ctx.Err() == nil {
		c, err := o.dialEdge()
		if err != nil {
			if backoff == 0 {
				backoff = refillBackoff0
			} else if backoff < refillBackoffM {
				backoff *= 2
				if backoff > refillBackoffM {
					backoff = refillBackoffM
				}
			}
			o.logConnect.printf("cannot reach the edge at %s: %v (retrying, currently every %s)",
				o.cfg.TunnelAddr, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0

		// Park until a user shows up. The spare lifetime doubles as the age cap:
		// when it expires we replace the connection rather than trusting a route
		// that a firewall may quietly have forgotten about.
		atomic.AddInt64(&o.st.parkedSpares, 1)
		targetPort, err := o.parkUntilActivated(ctx, c, o.cfg.SpareTTL)
		atomic.AddInt64(&o.st.parkedSpares, -1)

		if err != nil {
			_ = c.Close()
			if ctx.Err() != nil || errors.Is(err, errTeardownRequested) {
				return
			}
			// A timeout here is the normal recycle path, not a problem.
			if !isTimeout(err) {
				o.logConnect.printf("a parked connection to the edge ended early: %v", err)
			}
			continue
		}

		// Hand the session off and immediately rebuild this spare.
		o.wg.Add(1)
		go func(c net.Conn, targetPort uint16) {
			defer o.wg.Done()
			o.handleActivated(c, targetPort)
		}(c, targetPort)
	}
}

func (o *origin) dialEdge() (net.Conn, error) {
	raw, claim, err := o.routes.dial(10 * time.Second)
	if err != nil {
		return nil, err
	}
	tuneSocket(raw)
	// Apply the disguise before sending anything of ours, claiming whatever name
	// belongs to the route we got.
	c, err := wrapDial(raw, o.cfg.withClaimedName(claim))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := sendAuth(c, o.cfg.secret); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// parkUntilActivated waits for the edge to signal a user, but gives up at once
// if we are shutting down.
//
// The wait itself is a blocking read with a deadline measured in minutes.
// Cancelling a context does not interrupt a blocked socket read, so without this
// the process would appear to hang on shutdown until that deadline expired.
// Moving the deadline to "now" makes the read return immediately.
func (o *origin) parkUntilActivated(ctx context.Context, c net.Conn, timeout time.Duration) (uint16, error) {
	unpark := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.SetReadDeadline(time.Now())
		case <-unpark:
		}
	}()
	defer close(unpark)

	return o.awaitActivation(c, timeout)
}

// awaitActivation blocks until the edge says a user has arrived. Anything other
// than the activation byte means the connection is finished with.
func (o *origin) awaitActivation(c net.Conn, timeout time.Duration) (uint16, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	var sig [1]byte
	if _, err := io.ReadFull(c, sig[:]); err != nil {
		return 0, err
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return 0, err
	}
	switch sig[0] {
	case msgActivate:
		return 0, nil
	case msgActivatePort:
		var portBuf [2]byte
		if _, err := io.ReadFull(c, portBuf[:]); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(portBuf[:]), nil
	case msgTeardown:
		_ = c.SetWriteDeadline(time.Now().Add(activateWriteTimeout))
		_, _ = c.Write([]byte{msgTeardownAck})
		o.triggerTeardown()
		return 0, errTeardownRequested
	case rejClockSkew, rejReplay:
		err := describeRejection(sig[0])
		o.logAuth.printf("the edge refused our credentials: %v", err)
		return 0, err
	default:
		return 0, errBadAck
	}
}

// handleActivated is reached only once a real user is waiting on the other side.
func (o *origin) handleActivated(tunnel net.Conn, targetPort uint16) {
	select {
	case o.active <- struct{}{}:
	default:
		atomic.AddInt64(&o.st.droppedSessions, 1)
		o.logCapacity.printf("at capacity (%d sessions); dropping an activated session", o.cfg.MaxConn)
		_ = tunnel.Close()
		return
	}
	defer func() { <-o.active }()

	atomic.AddInt64(&o.st.activeSessions, 1)
	defer atomic.AddInt64(&o.st.activeSessions, -1)

	inboundAddr := o.cfg.InboundFor(targetPort)
	svc, err := net.DialTimeout("tcp", inboundAddr, inboundDialTimeout)
	if err != nil {
		atomic.AddInt64(&o.st.failedSessions, 1)
		o.logDial.printf("cannot reach the local service at %s: %v", inboundAddr, err)
		_ = tunnel.Close()
		return
	}

	// Confirm we got through. Until this lands the edge is free to abandon this
	// connection and replay the user's opening bytes down a different one.
	if err := tunnel.SetWriteDeadline(time.Now().Add(activateWriteTimeout)); err != nil {
		_ = tunnel.Close()
		_ = svc.Close()
		return
	}
	if _, err := tunnel.Write([]byte{msgAck}); err != nil {
		_ = tunnel.Close()
		_ = svc.Close()
		return
	}
	_ = tunnel.SetWriteDeadline(time.Time{})

	if err := relay(svc, tunnel); err != nil {
		o.logRelay.printf("a session was cut short taking data from the tunnel: %v", err)
	}
}

func (o *origin) triggerTeardown() {
	o.teardownOnce.Do(func() {
		log.Printf("remote teardown requested by edge; proceeding with self-deletion")
		go o.selfDelete()
	})
}

func (o *origin) selfDelete() {
	name := o.cfg.Name
	log.Printf("[%s] initiating remote teardown and self-cleanup", name)

	// 1. Remove firewall rules
	fwCmd := exec.Command("/usr/local/bin/portbridge-firewall", "remove", name)
	if out, err := fwCmd.CombinedOutput(); err != nil {
		log.Printf("[%s] firewall remove output: %s (err: %v)", name, string(out), err)
	}

	// 2. Remove configuration, secrets, certificates, and runtime files
	filesToRemove := []string{
		o.cfg.Path,
		o.cfg.SecretFile,
		o.cfg.StatusFile,
		o.cfg.ControlSocketPath(),
		o.cfg.CertFile,
		o.cfg.KeyFile,
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

	// 4. Cancel origin context so running loops exit
	if o.cancel != nil {
		o.cancel()
	}
}

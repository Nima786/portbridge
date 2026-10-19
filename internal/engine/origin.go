package engine

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nima786/portbridge/internal/proxyproto"
)

// inboundDialTimeout bounds how long we spend connecting to the local service.
// It must stay comfortably below the other side's confirmation timeout, or a
// slow service would look like a broken tunnel connection.
const inboundDialTimeout = 2500 * time.Millisecond

// parkedSilenceLimit is how long a spare that is being pinged may stay silent
// before it is treated as dead. The edge pings every 15 seconds.
const parkedSilenceLimit = 50 * time.Second

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

	// health is what this side believes about whether data really flows.
	health *pathHealth

	// parkedSet tracks the spare connections this side is holding open, so they
	// can all be dropped when the route underneath them changes.
	parkedMu  sync.Mutex
	parkedSet map[net.Conn]struct{}

	// quietUntil (unix nano, atomic) silences the "ended early" message for
	// connections dropped on purpose.
	quietUntil int64

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
	logProxy    *throttled

	proxyStateMu sync.Mutex
	proxyBypass  map[string]time.Time
	proxyWorks   map[string]time.Time

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
		logProxy:    newThrottled(),
	}

	ctrl, err := startOriginControlServer(ctx, cfg, o)
	if err != nil {
		log.Printf("warning: could not start local control socket: %v", err)
	} else if ctrl != nil {
		defer ctrl.Close()
	}

	if cfg.Mode == ModeReverse {
		// This side dials, so it needs no certificate, only the settings it will
		// present. Prepared once: see prepareTLS for why per-connection settings
		// were the single most expensive thing on a disguised link.
		cfg.prepareTLS(nil)
		o.routes = newRouter(cfg)
		st.routes = o.routes
		log.Printf("reaching the other server at %s", o.routes.describe())
		o.health = newPathHealth(o.routes.hasFallback())
		st.health = o.health
		if cfg.PathProbe {
			// This side dials, so it is the one that checks the routes and
			// moves traffic between them. See health.go.
			pr := newProber(cfg, o.routes, o.health, o.routeChanged)
			go pr.run(ctx)
		}
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

	a, err := o.awaitActivation(tunnel, muxActivateWait)
	if err != nil {
		_ = tunnel.Close()
		return
	}
	if a.port == 0 {
		if pt, ok := tunnel.(interface{ TargetPort() uint16 }); ok {
			a.port = pt.TargetPort()
		}
	}
	o.handleActivated(tunnel, a)
}

// runDirect accepts tunnel connections from the edge.
func (o *origin) runDirect(ctx context.Context) error {
	if o.cfg.Transport != TransportPlain && !o.cfg.Transport.IsPacketBased() {
		cert, err := EnsureCert(o.cfg.CertFile, o.cfg.KeyFile, o.cfg.EffectiveServerName())
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

	var ln net.Listener
	var err error
	if o.cfg.Transport.IsPacketBased() {
		ln, err = kcpListen(o.cfg.TunnelAddr, o.cfg)
	} else {
		ln, err = net.Listen("tcp", o.cfg.TunnelAddr)
	}
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
				c, err := wrapAccept(raw, o.cfg, o.cert, o.guard)
				if err != nil {
					if errors.Is(err, errStrangerForwarded) || errors.Is(err, errSplitLegAttached) {
						return
					}
					o.logAuth.printf("refused a tunnel connection from %s: %v", raw.RemoteAddr(), err)
					_ = raw.Close()
					return
				}
				purpose, err := recvAuthPurpose(c, o.cfg.secret, o.guard)
				if err != nil {
					o.logAuth.printf("refused a tunnel connection from %s: %v", c.RemoteAddr(), err)
					sinkGarbageAndClose(c)
					return
				}
				if purpose == authPurposeSpeedtest {
					log.Printf("[%s] connection from %s requested in-tunnel speedtest", o.cfg.Name, c.RemoteAddr())
					release()
					runSpeedtestServer(c)
					return
				}
				if !isTunnelPurpose(purpose) {
					o.logAuth.printf("refused a tunnel connection from %s: unknown purpose %d", c.RemoteAddr(), purpose)
					_ = c.Close()
					return
				}
				// Say by name when the two servers disagree about shared
				// connections, instead of letting users hang.
				if err := checkTunnelPurpose(o.cfg, purpose); err != nil {
					o.logAuth.printf("refused a tunnel connection from %s: %v", c.RemoteAddr(), err)
					writeReason(c, rejMuxMismatch)
					_ = c.Close()
					return
				}
				// Authenticated, so it no longer counts as unestablished.
				// Holding the slot while parked capped the number of spares that
				// could wait at the limit meant for half-open connections.
				release()
				if o.links != nil {
					// One connection, many sessions: hold it and let the
					// sessions arrive inside it.
					if !o.links.add(c) {
						_ = c.Close()
					}
					return
				}
				atomic.AddInt64(&o.st.parkedSpares, 1)
				a, err := o.parkUntilActivated(ctx, c, o.cfg.ParkTimeout)
				atomic.AddInt64(&o.st.parkedSpares, -1)
				if err != nil {
					_ = c.Close()
					return
				}
				o.handleActivated(c, a)
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
		o.trackParked(c, true)
		a, err := o.parkUntilActivated(ctx, c, o.cfg.SpareTTL)
		o.trackParked(c, false)
		atomic.AddInt64(&o.st.parkedSpares, -1)

		if err != nil {
			_ = c.Close()
			if ctx.Err() != nil || errors.Is(err, errTeardownRequested) {
				return
			}
			// A timeout here is the normal recycle path, not a problem, and a
			// connection dropped on purpose after a route change is not either.
			if !isTimeout(err) && time.Now().UnixNano() >= atomic.LoadInt64(&o.quietUntil) {
				o.logConnect.printf("a parked connection to the edge ended early: %v", err)
			}
			continue
		}

		// Hand the session off and immediately rebuild this spare.
		o.wg.Add(1)
		go func(c net.Conn, a arrival) {
			defer o.wg.Done()
			o.handleActivated(c, a)
		}(c, a)
	}
}

func (o *origin) dialEdge() (net.Conn, error) {
	raw, idx, err := o.routes.dialIdx(10 * time.Second)
	if err != nil {
		return nil, err
	}
	tuneSocket(raw)
	// Apply the disguise before sending anything of ours. The name and the CDN
	// defaults come from the route that was reached, because a fallback route may
	// claim a different name and is the one that goes through a CDN.
	purpose := tunnelPurposeFor(o.cfg)
	c, err := wrapDialPurpose(raw, o.routes.routeConfig(idx), purpose)
	if err != nil {
		_ = raw.Close()
		o.routes.handshakeFailed(idx, err)
		return nil, err
	}
	if err := sendAuthPurpose(c, o.cfg.secret, purpose); err != nil {
		_ = c.Close()
		o.routes.handshakeFailed(idx, err)
		return nil, err
	}
	o.routes.handshakeOK(idx)
	return c, nil
}

// trackParked keeps a record of the spare connections being held, so a route
// change can drop them all at once.
func (o *origin) trackParked(c net.Conn, add bool) {
	o.parkedMu.Lock()
	defer o.parkedMu.Unlock()
	if add {
		if o.parkedSet == nil {
			o.parkedSet = make(map[net.Conn]struct{})
		}
		o.parkedSet[c] = struct{}{}
		return
	}
	delete(o.parkedSet, c)
}

// routeChanged is called when traffic moved to a different route. Whatever was
// built over the old route is closed, and is rebuilt over the new one by the
// ordinary upkeep.
func (o *origin) routeChanged() {
	atomic.StoreInt64(&o.quietUntil, time.Now().Add(5*time.Second).UnixNano())
	o.parkedMu.Lock()
	conns := make([]net.Conn, 0, len(o.parkedSet))
	for c := range o.parkedSet {
		conns = append(conns, c)
	}
	o.parkedMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if o.links != nil {
		o.links.dropAll(errRouteChanged)
	}
}

// parkUntilActivated waits for the edge to signal a user, but gives up at once
// if we are shutting down.
//
// The wait itself is a blocking read with a deadline measured in minutes.
// Cancelling a context does not interrupt a blocked socket read, so without this
// the process would appear to hang on shutdown until that deadline expired.
// Moving the deadline to "now" makes the read return immediately.
func (o *origin) parkUntilActivated(ctx context.Context, c net.Conn, timeout time.Duration) (arrival, error) {
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

// arrival is what the edge says when it wakes a connection for a user: which of
// the published services they want (0 for the first), and, when proxy_protocol
// is on there, where they came from.
type arrival struct {
	port uint16
	from *proxyproto.Addrs
}

// awaitActivation blocks until the edge says a user has arrived. Anything other
// than the activation byte means the connection is finished with.
func (o *origin) awaitActivation(c net.Conn, timeout time.Duration) (arrival, error) {
	seenPing := false
	for {
		readTimeout := timeout
		if needsKeepalive(c) && readTimeout > 45*time.Second {
			readTimeout = 45 * time.Second
		}
		// Once the edge has shown it pings this connection, silence means the
		// connection is dead, however long the spare lifetime is. It pings every
		// 15 seconds, so waiting much longer only leaves a dead spare looking
		// alive. An edge that never pings is unaffected.
		if seenPing && readTimeout > parkedSilenceLimit {
			readTimeout = parkedSilenceLimit
		}
		if err := c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return arrival{}, err
		}
		var sig [1]byte
		if _, err := io.ReadFull(c, sig[:]); err != nil {
			return arrival{}, err
		}
		switch sig[0] {
		case msgParkPing:
			seenPing = true
			_ = c.SetWriteDeadline(time.Now().Add(activateWriteTimeout))
			if _, err := c.Write([]byte{msgParkPong}); err != nil {
				return arrival{}, err
			}
			_ = c.SetWriteDeadline(time.Time{})
			continue
		case msgActivate:
			if err := c.SetReadDeadline(time.Time{}); err != nil {
				return arrival{}, err
			}
			return arrival{}, nil
		case msgActivatePort, msgActivateFrom:
			if err := c.SetReadDeadline(time.Time{}); err != nil {
				return arrival{}, err
			}
			var portBuf [2]byte
			if _, err := io.ReadFull(c, portBuf[:]); err != nil {
				return arrival{}, err
			}
			a := arrival{port: binary.BigEndian.Uint16(portBuf[:])}
			if sig[0] == msgActivateFrom {
				// The address arrives in the same write as the signal, so a
				// short limit only guards against a broken peer, never a slow
				// route.
				_ = c.SetReadDeadline(time.Now().Add(ackWaitTimeout))
				from, err := proxyproto.ReadAddrs(c)
				_ = c.SetReadDeadline(time.Time{})
				if err != nil {
					o.logAuth.printf("%v", err)
					return arrival{}, err
				}
				a.from = from
			}
			return a, nil
		case msgTeardown:
			if err := c.SetReadDeadline(time.Time{}); err != nil {
				return arrival{}, err
			}
			_ = c.SetWriteDeadline(time.Now().Add(activateWriteTimeout))
			_, _ = c.Write([]byte{msgTeardownAck})
			o.triggerTeardown()
			return arrival{}, errTeardownRequested
		case msgSpeedtest:
			if err := c.SetReadDeadline(time.Time{}); err != nil {
				return arrival{}, err
			}
			runSpeedtestServer(c)
			return arrival{}, errSpeedtestFinished
		default:
			_ = c.SetReadDeadline(time.Time{})
			switch {
			case isRejection(sig[0]):
				err := describeRejection(sig[0])
				o.logAuth.printf("the other server refused this connection: %v", err)
				return arrival{}, err
			case sig[0] >= muxOpen && sig[0] <= muxTeardownAck:
				// Shared-connection frames arriving where single sessions are
				// expected: the other server has mux on and this one has not.
				o.logAuth.printf("%v", errMuxOnlyThere)
				return arrival{}, errMuxOnlyThere
			}
			return arrival{}, errBadAck
		}
	}
}

// tellService gives the service the user's address, in the PROXY protocol
// header, before anything else reaches it. It does nothing when proxy_protocol
// is off here. When the two servers disagree the tunnel still works, and the
// log says which one to change.
func (o *origin) tellService(svc net.Conn, a arrival) error {
	if o.cfg.ProxyProtocol == proxyproto.Off {
		if a.from != nil {
			o.logProxy.printf("the other server is sending users' real addresses, but proxy_protocol " +
				"is off here, so the service is not told them; turn it on here too, or off there")
		}
		return nil
	}
	if a.from == nil {
		o.logProxy.printf("proxy_protocol is on here, but the other server is not sending users' " +
			"real addresses, so the service is told they are unknown; turn proxy_protocol on there too")
	}
	if err := svc.SetWriteDeadline(time.Now().Add(activateWriteTimeout)); err != nil {
		return err
	}
	_, err := svc.Write(proxyproto.Header(o.cfg.ProxyProtocol, a.from))
	_ = svc.SetWriteDeadline(time.Time{})
	return err
}

func (o *origin) isProxyBypassed(addr string) (bypassed, knownWorking bool) {
	now := time.Now()
	o.proxyStateMu.Lock()
	defer o.proxyStateMu.Unlock()
	if until, ok := o.proxyBypass[addr]; ok && now.Before(until) {
		return true, false
	}
	if until, ok := o.proxyWorks[addr]; ok && now.Before(until) {
		return false, true
	}
	return false, false
}

func (o *origin) markProxyBypass(addr string, ttl time.Duration) {
	o.proxyStateMu.Lock()
	if o.proxyBypass == nil {
		o.proxyBypass = make(map[string]time.Time)
	}
	delete(o.proxyWorks, addr)
	o.proxyBypass[addr] = time.Now().Add(ttl)
	o.proxyStateMu.Unlock()
}

func (o *origin) markProxyWorks(addr string, ttl time.Duration) {
	o.proxyStateMu.Lock()
	if o.proxyWorks == nil {
		o.proxyWorks = make(map[string]time.Time)
	}
	delete(o.proxyBypass, addr)
	o.proxyWorks[addr] = time.Now().Add(ttl)
	o.proxyStateMu.Unlock()
}

// isProxyHeaderRejection reports whether the first bytes sent back by a local
// service immediately after receiving ONLY a PROXY protocol header indicate
// that the service does not have "Accept Proxy Protocol" enabled (for example,
// a TLS fatal alert 0x15 0x03 or an HTTP 400 Bad Request).
func isProxyHeaderRejection(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if b[0] == 0x15 { // TLS Alert record (e.g. alert 70 protocol_version)
		return true
	}
	s := string(b)
	return strings.HasPrefix(s, "HTTP/") || strings.HasPrefix(s, "<!DOC") || strings.HasPrefix(s, "<html")
}

type prefixedServiceConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixedServiceConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *prefixedServiceConn) CloseWrite() error {
	if cw, ok := p.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}

type proxyReplyWatchConn struct {
	net.Conn
	o         *origin
	addr      string
	firstRead bool
}

func (w *proxyReplyWatchConn) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if !w.firstRead {
		w.firstRead = true
		if (n == 0 && err != nil) || (n > 0 && n <= 32 && isProxyHeaderRejection(b[:n])) {
			w.o.markProxyBypass(w.addr, 60*time.Second)
			w.o.logProxy.printf("local service at %s rejected the PROXY protocol header (Accept Proxy Protocol is not enabled on that service); "+
				"automatically bypassing PROXY header so the tunnel keeps working", w.addr)
		}
	}
	return n, err
}

func (w *proxyReplyWatchConn) CloseWrite() error {
	if cw, ok := w.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return w.Conn.Close()
}

func (o *origin) dialAndTellService(inboundAddr string, a arrival) (net.Conn, error) {
	if o.cfg.ProxyProtocol == proxyproto.Off {
		svc, err := net.DialTimeout("tcp", inboundAddr, inboundDialTimeout)
		if err != nil {
			return nil, err
		}
		_ = o.tellService(svc, a)
		return svc, nil
	}

	bypassed, knownWorking := o.isProxyBypassed(inboundAddr)
	if bypassed {
		return net.DialTimeout("tcp", inboundAddr, inboundDialTimeout)
	}

	svc, err := net.DialTimeout("tcp", inboundAddr, inboundDialTimeout)
	if err != nil {
		return nil, err
	}
	if err := o.tellService(svc, a); err != nil {
		_ = svc.Close()
		return nil, err
	}
	if knownWorking {
		return &proxyReplyWatchConn{Conn: svc, o: o, addr: inboundAddr}, nil
	}

	// Probe briefly before any user bytes are sent: a local service without
	// "Accept Proxy Protocol" enabled immediately closes or replies with a
	// TLS alert / HTTP 400 upon seeing the PROXY header.
	var peek [8]byte
	_ = svc.SetReadDeadline(time.Now().Add(45 * time.Millisecond))
	n, rerr := svc.Read(peek[:])
	_ = svc.SetReadDeadline(time.Time{})

	if (rerr != nil && !isTimeout(rerr)) || (n > 0 && isProxyHeaderRejection(peek[:n])) {
		_ = svc.Close()
		o.markProxyBypass(inboundAddr, 60*time.Second)
		o.logProxy.printf("local service at %s rejected the PROXY protocol header (Accept Proxy Protocol is not enabled on that service); "+
			"automatically bypassing PROXY header so the tunnel keeps working", inboundAddr)
		return net.DialTimeout("tcp", inboundAddr, inboundDialTimeout)
	}

	o.markProxyWorks(inboundAddr, 60*time.Second)
	if n > 0 {
		return &prefixedServiceConn{Conn: svc, prefix: append([]byte(nil), peek[:n]...)}, nil
	}
	return &proxyReplyWatchConn{Conn: svc, o: o, addr: inboundAddr}, nil
}

// handleActivated is reached only once a real user is waiting on the other side.
func (o *origin) handleActivated(tunnel net.Conn, a arrival) {
	targetPort := a.port
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
	if inboundAddr == "" {
		atomic.AddInt64(&o.st.failedSessions, 1)
		o.logDial.printf("a user asked for port %d, which none of the published services uses "+
			"(%s); set server_inbound_port on the other server to match", targetPort, strings.Join(o.cfg.InboundAddrs, ", "))
		_ = tunnel.Close()
		return
	}
	svc, err := o.dialAndTellService(inboundAddr, a)
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

	// With the settings gone, anything of this tunnel's still in the firewall can
	// no longer be mistaken for something wanted.
	if out, err := exec.Command("/usr/local/bin/portbridge-firewall", "sweep", "quiet").CombinedOutput(); err != nil {
		log.Printf("[%s] sweeping leftovers: %s (err: %v)", name, string(out), err)
	}

	// 3. Stop and disable systemd unit
	unit := fmt.Sprintf("portbridge@%s.service", name)
	// Disabled first. Stopping is what ends this very process, so anything
	// queued after it may never run, and a unit left enabled would start again
	// at the next boot.
	_ = exec.Command("systemctl", "disable", unit).Run()
	_ = exec.Command("systemctl", "reset-failed", unit).Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "stop", "--no-block", unit).Run()

	// 4. Cancel origin context so running loops exit
	if o.cancel != nil {
		o.cancel()
	}
}

func startOriginControlServer(ctx context.Context, cfg *Config, o *origin) (io.Closer, error) {
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
			go handleOriginControlConn(c, o)
		}
	}()

	return ln, nil
}

func handleOriginControlConn(c net.Conn, o *origin) {
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
		if err := o.TeardownRemote(ctx); err != nil {
			_, _ = fmt.Fprintf(c, "err: %v\n", err)
			return
		}
		_, _ = fmt.Fprintln(c, "ok")
	case "speedtest":
		if o.cfg.Mode == ModeReverse {
			routes := newRouter(o.cfg)
			raw, claim, err := routes.dial(5 * time.Second)
			if err != nil {
				_, _ = fmt.Fprintf(c, "dial error: %v\n", err)
				return
			}
			defer raw.Close()
			tuneSocket(raw)
			// The purpose is said here too: a websocket link announces it in the
			// upgrade request, and a speed test announced as a tunnel never works.
			tc, err := wrapDialPurpose(raw, o.cfg.withClaimedName(claim), authPurposeSpeedtest)
			if err != nil {
				_, _ = fmt.Fprintf(c, "securing link: %v\n", err)
				return
			}
			defer tc.Close()
			if err := sendAuthPurpose(tc, o.cfg.secret, authPurposeSpeedtest); err != nil {
				_, _ = fmt.Fprintf(c, "auth error: %v\n", err)
				return
			}
			_ = runSpeedtestClient(tc, o.cfg, c)
			return
		}
		_, _ = fmt.Fprintln(c, "speedtest must be initiated from the edge in direct mode")
	default:
		_, _ = fmt.Fprintln(c, "unknown command")
	}
}

func (o *origin) TeardownRemote(ctx context.Context) error {
	if o.links != nil {
		return o.links.Teardown(ctx)
	}
	if o.cfg.Mode == ModeReverse {
		routes := newRouter(o.cfg)
		raw, claim, err := routes.dial(5 * time.Second)
		if err != nil {
			return fmt.Errorf("dialing %s: %w", o.cfg.TunnelAddr, err)
		}
		defer raw.Close()
		tuneSocket(raw)
		c, err := wrapDial(raw, o.cfg.withClaimedName(claim))
		if err != nil {
			return fmt.Errorf("wrapping dial: %w", err)
		}
		defer c.Close()
		if err := sendAuth(c, o.cfg.secret); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		return sendTeardown(c)
	}
	return nil
}

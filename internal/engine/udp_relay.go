package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// udpSessionIdleTimeout is how long an idle UDP client session stays mapped on
	// the edge before being reaped so NAT table entries and tunnel streams do not
	// accumulate forever.
	udpSessionIdleTimeout = 90 * time.Second

	// udpOriginIdleTimeout is slightly longer than udpSessionIdleTimeout so the
	// edge side closes cleanly first during normal idle expiry.
	udpOriginIdleTimeout = 95 * time.Second

	// udpPollStep is the per-read deadline step used to check shared bidirectional
	// activity timestamps without cutting off one-way UDP streams.
	udpPollStep = 15 * time.Second

	// udpSessionQueueCap bounds buffered outbound datagrams for a single client
	// session while its tunnel stream is activating or temporarily congested.
	udpSessionQueueCap = 128

	// udpMaxDatagram is the largest UDP datagram payload carried over the 2-byte
	// length-prefixed tunnel stream (IPv6 UDP max payload is 65527; 65507 on IPv4).
	udpMaxDatagram = 65527
)

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

type edgeUDPSession struct {
	clientAddr net.Addr
	firstPkt   []byte
	txCh       chan []byte
	lastActive atomic.Int64
	closed     atomic.Bool
	done       chan struct{}
	closeOnce  sync.Once
}

func (s *edgeUDPSession) close() {
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

func (e *edge) acceptUDPUsers(ctx context.Context, pc net.PacketConn, listenAddr string, st *status) {
	targetPort := e.cfg.TargetPortFor(listenAddr)

	var (
		mu       sync.Mutex
		sessions = make(map[string]*edgeUDPSession)
	)

	// Reap idle UDP sessions periodically and tear down all sessions on shutdown.
	reapDone := make(chan struct{})
	go func() {
		defer close(reapDone)
		tick := time.NewTicker(udpPollStep)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for k, s := range sessions {
					s.close()
					delete(sessions, k)
				}
				mu.Unlock()
				return
			case <-tick.C:
				cutoff := time.Now().Add(-udpSessionIdleTimeout).UnixNano()
				mu.Lock()
				for k, s := range sessions {
					if s.lastActive.Load() < cutoff {
						s.close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()
	defer func() {
		mu.Lock()
		for k, s := range sessions {
			s.close()
			delete(sessions, k)
		}
		mu.Unlock()
		<-reapDone
	}()

	rawBuf := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(rawBuf)
	buf := *rawBuf

	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			e.logAccept.printf("reading UDP user datagram on %s failed: %v", listenAddr, err)
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if n <= 0 || n > udpMaxDatagram {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		key := clientAddr.String()
		nowNS := time.Now().UnixNano()

		mu.Lock()
		sess := sessions[key]
		if sess != nil && !sess.closed.Load() {
			sess.lastActive.Store(nowNS)
			select {
			case sess.txCh <- pkt:
			default:
				// Drop excess datagram on this session rather than stalling all other UDP clients.
			}
			mu.Unlock()
			continue
		}

		select {
		case e.active <- struct{}{}:
		default:
			mu.Unlock()
			atomic.AddInt64(&st.droppedSessions, 1)
			e.logCapacity.printf("at capacity (%d sessions); dropping a UDP user session", e.cfg.MaxConn)
			continue
		}

		sess = &edgeUDPSession{
			clientAddr: clientAddr,
			firstPkt:   pkt,
			txCh:       make(chan []byte, udpSessionQueueCap),
			done:       make(chan struct{}),
		}
		sess.lastActive.Store(nowNS)
		sessions[key] = sess
		e.wg.Add(1)
		mu.Unlock()

		go func(key string, s *edgeUDPSession) {
			defer e.wg.Done()
			atomic.AddInt64(&st.activeSessions, 1)
			clientIP := st.addClient(s.clientAddr)
			defer func() {
				s.close()
				mu.Lock()
				if sessions[key] == s {
					delete(sessions, key)
				}
				mu.Unlock()
				st.removeClient(clientIP)
				atomic.AddInt64(&st.activeSessions, -1)
				<-e.active
			}()

			if err := e.serveUDPSession(ctx, pc, targetPort, s, st); err != nil && ctx.Err() == nil {
				e.logSession.printf("could not carry UDP user session over tunnel: %v", err)
			}
		}(key, sess)
	}
}

func (e *edge) serveUDPSession(ctx context.Context, pc net.PacketConn, targetPort uint16, s *edgeUDPSession, st *status) error {
	tries := maxActivateTries
	if e.health.isBlocked() {
		tries = 1
	}

	var (
		tunnel  net.Conn
		lastErr error
	)
	for attempt := 1; attempt <= tries; attempt++ {
		if ctx.Err() != nil || s.closed.Load() {
			return ctx.Err()
		}
		c, err := e.takeTunnel(ctx, targetPort)
		if err != nil {
			lastErr = err
			if errors.Is(err, errNoSpare) {
				break
			}
			continue
		}
		if err := activateUDP(c, s.firstPkt, targetPort); err != nil {
			if sus, ok := c.(interface{ suspect() }); ok {
				sus.suspect()
			}
			_ = c.Close()
			lastErr = err
			atomic.AddInt64(&st.retries, 1)
			e.health.activationFailed(err)
			if e.pool != nil && attempt < tries {
				e.pool.verifyAll(ctx)
			}
			continue
		}
		tunnel = c
		break
	}
	if tunnel == nil {
		atomic.AddInt64(&st.failedSessions, 1)
		if lastErr != nil {
			return lastErr
		}
		return errors.New("could not open tunnel stream for UDP session")
	}

	e.health.activationOK()
	atomic.AddInt64(&st.bytesUp, int64(len(s.firstPkt)))
	s.firstPkt = nil // release initial slice once sent

	var closeTunnelOnce sync.Once
	closeBoth := func() {
		s.close()
		closeTunnelOnce.Do(func() {
			_ = tunnel.Close()
		})
	}
	defer closeBoth()

	// Uplink pump: client UDP datagrams -> framed tunnel stream.
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		defer closeBoth()
		frameBufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(frameBufPtr)
		frameBuf := *frameBufPtr
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				_ = tunnel.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
				_, _ = tunnel.Write([]byte{0, 0})
				return
			case pkt := <-s.txCh:
				if len(pkt) == 0 || len(pkt) > udpMaxDatagram {
					continue
				}
				binary.BigEndian.PutUint16(frameBuf[:2], uint16(len(pkt)))
				copy(frameBuf[2:], pkt)
				_ = tunnel.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, err := tunnel.Write(frameBuf[:2+len(pkt)])
				_ = tunnel.SetWriteDeadline(time.Time{})
				if err != nil {
					return
				}
				s.lastActive.Store(time.Now().UnixNano())
				atomic.AddInt64(&st.bytesUp, int64(len(pkt)))
			}
		}
	}()

	// Downlink pump: framed tunnel stream -> client UDP datagrams.
	rxBufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(rxBufPtr)
	rxBuf := *rxBufPtr
	var lenHdr [2]byte

	for {
		if s.closed.Load() || ctx.Err() != nil {
			break
		}
		_ = tunnel.SetReadDeadline(time.Now().Add(udpPollStep))
		_, err := io.ReadFull(tunnel, lenHdr[:])
		if err != nil {
			if isTimeout(err) {
				if time.Since(time.Unix(0, s.lastActive.Load())) < udpSessionIdleTimeout && !s.closed.Load() && ctx.Err() == nil {
					continue
				}
				break
			}
			break
		}
		dgramLen := int(binary.BigEndian.Uint16(lenHdr[:]))
		if dgramLen == 0 {
			break
		}
		if dgramLen > udpMaxDatagram {
			closeBoth()
			writerWG.Wait()
			return fmt.Errorf("invalid UDP frame length %d from origin", dgramLen)
		}
		_ = tunnel.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err = io.ReadFull(tunnel, rxBuf[:dgramLen])
		_ = tunnel.SetReadDeadline(time.Time{})
		if err != nil {
			break
		}
		s.lastActive.Store(time.Now().UnixNano())
		if _, werr := pc.WriteTo(rxBuf[:dgramLen], s.clientAddr); werr == nil {
			atomic.AddInt64(&st.bytesDown, int64(dgramLen))
		}
	}

	closeBoth()
	writerWG.Wait()
	return nil
}

// activateUDP sends [msgActivateUDP][2B targetPort BE][2B len(firstPkt) BE][firstPkt]
// in one coalesced write and waits for msgAck from the origin.
func activateUDP(tunnel net.Conn, firstPkt []byte, targetPort uint16) error {
	if len(firstPkt) == 0 || len(firstPkt) > udpMaxDatagram {
		return fmt.Errorf("invalid initial UDP datagram length %d", len(firstPkt))
	}
	opening := make([]byte, 5+len(firstPkt))
	opening[0] = msgActivateUDP
	binary.BigEndian.PutUint16(opening[1:3], targetPort)
	binary.BigEndian.PutUint16(opening[3:5], uint16(len(firstPkt)))
	copy(opening[5:], firstPkt)

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
		if isRejection(ack[0]) {
			return describeRejection(ack[0])
		}
		return errBadAck
	}
	return nil
}

// handleActivatedUDP serves an incoming framed UDP session on the origin server
// by opening a dedicated connected local UDP socket to inboundAddr so stateful
// UDP services (WireGuard, Hysteria2, TUIC, OpenVPN, game servers) isolate each
// user session by distinct local ephemeral port.
func (o *origin) handleActivatedUDP(tunnel net.Conn, inboundAddr string) {
	svc, err := net.DialTimeout("udp", inboundAddr, inboundDialTimeout)
	if err != nil {
		atomic.AddInt64(&o.st.failedSessions, 1)
		o.logDial.printf("cannot open local UDP socket to %s: %v", inboundAddr, err)
		_ = tunnel.Close()
		return
	}

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

	o.relayUDPOrigin(svc, tunnel)
}

func (o *origin) relayUDPOrigin(svc, tunnel net.Conn) {
	var (
		lastActive atomic.Int64
		closed     atomic.Bool
		closeOnce  sync.Once
	)
	lastActive.Store(time.Now().UnixNano())

	closeBoth := func() {
		closed.Store(true)
		closeOnce.Do(func() {
			_ = svc.Close()
			_ = tunnel.Close()
		})
	}
	defer closeBoth()

	var uplinkWG sync.WaitGroup
	uplinkWG.Add(1)
	go func() {
		defer uplinkWG.Done()
		defer closeBoth()
		upBufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(upBufPtr)
		upBuf := *upBufPtr
		var lenHdr [2]byte

		for {
			if closed.Load() {
				return
			}
			_ = tunnel.SetReadDeadline(time.Now().Add(udpPollStep))
			_, err := io.ReadFull(tunnel, lenHdr[:])
			if err != nil {
				if isTimeout(err) {
					if time.Since(time.Unix(0, lastActive.Load())) < udpOriginIdleTimeout && !closed.Load() {
						continue
					}
				}
				return
			}
			dgramLen := int(binary.BigEndian.Uint16(lenHdr[:]))
			if dgramLen == 0 || dgramLen > udpMaxDatagram {
				return
			}
			_ = tunnel.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, err = io.ReadFull(tunnel, upBuf[:dgramLen])
			_ = tunnel.SetReadDeadline(time.Time{})
			if err != nil {
				return
			}
			lastActive.Store(time.Now().UnixNano())
			_ = svc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, werr := svc.Write(upBuf[:dgramLen])
			_ = svc.SetWriteDeadline(time.Time{})
			if werr != nil {
				return
			}
			atomic.AddInt64(&o.st.bytesUp, int64(n))
		}
	}()

	downBufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(downBufPtr)
	downBuf := *downBufPtr

	for {
		if closed.Load() {
			break
		}
		_ = svc.SetReadDeadline(time.Now().Add(udpPollStep))
		n, err := svc.Read(downBuf[2:])
		if err != nil {
			if isTimeout(err) {
				if time.Since(time.Unix(0, lastActive.Load())) < udpOriginIdleTimeout && !closed.Load() {
					continue
				}
			}
			break
		}
		if n <= 0 || n > udpMaxDatagram {
			continue
		}
		lastActive.Store(time.Now().UnixNano())
		binary.BigEndian.PutUint16(downBuf[:2], uint16(n))
		_ = tunnel.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, werr := tunnel.Write(downBuf[:2+n])
		_ = tunnel.SetWriteDeadline(time.Time{})
		if werr != nil {
			break
		}
		atomic.AddInt64(&o.st.bytesDown, int64(n))
	}

	closeBoth()
	uplinkWG.Wait()
}

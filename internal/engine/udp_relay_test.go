package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// udpEchoService echoes each datagram back prefixed with the Origin ephemeral
// UDP port it arrived from ("<port>|<UPPERCASE_PAYLOAD>"), proving both payload
// integrity and per-client UDP socket isolation on Origin.
type udpEchoService struct {
	addr string
	pc   net.PacketConn
	wg   sync.WaitGroup
}

func startUDPEchoService(t *testing.T) *udpEchoService {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	s := &udpEchoService{addr: pc.LocalAddr().String(), pc: pc}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, port, _ := net.SplitHostPort(from.String())
			reply := fmt.Sprintf("%s|%s", port, bytes.ToUpper(buf[:n]))
			_, _ = pc.WriteTo([]byte(reply), from)
		}
	}()
	return s
}

func (s *udpEchoService) stop() {
	_ = s.pc.Close()
	s.wg.Wait()
}

func freeDualPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp listen on %s: %v", addr, err)
	}
	_ = pc.Close()
	return addr
}

func TestUDPRelayPoolAndMuxClientIsolationAndBytes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mux          bool
		forwardProto string
	}{
		{name: "pool_both", mux: false, forwardProto: "both"},
		{name: "mux_both", mux: true, forwardProto: "both"},
		{name: "mux_udp_only", mux: true, forwardProto: "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			udpSvc := startUDPEchoService(t)
			defer udpSvc.stop()

			var tcpSvc *service
			inboundAddr := udpSvc.addr
			if tc.forwardProto == "both" {
				// Bind a TCP echo service on the exact same port as udpSvc so a single
				// port forwards both TCP and UDP simultaneously.
				ln, err := net.Listen("tcp", udpSvc.addr)
				if err != nil {
					t.Fatalf("tcp listen on shared service addr %s: %v", udpSvc.addr, err)
				}
				tcpSvc = &service{addr: ln.Addr().String(), ln: ln}
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						tcpSvc.wg.Add(1)
						go func(c net.Conn) {
							defer tcpSvc.wg.Done()
							defer c.Close()
							buf := make([]byte, 4096)
							for {
								n, rerr := c.Read(buf)
								if n > 0 {
									_, _ = c.Write(bytes.ToUpper(buf[:n]))
								}
								if rerr != nil {
									return
								}
							}
						}(c)
					}
				}()
				defer tcpSvc.stop()
			}

			tunnelAddr := freeAddr(t)
			userAddr := freeDualPort(t)
			secretFile := writeSecret(t, testSecret)

			mkCfg := func(role Role) *Config {
				cfg := DefaultConfig()
				cfg.Name = "udp_" + tc.name + "_" + string(role)
				cfg.Mode = ModeDirect
				cfg.Role = role
				cfg.Transport = TransportPlain
				cfg.ForwardProto = tc.forwardProto
				cfg.Mux = tc.mux
				cfg.MuxLinks = 2
				cfg.PoolSize = 6
				cfg.MaxConn = 100
				cfg.MaxPending = 32
				cfg.Drain = 500 * time.Millisecond
				cfg.SecretFile = secretFile
				cfg.StatusFile = ""
				cfg.TunnelAddr = tunnelAddr
				if role == RoleEdge {
					cfg.UserListen = userAddr
				} else {
					cfg.InboundAddr = inboundAddr
				}
				if err := cfg.Validate(); err != nil {
					t.Fatalf("validate %s: %v", role, err)
				}
				if err := cfg.LoadSecret(); err != nil {
					t.Fatalf("secret %s: %v", role, err)
				}
				return cfg
			}

			edgeCfg := mkCfg(RoleEdge)
			originCfg := mkCfg(RoleOrigin)
			edgeSt := newStatus(edgeCfg)
			originSt := newStatus(originCfg)

			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_ = runOrigin(ctx, originCfg, originSt)
			}()
			time.Sleep(100 * time.Millisecond)
			go func() {
				defer wg.Done()
				_ = runEdge(ctx, edgeCfg, edgeSt)
			}()
			defer func() {
				cancel()
				wg.Wait()
			}()

			time.Sleep(350 * time.Millisecond)

			sendRecvUDP := func(conn *net.UDPConn, msg string) (originPort, payload string) {
				t.Helper()
				for attempt := 0; attempt < 4; attempt++ {
					if _, err := conn.Write([]byte(msg)); err != nil {
						t.Fatalf("udp write: %v", err)
					}
					_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
					buf := make([]byte, 4096)
					n, err := conn.Read(buf)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() && attempt < 3 {
							continue
						}
						t.Fatalf("udp read for %q: %v", msg, err)
					}
					p, body, ok := strings.Cut(string(buf[:n]), "|")
					if !ok {
						t.Fatalf("malformed echo %q", string(buf[:n]))
					}
					return p, body
				}
				t.Fatalf("no udp reply for %q", msg)
				return "", ""
			}

			raddr, err := net.ResolveUDPAddr("udp", userAddr)
			if err != nil {
				t.Fatalf("resolve userAddr: %v", err)
			}
			clientA, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				t.Fatalf("dial clientA: %v", err)
			}
			defer clientA.Close()
			clientB, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				t.Fatalf("dial clientB: %v", err)
			}
			defer clientB.Close()

			portA1, gotA1 := sendRecvUDP(clientA, "wireguard-handshake-a1")
			if gotA1 != "WIREGUARD-HANDSHAKE-A1" {
				t.Fatalf("clientA got %q, want WIREGUARD-HANDSHAKE-A1", gotA1)
			}
			portB1, gotB1 := sendRecvUDP(clientB, "hysteria2-packet-b1")
			if gotB1 != "HYSTERIA2-PACKET-B1" {
				t.Fatalf("clientB got %q, want HYSTERIA2-PACKET-B1", gotB1)
			}
			if portA1 == portB1 {
				t.Fatalf("expected distinct Origin ephemeral UDP ports per client, both got %s", portA1)
			}

			// Subsequent datagrams from clientA must reuse the same stateful session port.
			portA2, gotA2 := sendRecvUDP(clientA, "wireguard-keepalive-a2")
			if gotA2 != "WIREGUARD-KEEPALIVE-A2" {
				t.Fatalf("clientA second packet got %q", gotA2)
			}
			if portA2 != portA1 {
				t.Fatalf("clientA session port changed from %s to %s", portA1, portA2)
			}

			// Verify byte counters on both Edge and Origin recorded the UDP traffic.
			eUp, eDown := atomic.LoadInt64(&edgeSt.bytesUp), atomic.LoadInt64(&edgeSt.bytesDown)
			if eUp <= 0 || eDown <= 0 {
				t.Fatalf("edge byte counters not incremented: up=%d down=%d", eUp, eDown)
			}
			oUp, oDown := atomic.LoadInt64(&originSt.bytesUp), atomic.LoadInt64(&originSt.bytesDown)
			if oUp <= 0 || oDown <= 0 {
				t.Fatalf("origin byte counters not incremented: up=%d down=%d", oUp, oDown)
			}

			if tc.forwardProto == "both" {
				// TCP must work simultaneously on the same user port.
				tcConn, err := net.DialTimeout("tcp", userAddr, 2*time.Second)
				if err != nil {
					t.Fatalf("tcp dial on dual tcp+udp port failed: %v", err)
				}
				defer tcConn.Close()
				msg := "simultaneous-tcp-stream"
				if _, err := tcConn.Write([]byte(msg)); err != nil {
					t.Fatalf("tcp write: %v", err)
				}
				got := make([]byte, len(msg))
				_ = tcConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := io.ReadFull(tcConn, got); err != nil {
					t.Fatalf("tcp read: %v", err)
				}
				if string(got) != strings.ToUpper(msg) {
					t.Fatalf("tcp got %q, want %q", string(got), strings.ToUpper(msg))
				}
			} else if tc.forwardProto == "udp" {
				// UDP-only mode must not open a TCP user listener.
				if c, err := net.DialTimeout("tcp", userAddr, 250*time.Millisecond); err == nil {
					_ = c.Close()
					t.Fatalf("expected TCP dial to fail on udp-only user port %s", userAddr)
				}
			}
		})
	}
}

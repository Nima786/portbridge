package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// Exercises the disguise wrappers on their own, so a failure points at the
// wrapper rather than at the whole tunnel.
func TestWrapRoundTripPerTransport(t *testing.T) {
	for _, tr := range []Transport{TransportPlain, TransportTLS, TransportWSS} {
		t.Run(string(tr), func(t *testing.T) {
			certFile, keyFile := certPaths(t)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			cfg := defaultConfig()
			cfg.Transport = tr
			cfg.ServerName = "www.example.com"
			cfg.WSPath = "/live/stream"
			cfg.TunnelAddr = ln.Addr().String()
			cfg.CertFile, cfg.KeyFile = certFile, keyFile

			var cert *tls.Certificate
			if tr != TransportPlain {
				c, err := ensureCert(certFile, keyFile, cfg.effectiveServerName())
				if err != nil {
					t.Fatalf("cert: %v", err)
				}
				cert = &c
			}

			type res struct {
				c   net.Conn
				err error
			}
			accepted := make(chan res, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					accepted <- res{nil, err}
					return
				}
				c, err := wrapAccept(raw, cfg, cert)
				accepted <- res{c, err}
			}()

			raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			client, err := wrapDial(raw, cfg)
			if err != nil {
				t.Fatalf("wrapDial failed: %v", err)
			}
			defer client.Close()

			r := <-accepted
			if r.err != nil {
				t.Fatalf("wrapAccept failed: %v", r.err)
			}
			server := r.c
			defer server.Close()

			// Small message each way.
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatalf("client write: %v", err)
			}
			buf := make([]byte, 4)
			_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(server, buf); err != nil {
				t.Fatalf("server read: %v", err)
			}
			if string(buf) != "ping" {
				t.Fatalf("server got %q", buf)
			}
			if _, err := server.Write([]byte("pong")); err != nil {
				t.Fatalf("server write: %v", err)
			}
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatalf("client read: %v", err)
			}
			if string(buf) != "pong" {
				t.Fatalf("client got %q", buf)
			}

			// A payload well past one frame-length boundary, echoed back.
			//
			// Both sides must read while writing. A payload this size does not
			// fit in socket buffers, so writing it all before reading anything
			// deadlocks the test rather than the code.
			big := make([]byte, 300_000)
			if _, err := rand.Read(big); err != nil {
				t.Fatal(err)
			}
			_ = server.SetDeadline(time.Now().Add(30 * time.Second))
			_ = client.SetDeadline(time.Now().Add(30 * time.Second))

			echoed := make(chan error, 1)
			go func() {
				got := make([]byte, len(big))
				if _, err := io.ReadFull(server, got); err != nil {
					echoed <- err
					return
				}
				if !bytes.Equal(got, big) {
					echoed <- io.ErrUnexpectedEOF
					return
				}
				_, err := server.Write(got)
				echoed <- err
			}()

			readBack := make(chan error, 1)
			back := make([]byte, len(big))
			go func() {
				_, err := io.ReadFull(client, back)
				readBack <- err
			}()

			if _, err := client.Write(big); err != nil {
				t.Fatalf("client write big: %v", err)
			}
			if err := <-echoed; err != nil {
				t.Fatalf("server side of the big transfer: %v", err)
			}
			if err := <-readBack; err != nil {
				t.Fatalf("client read big: %v", err)
			}
			if !bytes.Equal(back, big) {
				t.Fatal("the large payload came back altered")
			}
		})
	}
}

// wsPair gives two ends of the full CDN disguise, secured channel and all, over
// real TCP.
//
// Both details matter for what these tests are about. Real sockets, because the
// fault is in what the operating system does with unread data when a socket is
// closed, which an in-memory pipe cannot show. And the full stack, because the
// unread data in question is the secure channel's own goodbye, which sits on the
// wire after the websocket has already said it is finished.
func wsPair(t *testing.T) (client, server net.Conn) {
	t.Helper()

	certFile, keyFile := certPaths(t)
	cfg := defaultConfig()
	cfg.Transport = TransportWSS
	cfg.ServerName = "www.example.com"
	cfg.WSPath = "/live/stream"
	cfg.CertFile, cfg.KeyFile = certFile, keyFile

	cert, err := ensureCert(certFile, keyFile, cfg.effectiveServerName())
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg.TunnelAddr = ln.Addr().String()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			accepted <- res{nil, err}
			return
		}
		c, err := wrapAccept(raw, cfg, &cert)
		accepted <- res{c, err}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client, err = wrapDial(raw, cfg)
	if err != nil {
		t.Fatalf("wrapDial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("wrapAccept: %v", r.err)
	}
	return client, r.c
}

// One end finishing sending early must not cost the other end the reply.
//
// This walks through the exact sequence that used to lose data, which is the
// ordinary shape of a request and a large answer:
//
//	the asking end says what it wants and finishes sending
//	the answering end notices, and stops reading at that point
//	the answering end sends a large reply and closes
//
// The trap is in the middle step. The websocket says it is finished one frame
// before the secure channel underneath does, so the answering end stops reading
// with a few bytes of the channel's goodbye still on the wire. Closing a socket
// that has unread data waiting is not a polite finish: the system sends a reset,
// and the reset tells the asking end to throw away everything it has not handed
// over yet. That showed up as a download stopping short, at random, with nothing
// in any log.
func TestWebsocketEarlyFinishDoesNotLoseTheReply(t *testing.T) {
	// Several sizes, because whether anything is lost depends on how far behind
	// the reader is when the close lands. A reply small enough to sit entirely in
	// the socket's own buffer is the worst case: the answering end finishes and
	// closes before the asking end has read a single byte.
	for _, size := range []int{16 << 10, 64 << 10, 256 << 10, 1 << 20} {
		client, server := wsPair(t)
		payload := bytes.Repeat([]byte("PortBridge!"), size/11)

		// The asking end sends a little and finishes.
		_ = client.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := client.Write([]byte("go")); err != nil {
			t.Fatalf("%d bytes: write: %v", size, err)
		}
		if cw, ok := client.(closeWriter); ok {
			if err := cw.CloseWrite(); err != nil {
				t.Fatalf("%d bytes: finish sending: %v", size, err)
			}
		}

		sendDone := make(chan error, 1)
		go func() {
			_ = server.SetDeadline(time.Now().Add(30 * time.Second))
			// Read until the asking end has finished, which is where the
			// channel's goodbye is left unread.
			_, _ = io.Copy(io.Discard, server)
			if _, err := server.Write(payload); err != nil {
				sendDone <- err
				return
			}
			if cw, ok := server.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			sendDone <- server.Close()
		}()

		// Deliberately behind. Nothing has been read here yet when the answering
		// end finishes and closes.
		time.Sleep(250 * time.Millisecond)

		got, err := io.ReadAll(client)
		if err != nil {
			t.Fatalf("%d bytes: read: %v", size, err)
		}
		if err := <-sendDone; err != nil {
			t.Fatalf("%d bytes: answering end: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%d of %d bytes arrived, so the tail was lost",
				len(got), len(payload))
		}
		_ = client.Close()
	}
}

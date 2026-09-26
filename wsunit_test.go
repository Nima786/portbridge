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

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeXHTTPTestCert(t *testing.T, serverName string) tls.Certificate {
	t.Helper()
	dir := t.TempDir()
	cert, err := EnsureCert(
		filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "key.pem"),
		serverName,
	)
	if err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	return cert
}

func TestXHTTPBidirectionalTransferAndRotation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cert := makeXHTTPTestCert(t, "www.bing.com")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	serverCfg := DefaultConfig()
	serverCfg.Mode = ModeDirect
	serverCfg.Role = RoleOrigin
	serverCfg.Transport = TransportXHTTP
	serverCfg.ServerName = "www.bing.com"
	serverCfg.WSPath = "/api/v1/testxhttp"
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	acceptedCh := make(chan net.Conn, 2)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, serverCfg, &cert)
				if err != nil {
					if !errors.Is(err, errXHTTPUplinkAttached) {
						_ = c.Close()
					}
					return
				}
				if _, err := recvAuthPurpose(sc, secret, nil); err != nil {
					_ = sc.Close()
					return
				}
				acceptedCh <- sc
			}(raw)
		}
	}()

	clientCfg := DefaultConfig()
	clientCfg.Mode = ModeDirect
	clientCfg.Role = RoleEdge
	clientCfg.TunnelAddr = ln.Addr().String()
	clientCfg.Transport = TransportXHTTP
	clientCfg.ServerName = "www.bing.com"
	clientCfg.WSPath = "/api/v1/testxhttp"
	clientCfg.UTLS = true
	clientCfg.TLSFragment = true
	clientCfg.utlsSet = true
	clientCfg.fragmentSet = true
	clientCfg.echSet = true
	clientCfg.secret = secret
	clientCfg.prepareTLS(nil)

	rawDial, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	cc, err := wrapDial(rawDial, clientCfg)
	if err != nil {
		t.Fatalf("wrapDial(xhttp): %v", err)
	}
	defer cc.Close()

	if err := sendAuthPurpose(cc, secret, authPurposeTunnel); err != nil {
		t.Fatalf("sendAuthPurpose: %v", err)
	}

	var sc net.Conn
	select {
	case sc = <-acceptedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to accept XHTTP session")
	}
	defer sc.Close()

	// Transfer 3 MB each way simultaneously (exercises multi-worker POSTs,
	// sequence reordering, and chunked downlink streaming).
	const payloadBytes = 3 * 1024 * 1024
	upData := make([]byte, payloadBytes)
	downData := make([]byte, payloadBytes)
	_, _ = rand.Read(upData)
	_, _ = rand.Read(downData)

	upWant := sha256.Sum256(upData)
	downWant := sha256.Sum256(downData)

	var wg sync.WaitGroup
	var upGot [32]byte
	var downGot [32]byte
	var upErr, downErr, wUpErr, wDownErr error

	wg.Add(4)
	go func() {
		defer wg.Done()
		for off := 0; off < len(upData); {
			step := 24 * 1024
			if off+step > len(upData) {
				step = len(upData) - off
			}
			if _, err := cc.Write(upData[off : off+step]); err != nil {
				wUpErr = err
				return
			}
			off += step
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, len(upData))
		if _, err := io.ReadFull(sc, buf); err != nil {
			upErr = err
			return
		}
		upGot = sha256.Sum256(buf)
	}()
	go func() {
		defer wg.Done()
		for off := 0; off < len(downData); {
			step := 40 * 1024
			if off+step > len(downData) {
				step = len(downData) - off
			}
			if _, err := sc.Write(downData[off : off+step]); err != nil {
				wDownErr = err
				return
			}
			off += step
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, len(downData))
		if _, err := io.ReadFull(cc, buf); err != nil {
			downErr = err
			return
		}
		downGot = sha256.Sum256(buf)
	}()

	wg.Wait()
	for _, err := range []error{wUpErr, upErr, wDownErr, downErr} {
		if err != nil {
			t.Fatalf("bidirectional XHTTP transfer failed: %v", err)
		}
	}
	if upGot != upWant {
		t.Fatal("uplink SHA256 mismatch")
	}
	if downGot != downWant {
		t.Fatal("downlink SHA256 mismatch")
	}
}

func TestXHTTPMuxConcurrentStreams(t *testing.T) {
	secret := []byte("fedcba9876543210fedcba9876543210")
	cert := makeXHTTPTestCert(t, "www.bing.com")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	serverCfg := DefaultConfig()
	serverCfg.Mode = ModeDirect
	serverCfg.Role = RoleOrigin
	serverCfg.Transport = TransportXHTTP
	serverCfg.ServerName = "www.bing.com"
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, serverCfg, &cert)
				if err != nil {
					if !errors.Is(err, errXHTTPUplinkAttached) {
						_ = c.Close()
					}
					return
				}
				srvCarrier := newCarrier(sc)
				srvCarrier.start()
				for {
					select {
					case <-srvCarrier.done:
						return
					case st := <-srvCarrier.incoming:
						go func(s *muxStream) {
							defer s.Close()
							_, _ = io.Copy(s, s)
							_ = s.CloseWrite()
						}(st)
					}
				}
			}(raw)
		}
	}()

	clientCfg := DefaultConfig()
	clientCfg.Mode = ModeDirect
	clientCfg.Role = RoleEdge
	clientCfg.TunnelAddr = ln.Addr().String()
	clientCfg.Transport = TransportXHTTP
	clientCfg.ServerName = "www.bing.com"
	clientCfg.secret = secret
	clientCfg.prepareTLS(nil)

	rawDial, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	cc, err := wrapDial(rawDial, clientCfg)
	if err != nil {
		t.Fatalf("wrapDial: %v", err)
	}
	defer cc.Close()

	muxCli := newCarrier(cc)
	muxCli.start()
	defer muxCli.fail(errMuxClosed)

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			st, err := muxCli.open()
			if err != nil {
				errCh <- err
				return
			}
			defer st.Close()
			msg := make([]byte, 32*1024)
			_, _ = rand.Read(msg)
			if _, err := st.Write(msg); err != nil {
				errCh <- err
				return
			}
			_ = st.CloseWrite()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(msg, got) {
				errCh <- errors.New("echo mismatch on mux stream")
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("mux stream over XHTTP failed: %v", err)
	}
}

func TestXHTTPCdnReverseProxyCompatibility(t *testing.T) {
	secret := []byte("cdn-test-secret-0123456789abcdef")
	originCert := makeXHTTPTestCert(t, "edge.example.com")

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer originLn.Close()

	originCfg := DefaultConfig()
	originCfg.Mode = ModeDirect
	originCfg.Role = RoleOrigin
	originCfg.Transport = TransportXHTTP
	originCfg.CDN = true
	originCfg.ServerName = "edge.example.com"
	originCfg.WSPath = "/cdn/stream"
	originCfg.secret = secret
	originCfg.prepareTLS(&originCert)

	go func() {
		for {
			raw, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, originCfg, &originCert)
				if err != nil {
					if !errors.Is(err, errXHTTPUplinkAttached) {
						_ = c.Close()
					}
					return
				}
				defer sc.Close()
				_, _ = io.Copy(sc, sc)
			}(raw)
		}
	}()

	// Standard HTTP/1.1 TLS reverse proxy simulating a CDN edge node:
	// terminates client TLS, forwards GET and POST over separate backend
	// connections to Origin, and flushes chunked responses immediately.
	targetURL, _ := url.Parse("https://" + originLn.Addr().String())
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.FlushInterval = -1
	rp.Transport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
		MaxIdleConnsPerHost: 4,
	}
	cdnSrv := httptest.NewUnstartedServer(rp)
	cdnSrv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	cdnSrv.StartTLS()
	defer cdnSrv.Close()

	cdnAddr := strings.TrimPrefix(cdnSrv.URL, "https://")

	clientCfg := DefaultConfig()
	clientCfg.Mode = ModeDirect
	clientCfg.Role = RoleEdge
	clientCfg.TunnelAddr = cdnAddr
	clientCfg.Transport = TransportXHTTP
	clientCfg.CDN = true
	clientCfg.ServerName = "edge.example.com"
	clientCfg.CleanIPs = []string{cdnAddr}
	clientCfg.WSPath = "/cdn/stream"
	clientCfg.ECH = false
	clientCfg.echSet = true
	clientCfg.secret = secret
	clientCfg.prepareTLS(nil)

	rawDial, err := net.DialTimeout("tcp", cdnAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial CDN proxy: %v", err)
	}
	cc, err := wrapDial(rawDial, clientCfg)
	if err != nil {
		t.Fatalf("wrapDial through CDN reverse proxy: %v", err)
	}
	defer cc.Close()

	payload := make([]byte, 256*1024)
	_, _ = rand.Read(payload)

	errCh := make(chan error, 1)
	go func() {
		_, werr := cc.Write(payload)
		errCh <- werr
	}()

	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, echoed); err != nil {
		t.Fatalf("read echoed payload through CDN proxy: %v", err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatalf("write payload through CDN proxy: %v", werr)
	}
	if !bytes.Equal(payload, echoed) {
		t.Fatal("payload corrupted across CDN HTTP reverse proxy")
	}
}

func TestXHTTPDecoyResponseOnInvalidAuthOrPath(t *testing.T) {
	secret := []byte("decoy-test-secret-0123456789abcd")
	cert := makeXHTTPTestCert(t, "www.bing.com")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	serverCfg := DefaultConfig()
	serverCfg.Mode = ModeDirect
	serverCfg.Role = RoleOrigin
	serverCfg.Transport = TransportXHTTP
	serverCfg.ServerName = "www.bing.com"
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = wrapAccept(c, serverCfg, &cert)
				_ = c.Close()
			}(raw)
		}
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
	}
	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	for _, path := range []string{
		"/wrong/path",
		defaultXHTTPPath + "/00112233445566778899aabbccddeeff",
	} {
		resp, err := cli.Get("https://" + ln.Addr().String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: got status %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestXHTTPProbeListenerIntegration(t *testing.T) {
	secret := []byte("probe-xhttp-secret-0123456789abc")
	pl, err := StartProbeListener("127.0.0.1", 0, secret, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener: %v", err)
	}
	defer pl.Close()

	var xhttpSpec *ProbeCandidateSpec
	for _, c := range BuildProbeCandidates("direct", "127.0.0.1", "", pl.Port, "") {
		if c.Link == "xhttp" {
			cp := c
			xhttpSpec = &cp
			break
		}
	}
	if xhttpSpec == nil {
		t.Fatal("BuildProbeCandidates did not include direct-xhttp candidate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := RunProbeDialer(ctx, []ProbeCandidateSpec{*xhttpSpec}, secret, 128*1024)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != "ok" || r.Successes < 2 {
		t.Fatalf("probe direct-xhttp failed: status=%q successes=%d err=%q summary=%q",
			r.Status, r.Successes, r.Error, r.Summary)
	}
}

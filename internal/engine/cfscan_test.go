package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestExpandCFScanCandidatesDefaultSubnets(t *testing.T) {
	ips := expandCFScanCandidates(nil)
	if len(ips) != len(DefaultCloudflareSubnets) {
		t.Fatalf("got %d sampled IPs, want %d", len(ips), len(DefaultCloudflareSubnets))
	}
	seen24 := map[string]bool{}
	for _, s := range ips {
		if err := CheckCleanIP(s); err != nil {
			t.Fatalf("CheckCleanIP(%q) failed: %v", s, err)
		}
		ip := net.ParseIP(s).To4()
		if ip == nil {
			t.Fatalf("expected IPv4 from DefaultCloudflareSubnets, got %q", s)
		}
		if ip[3] == 0 || ip[3] == 1 || ip[3] == 255 {
			t.Fatalf("sampled reserved edge octet in %q", s)
		}
		sub := subnet24Key(s)
		if seen24[sub] {
			t.Fatalf("duplicate /24 %s in default candidate expansion", sub)
		}
		seen24[sub] = true
	}
}

func TestScanCloudflareCleanIPsEndToEnd(t *testing.T) {
	pl, err := StartProbeListener("127.0.0.1", 0, nil, time.Minute)
	if err != nil {
		t.Fatalf("StartProbeListener: %v", err)
	}
	defer pl.Close()

	for _, tr := range []string{"wss", "xhttp", "grpc", "h3"} {
		t.Run(tr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			rep, err := ScanCloudflareCleanIPs(ctx, CFScanRequest{
				Domain:     "edge.example.com",
				Port:       pl.Port,
				Transport:  tr,
				Secret:     pl.Secret,
				Candidates: []string{"127.0.0.1"},
				MaxSelect:  3,
			})
			if err != nil {
				t.Fatalf("ScanCloudflareCleanIPs(%s): %v", tr, err)
			}
			if rep.ScannedCount != 1 || rep.PassedStage1 != 1 || rep.VerifiedCount != 1 {
				t.Fatalf("unexpected counts for %s: %+v", tr, rep)
			}
			if len(rep.Recommended) != 1 || rep.Recommended[0] != "127.0.0.1" {
				t.Fatalf("unexpected recommended IPs for %s: %v", tr, rep.Recommended)
			}
			if len(rep.Results) != 1 || rep.Results[0].Status != "ok" || !rep.Results[0].Selected {
				t.Fatalf("unexpected result entry for %s: %+v", tr, rep.Results)
			}
			if rep.Results[0].DownMbps <= 0 || rep.Results[0].UpMbps <= 0 || rep.Results[0].Score <= 0 {
				t.Fatalf("expected positive throughput & score for %s, got %+v", tr, rep.Results[0])
			}
		})
	}

	t.Run("wrong_secret_rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		rep, err := ScanCloudflareCleanIPs(ctx, CFScanRequest{
			Domain:     "edge.example.com",
			Port:       pl.Port,
			Transport:  "wss",
			Secret:     bytes.Repeat([]byte{0x5a}, 32),
			Candidates: []string{"127.0.0.1"},
		})
		if err != nil {
			t.Fatalf("ScanCloudflareCleanIPs(wrong secret): %v", err)
		}
		if rep.VerifiedCount != 0 || len(rep.Recommended) != 0 {
			t.Fatalf("wrong secret should verify 0 IPs, got %+v", rep)
		}
		if len(rep.Results) != 1 || rep.Results[0].Status != "blocked" {
			t.Fatalf("expected blocked status on auth mismatch, got %+v", rep.Results)
		}
	})

	t.Run("validation", func(t *testing.T) {
		if _, err := ScanCloudflareCleanIPs(context.Background(), CFScanRequest{Secret: pl.Secret}); err == nil {
			t.Fatal("expected error for empty domain")
		}
		if _, err := ScanCloudflareCleanIPs(context.Background(), CFScanRequest{Domain: "edge.example.com"}); err == nil {
			t.Fatal("expected error for missing secret")
		}
	})
}

func TestRouterCleanIPsPrimaryAndCDNBackup(t *testing.T) {
	// 1. Primary CDN mode: CleanIPs are primary routes (#0..k-1) and rotating
	// between them must still report preferred == true (not OnBackupRoute).
	cdnCfg := DefaultConfig()
	cdnCfg.Mode = ModeDirect
	cdnCfg.Role = RoleEdge
	cdnCfg.Transport = TransportWSS
	cdnCfg.CDN = true
	cdnCfg.ServerName = "cdn.example.com"
	cdnCfg.TunnelAddr = "cdn.example.com:2053"
	cdnCfg.CleanIPs = []string{"104.16.12.50", "172.67.18.90"}

	r1 := newRouter(cdnCfg)
	if len(r1.targets) != 3 {
		t.Fatalf("primary CDN router targets = %d, want 3: %+v", len(r1.targets), r1.targets)
	}
	if r1.targets[0].addr != "104.16.12.50:2053" || !r1.targets[0].clean || !r1.targets[0].cdn {
		t.Fatalf("unexpected target[0]: %+v", r1.targets[0])
	}
	if r1.targets[1].addr != "172.67.18.90:2053" || !r1.targets[1].clean || !r1.targets[1].cdn {
		t.Fatalf("unexpected target[1]: %+v", r1.targets[1])
	}
	if r1.targets[2].addr != "cdn.example.com:2053" || r1.targets[2].clean {
		t.Fatalf("unexpected target[2]: %+v", r1.targets[2])
	}
	if _, pref := r1.inUse(); !pref {
		t.Fatal("target[0] should be preferred")
	}
	r1.settle(1)
	if addr, pref := r1.inUse(); addr != "172.67.18.90:2053" || !pref {
		t.Fatalf("rotated clean IP target[1] should remain preferred, got addr=%q pref=%v", addr, pref)
	}
	r1.settle(2)
	if _, pref := r1.inUse(); pref {
		t.Fatal("DNS hostname fallback target[2] should report preferred=false when clean IPs exist")
	}

	// 2. Direct + CDN Backup (website-cdn-backup): direct IP stays route #0,
	// while CleanIPs become clean CDN fallback routes ahead of AltTarget.
	bkpCfg := DefaultConfig()
	bkpCfg.Mode = ModeDirect
	bkpCfg.Role = RoleEdge
	bkpCfg.Transport = TransportWSS
	bkpCfg.CDN = false
	bkpCfg.ServerName = "www.mysite.com"
	bkpCfg.TunnelAddr = "203.0.113.10:443"
	bkpCfg.AltTarget = "cdn.mysite.com:2053"
	bkpCfg.AltServerName = "cdn.mysite.com"
	bkpCfg.CleanIPs = []string{"104.18.6.22"}

	r2 := newRouter(bkpCfg)
	if len(r2.targets) != 3 {
		t.Fatalf("website-cdn-backup router targets = %d, want 3: %+v", len(r2.targets), r2.targets)
	}
	if r2.targets[0].addr != "203.0.113.10:443" || r2.targets[0].cdn || r2.targets[0].clean {
		t.Fatalf("direct target[0] must stay primary non-CDN: %+v", r2.targets[0])
	}
	if r2.targets[1].addr != "104.18.6.22:2053" || !r2.targets[1].cdn || !r2.targets[1].clean || r2.targets[1].name != "cdn.mysite.com" {
		t.Fatalf("clean CDN backup target[1] mismatch: %+v", r2.targets[1])
	}
	if r2.targets[2].addr != "cdn.mysite.com:2053" || !r2.targets[2].cdn || r2.targets[2].clean {
		t.Fatalf("AltTarget fallback target[2] mismatch: %+v", r2.targets[2])
	}
	r2.settle(1)
	if _, pref := r2.inUse(); pref {
		t.Fatal("CDN backup clean IP target[1] must report preferred=false (OnBackupRoute=true)")
	}
}

func TestCFScanThroughSimulatedCloudflareH2OriginProxy(t *testing.T) {
	// Subtest 1: ProbeListener in default multi-mode (NextProtos: ["h2", "http/1.1"],
	// as used by Find Best Tunnel Mode) behind a TLS reverse proxy that speaks
	// HTTP/2 to Origin (matching Cloudflare's default "HTTP/2 to Origin" setting).
	t.Run("h2_to_origin_xhttp", func(t *testing.T) {
		pl, err := StartProbeListener("127.0.0.1", 0, nil, time.Minute)
		if err != nil {
			t.Fatalf("StartProbeListener: %v", err)
		}
		defer pl.Close()

		originURL, err := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", pl.Port))
		if err != nil {
			t.Fatal(err)
		}
		rp := httputil.NewSingleHostReverseProxy(originURL)
		rp.FlushInterval = -1
		rp.Transport = &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // loopback self-signed probe cert
				NextProtos:         []string{"h2"},
			},
		}

		edgeProxy := httptest.NewTLSServer(rp)
		defer edgeProxy.Close()
		proxyPort := edgeProxy.Listener.Addr().(*net.TCPAddr).Port

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		rep, err := ScanCloudflareCleanIPs(ctx, CFScanRequest{
			Domain:     "ae.example.com",
			Port:       proxyPort,
			Transport:  "xhttp",
			Secret:     pl.Secret,
			Candidates: []string{"127.0.0.1"},
			MaxSelect:  3,
		})
		if err != nil {
			t.Fatalf("ScanCloudflareCleanIPs over H2-to-Origin proxy: %v", err)
		}
		if rep.VerifiedCount != 1 || len(rep.Recommended) != 1 {
			t.Fatalf("expected 1 verified clean IP over H2-to-Origin proxy, got %+v", rep)
		}

		// Also verify Find Best Tunnel Mode's probeOneSpec (xhttp-cdn) succeeds
		// through the same HTTP/2-to-Origin proxy.
		cand := probeOneSpec(ctx, ProbeCandidateSpec{
			ID:         "direct-xhttp-cdn",
			Label:      "Cloudflare / CDN SplitHTTP (XHTTP)",
			Mode:       "direct",
			Link:       "xhttp-cdn",
			TargetAddr: fmt.Sprintf("ae.example.com:%d", proxyPort),
			Port:       proxyPort,
			Transport:  "xhttp",
			ServerName: "ae.example.com",
			Domain:     "ae.example.com",
			CDN:        true,
			CleanIPs:   []string{"127.0.0.1"},
		}, pl.Secret, 64*1024)
		if cand.Status != "ok" {
			t.Fatalf("probeOneSpec(xhttp-cdn) over H2-to-Origin proxy failed: %+v", cand)
		}
	})

	// Subtest 2: ProbeListener with SetHTTP1Only(true) forces an HTTP/2-capable
	// reverse proxy (ForceAttemptHTTP2: true) to negotiate HTTP/1.1 to Origin so
	// both WSS (HTTP/1.1 Upgrade) and XHTTP succeed end-to-end.
	t.Run("http1_only_wss_and_xhttp", func(t *testing.T) {
		pl, err := StartProbeListener("127.0.0.1", 0, nil, time.Minute)
		if err != nil {
			t.Fatalf("StartProbeListener: %v", err)
		}
		defer pl.Close()
		pl.SetHTTP1Only(true)

		originURL, err := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", pl.Port))
		if err != nil {
			t.Fatal(err)
		}
		rp := httputil.NewSingleHostReverseProxy(originURL)
		rp.FlushInterval = -1
		rp.Transport = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // loopback self-signed probe cert
			},
		}

		edgeProxy := httptest.NewTLSServer(rp)
		defer edgeProxy.Close()
		proxyPort := edgeProxy.Listener.Addr().(*net.TCPAddr).Port

		for _, tr := range []string{"wss", "xhttp"} {
			t.Run(tr, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				rep, err := ScanCloudflareCleanIPs(ctx, CFScanRequest{
					Domain:     "ae.example.com",
					Port:       proxyPort,
					Transport:  tr,
					Secret:     pl.Secret,
					Candidates: []string{"127.0.0.1"},
					MaxSelect:  3,
				})
				if err != nil {
					t.Fatalf("ScanCloudflareCleanIPs(%s) with HTTP1Only: %v", tr, err)
				}
				if rep.VerifiedCount != 1 || len(rep.Recommended) != 1 {
					t.Fatalf("expected 1 verified clean IP for %s with HTTP1Only, got %+v", tr, rep)
				}
			})
		}
	})
}

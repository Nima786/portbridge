package cfscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestExpandCandidatesDiversityAndCustomRanges(t *testing.T) {
	c44 := ExpandCandidates(nil, 44)
	if len(c44) != 44 {
		t.Fatalf("expected 44 default candidates, got %d", len(c44))
	}
	for _, ipStr := range c44 {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			t.Fatalf("expected IPv4, got %q", ipStr)
		}
		if ip[3] == 0 || ip[3] == 1 || ip[3] == 255 {
			t.Fatalf("reserved host octet sampled: %s", ipStr)
		}
	}

	c160 := ExpandCandidates(nil, 160)
	if len(c160) != 160 {
		t.Fatalf("expected 160 deep candidates, got %d", len(c160))
	}

	custom := ExpandCandidates([]string{"104.16.12.34, 172.67.45.67\n104.18.6.0/24"}, 10)
	if len(custom) != 10 {
		t.Fatalf("expected 10 custom expanded candidates, got %d (%v)", len(custom), custom)
	}
	if custom[0] != "104.16.12.34" || custom[1] != "172.67.45.67" {
		t.Fatalf("expected explicit custom IPs preserved first, got %v", custom[:2])
	}
}

func TestDetectISPMergesAndFallsBack(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","query":"5.120.44.18","isp":"Irancell","as":"AS44244","country":"Iran","city":"Tehran"}`)
	}))
	t.Cleanup(ipSrv.Close)

	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"clientIp":"5.120.44.18","asn":44244,"asOrganization":"MTN Irancell","country":"IR","city":"Tehran","colo":"DXB"}`)
	}))
	t.Cleanup(cfSrv.Close)

	oldIP, oldCF := ipAPIURL, cfMetaURL
	ipAPIURL = ipSrv.URL
	cfMetaURL = cfSrv.URL
	t.Cleanup(func() {
		ipAPIURL = oldIP
		cfMetaURL = oldCF
	})

	info := DetectISP(context.Background())
	if !info.Detected || info.IP != "5.120.44.18" || info.ISP != "Irancell" || info.Colo != "DXB" {
		t.Fatalf("unexpected ISP info: %+v", info)
	}

	// Fallback when Cloudflare meta is unreachable (e.g. default CF IP blocked on ISP).
	cfMetaURL = "http://127.0.0.1:1"
	info2 := DetectISP(context.Background())
	if !info2.Detected || info2.ISP != "Irancell" {
		t.Fatalf("expected fallback to ip-api when CF meta blocked, got %+v", info2)
	}
}

func TestRunFullTwoStageRealTLSSpeedAndFragmentation(t *testing.T) {
	var mu sync.Mutex
	seenSNIs := map[string]int{}

	mux := http.NewServeMux()
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			mu.Lock()
			seenSNIs[r.TLS.ServerName]++
			mu.Unlock()
		}
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "89abcdef12345678-FRA")
		_, _ = io.WriteString(w, "fl=123f45\nh="+r.Host+"\nip=5.120.44.18\ncolo=FRA\n")
	})
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		if n <= 0 || n > 4*1024*1024 {
			n = 512 * 1024
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = io.CopyN(w, zeroReader{}, int64(n))
	})
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	// Point ISP detection at a fast local stub so the test makes zero external calls.
	ipStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"status":"success","query":"5.120.1.2","isp":"MCI","as":"AS197207","country":"Iran","city":"Tehran"}`)
	}))
	t.Cleanup(ipStub.Close)
	oldIP, oldCF := ipAPIURL, cfMetaURL
	ipAPIURL = ipStub.URL
	cfMetaURL = ipStub.URL
	t.Cleanup(func() {
		ipAPIURL = oldIP
		cfMetaURL = oldCF
	})

	for _, frag := range []bool{false, true} {
		var phases []string
		rep, err := Run(context.Background(), Request{
			Domain:        "cdn.test.example.com",
			Port:          port,
			Count:         1,
			MaxSelect:     1,
			Fragment:      frag,
			CustomRanges:  []string{host},
			DownloadBytes: 512 * 1024,
			UploadBytes:   128 * 1024,
			SpeedHost:     "speed.test.example.com",
			SpeedPort:     port,
			TLSConfigHook: func(c *tls.Config) {
				c.InsecureSkipVerify = true
			},
		}, func(p Progress) {
			phases = append(phases, p.Phase)
		})
		if err != nil {
			t.Fatalf("Run(fragment=%v) failed: %v", frag, err)
		}
		if rep.VerifiedCount != 1 || len(rep.Recommended) != 1 || rep.Recommended[0] != host {
			t.Fatalf("Run(fragment=%v) unexpected report: %+v", frag, rep)
		}
		got := rep.Results[0]
		if got.Status != "ok" || got.Colo != "FRA" || got.DownMbps <= 0 || got.UpMbps <= 0 || got.Score < 50 {
			t.Fatalf("Run(fragment=%v) unexpected result row: %+v", frag, got)
		}
		if len(phases) < 3 || !strings.Contains(strings.Join(phases, ","), "stage2") {
			t.Fatalf("expected stage1 + stage2 + done progress events, got %v", phases)
		}
	}

	mu.Lock()
	sniHits := seenSNIs["cdn.test.example.com"]
	mu.Unlock()
	if sniHits < 2 {
		t.Fatalf("expected custom SNI cdn.test.example.com to be sent on TLS handshake, got %d hits (%v)", sniHits, seenSNIs)
	}
}

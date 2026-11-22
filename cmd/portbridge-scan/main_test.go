package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/cfscan"
)

func TestLocalScannerWebUIAndTokenGuard(t *testing.T) {
	srv := newServer()
	srv.ispFn = func(context.Context) cfscan.ISPInfo {
		return cfscan.ISPInfo{IP: "5.120.44.18", ISP: "Irancell", ASN: "AS44244", Country: "Iran", Detected: true}
	}
	srv.runFn = func(ctx context.Context, req cfscan.Request, onProgress func(cfscan.Progress)) (*cfscan.Report, error) {
		res := []cfscan.Result{{
			IP: "104.16.12.34", Subnet: "104.16.12.0/24", Colo: "FRA",
			Status: "ok", Selected: true, RTTMS: 72, DownMbps: 48.5, UpMbps: 18.2, Score: 92,
		}}
		onProgress(cfscan.Progress{
			Phase: "done", Message: "Finished", Done: 1, Total: 1, Percent: 100,
			PassedStage1: 1, VerifiedCount: 1, Results: res,
		})
		return &cfscan.Report{
			Domain: "speed.cloudflare.com", Port: 443,
			ISP:           srv.ispFn(ctx),
			ScannedCount:  1,
			PassedStage1:  1,
			VerifiedCount: 1,
			Recommended:   []string{"104.16.12.34"},
			Results:       res,
		}, nil
	}

	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)

	// 1. Static embedded UI serves HTML/CSS/JS with strict CSP.
	for _, path := range []string{"/", "/app.css", "/app.js"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
			t.Fatalf("missing strict CSP on %s: %q", path, csp)
		}
	}

	// 2. POST without X-PB-Token is rejected with 403 Forbidden.
	resp, err := http.Post(ts.URL+"/api/scan/start", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without token, got %d", resp.StatusCode)
	}

	// 3. Fetch token from /api/info, run scan, and poll /api/scan/status to completion.
	infoResp, err := http.Get(ts.URL + "/api/info")
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Token string         `json:"token"`
		ISP   cfscan.ISPInfo `json:"isp"`
	}
	if err := json.NewDecoder(infoResp.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	_ = infoResp.Body.Close()
	if info.Token == "" || info.ISP.ISP != "Irancell" {
		t.Fatalf("unexpected /api/info: %+v", info)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/scan/start", bytes.NewReader([]byte(`{"count":1}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-PB-Token", info.Token)
	startResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/scan/start = %d", startResp.StatusCode)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stResp, err := http.Get(ts.URL + "/api/scan/status")
		if err != nil {
			t.Fatal(err)
		}
		var st struct {
			Running bool           `json:"running"`
			Report  *cfscan.Report `json:"report"`
		}
		_ = json.NewDecoder(stResp.Body).Decode(&st)
		_ = stResp.Body.Close()
		if !st.Running && st.Report != nil {
			if len(st.Report.Recommended) != 1 || st.Report.Recommended[0] != "104.16.12.34" {
				t.Fatalf("unexpected scan report: %+v", st.Report)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("scan did not finish in time")
}

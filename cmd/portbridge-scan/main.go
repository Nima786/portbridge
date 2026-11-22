package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nima786/portbridge/internal/cfscan"
)

// version is stamped at build time (-X main.version=vX.Y.Z).
var version = "dev"

//go:embed web/*
var webFS embed.FS

type scanState struct {
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	prog    cfscan.Progress
	report  *cfscan.Report
	errMsg  string
}

type server struct {
	token  string
	state  scanState
	quitCh chan struct{}
	once   sync.Once
	runFn  func(context.Context, cfscan.Request, func(cfscan.Progress)) (*cfscan.Report, error)
	ispFn  func(context.Context) cfscan.ISPInfo
}

func newServer() *server {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return &server{
		token:  hex.EncodeToString(b[:]),
		quitCh: make(chan struct{}),
		runFn:  cfscan.Run,
		ispFn:  cfscan.DetectISP,
	}
}

func (s *server) handler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	fileSrv := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("GET /api/isp", s.handleISP)
	mux.HandleFunc("POST /api/scan/start", s.withToken(s.handleStart))
	mux.HandleFunc("GET /api/scan/status", s.handleStatus)
	mux.HandleFunc("POST /api/scan/stop", s.withToken(s.handleStop))
	mux.HandleFunc("POST /api/quit", s.withToken(s.handleQuit))
	mux.Handle("/", fileSrv)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) withToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-PB-Token")
		if len(got) != len(s.token) || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid local session token"})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	isp := s.ispFn(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"version":               version,
		"os":                    runtime.GOOS,
		"arch":                  runtime.GOARCH,
		"token":                 s.token,
		"isp":                   isp,
		"default_subnets_count": len(cfscan.DefaultSubnets),
	})
}

func (s *server) handleISP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ispFn(r.Context()))
}

func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	var req cfscan.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan request"})
		return
	}

	s.state.mu.Lock()
	if s.state.cancel != nil {
		s.state.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.state.cancel = cancel
	s.state.running = true
	s.state.report = nil
	s.state.errMsg = ""
	s.state.prog = cfscan.Progress{
		Phase:   "stage1",
		Message: "Starting real TLS & speed scan…",
		Percent: 2,
	}
	s.state.mu.Unlock()

	go func() {
		defer cancel()
		rep, err := s.runFn(ctx, req, func(p cfscan.Progress) {
			s.state.mu.Lock()
			// Only update if this scan is still the active one.
			if s.state.running {
				s.state.prog = p
			}
			s.state.mu.Unlock()
		})
		s.state.mu.Lock()
		s.state.running = false
		if err != nil {
			s.state.errMsg = err.Error()
		} else {
			s.state.report = rep
		}
		s.state.mu.Unlock()
	}()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.state.mu.Lock()
	running := s.state.running
	prog := s.state.prog
	rep := s.state.report
	errMsg := s.state.errMsg
	s.state.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"running":        running,
		"phase":          prog.Phase,
		"message":        prog.Message,
		"done":           prog.Done,
		"total":          prog.Total,
		"percent":        prog.Percent,
		"passed_stage1":  prog.PassedStage1,
		"verified_count": prog.VerifiedCount,
		"current_ip":     prog.CurrentIP,
		"results":        prog.Results,
		"report":         rep,
		"error":          errMsg,
	})
}

func (s *server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.state.mu.Lock()
	if s.state.cancel != nil {
		s.state.cancel()
	}
	s.state.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	s.state.mu.Lock()
	if s.state.cancel != nil {
		s.state.cancel()
	}
	s.state.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	s.once.Do(func() { close(s.quitCh) })
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		if p, err := exec.LookPath("termux-open-url"); err == nil {
			_ = exec.Command(p, url).Start()
			return
		}
		if p, err := exec.LookPath("xdg-open"); err == nil {
			_ = exec.Command(p, url).Start()
		}
	}
}

func runCLI(domain string, port, count, top int, fragment bool, ranges string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("PortBridge Local ISP Cloudflare Scanner %s\n", version)
	fmt.Println("Make sure your VPN is OFF so tests reflect your real ISP.")
	isp := cfscan.DetectISP(ctx)
	if isp.Detected {
		fmt.Printf("Detected ISP: %s (%s) %s\n", isp.ISP, isp.IP, isp.ASN)
	}
	var custom []string
	if strings.TrimSpace(ranges) != "" {
		custom = []string{ranges}
	}
	lastMsg := ""
	rep, err := cfscan.Run(ctx, cfscan.Request{
		Domain:       domain,
		Port:         port,
		Count:        count,
		MaxSelect:    top,
		Fragment:     fragment,
		CustomRanges: custom,
	}, func(p cfscan.Progress) {
		if p.Message != lastMsg {
			lastMsg = p.Message
			fmt.Printf("\r[%3d%%] %-72s", p.Percent, p.Message)
		}
	})
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Printf("\n%-16s %-5s %-10s %-7s %-10s %-10s %-8s\n", "IP", "COLO", "STATUS", "SCORE", "DOWNLOAD", "UPLOAD", "PING")
	fmt.Println(strings.Repeat("-", 74))
	shown := 0
	for _, r := range rep.Results {
		if r.Status == "blocked" && shown >= 15 {
			continue
		}
		mark := ""
		if r.Selected {
			mark = "*"
		}
		fmt.Printf("%-16s %-5s %-10s %3d/100 %6.1f Mbps %6.1f Mbps %5.0f ms %s\n",
			r.IP, r.Colo, r.Status, r.Score, r.DownMbps, r.UpMbps, r.RTTMS, mark)
		shown++
		if shown >= 25 {
			break
		}
	}
	if len(rep.Recommended) > 0 {
		fmt.Printf("\nRecommended Clean IPs (comma-separated):\n%s\n", strings.Join(rep.Recommended, ","))
	} else {
		fmt.Println("\nNo clean Cloudflare IPs passed full speed verification on this ISP.")
	}
	return 0
}

func listenLocal(preferred string) (net.Listener, error) {
	if preferred != "" {
		return net.Listen("tcp", preferred)
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:8787"); err == nil {
		return ln, nil
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func main() {
	listenAddr := flag.String("listen", "", "Local listen address (default 127.0.0.1:8787 or free local port)")
	noOpen := flag.Bool("no-open", false, "Do not auto-open the web browser")
	cliMode := flag.Bool("cli", false, "Run directly in terminal without starting the web UI")
	domain := flag.String("domain", "", "Optional Cloudflare-proxied subdomain to verify SNI")
	port := flag.Int("port", 443, "Cloudflare HTTPS port (443, 2053, 2083, 2087, 2096, 8443)")
	count := flag.Int("count", 64, "Number of candidate Cloudflare IPs to scan")
	top := flag.Int("top", 5, "Number of subnet-diverse clean IPs to recommend")
	fragment := flag.Bool("fragment", false, "Fragment TLS ClientHello into 40-byte chunks")
	ranges := flag.String("ranges", "", "Optional comma-separated custom IP/CIDR list")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *cliMode {
		os.Exit(runCLI(*domain, *port, *count, *top, *fragment, *ranges))
	}

	ln, err := listenLocal(*listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not listen locally: %v\n", err)
		os.Exit(1)
	}
	srv := newServer()
	httpSrv := &http.Server{
		Handler:           srv.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	url := "http://" + ln.Addr().String()
	fmt.Printf("PortBridge Local ISP Cloudflare Scanner %s\n", version)
	fmt.Printf("Open in your browser: %s\n", url)
	fmt.Println("Disconnect your VPN before scanning so tests measure your real ISP.")
	fmt.Println("Press Ctrl+C or click Quit in the browser to exit.")

	if !*noOpen {
		openBrowser(url)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-sigCh:
	case <-srv.quitCh:
		time.Sleep(150 * time.Millisecond)
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

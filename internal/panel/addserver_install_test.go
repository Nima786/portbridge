package panel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func buildTestReleaseArchive(t *testing.T, padBytes int) ([]byte, string) {
	t.Helper()
	pad := make([]byte, padBytes)
	if _, err := rand.Read(pad); err != nil {
		t.Fatal(err)
	}
	binData := append([]byte("#!/bin/sh\necho v0.17.75\n"), pad...)
	archive, err := packArchive([]pkgFile{
		{name: "portbridge", mode: 0o755, data: binData},
		{name: "install.sh", mode: 0o755, data: []byte("#!/bin/sh\nexit 0\n")},
	})
	if err != nil {
		t.Fatalf("packArchive: %v", err)
	}
	sum := sha256.Sum256(archive)
	return archive, hex.EncodeToString(sum[:])
}

type execSSHBehavior struct {
	githubDownloadOK bool
	githubErrReason  string
	freezeBulkStdin  bool
	stdinBytes       atomic.Int64
	commandsMu       sync.Mutex
	commands         []string
}

func (b *execSSHBehavior) recordCmd(cmd string) {
	b.commandsMu.Lock()
	b.commands = append(b.commands, cmd)
	b.commandsMu.Unlock()
}

func (b *execSSHBehavior) snapshotCmds() []string {
	b.commandsMu.Lock()
	defer b.commandsMu.Unlock()
	return append([]string(nil), b.commands...)
}

func startExecSSHServer(t *testing.T, signer ssh.Signer, password string, beh *execSSHBehavior) (int, string) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleExecSSHConn(rawConn, cfg, beh)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
}

func handleExecSSHConn(rawConn net.Conn, cfg *ssh.ServerConfig, beh *execSSHBehavior) {
	defer rawConn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
			for req := range chReqs {
				if req.Type != "exec" || len(req.Payload) < 4 {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload[:4])
				if int(4+n) > len(req.Payload) {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				cmd := string(req.Payload[4 : 4+n])
				beh.recordCmd(cmd)
				if req.WantReply {
					_ = req.Reply(true, nil)
				}

				if beh.freezeBulkStdin && strings.Contains(cmd, "tar -xzf -") {
					// Simulate GFW freezing bulk SSH upload: read only 4 KB and then
					// stop reading until the client force-closes the socket.
					buf := make([]byte, 4096)
					nr, _ := ch.Read(buf)
					beh.stdinBytes.Add(int64(nr))
					// Hold channel open without reading further until connection closes.
					<-time.After(10 * time.Second)
					_ = ch.Close()
					return
				}

				data, _ := io.ReadAll(ch)
				beh.stdinBytes.Add(int64(len(data)))

				exitCode := uint32(0)
				switch {
				case strings.Contains(cmd, "pb_dl=ok"):
					if beh.githubDownloadOK {
						_, _ = io.WriteString(ch, "pb_dl=ok\n")
					} else {
						reason := beh.githubErrReason
						if reason == "" {
							reason = "checksums_unreachable"
						}
						_, _ = io.WriteString(ch, "pb_dl_err="+reason+"\n")
						exitCode = 10
					}
				case strings.Contains(cmd, "pb_uid="):
					_, _ = io.WriteString(ch, "pb_uid=0\npb_arch=x86_64\npb_systemd=yes\npb_version=\n")
				}

				var status [4]byte
				binary.BigEndian.PutUint32(status[:], exitCode)
				_, _ = ch.SendRequest("exit-status", false, status[:])
				_ = ch.Close()
				return
			}
		}(ch, chReqs)
	}
}

func TestRemoteGitHubDownloadScriptChecksumAndTamperGuard(t *testing.T) {
	shPath := ""
	if runtime.GOOS == "windows" {
		for _, cand := range []string{`C:\Program Files\Git\bin\sh.exe`, `C:\Program Files\Git\usr\bin\sh.exe`} {
			if _, err := exec.LookPath(cand); err == nil {
				shPath = cand
				break
			}
		}
	} else if p, err := exec.LookPath("sh"); err == nil {
		shPath = p
	}
	if shPath == "" {
		t.Skip("POSIX sh not available")
	}
	// Verify curl/wget + tar + sha256sum/openssl exist inside sh.
	checkCmd := exec.Command(shPath, "-c", "(command -v curl || command -v wget) >/dev/null 2>&1 && command -v tar >/dev/null 2>&1 && (command -v sha256sum || command -v openssl) >/dev/null 2>&1")
	if err := checkCmd.Run(); err != nil {
		t.Skip("required shell utilities (curl/wget, tar, sha256sum/openssl) not available")
	}

	const ver = "v0.17.75"
	const arch = "amd64"
	tarName := agent.ReleaseArchiveName(ver, arch)
	goodArchive, goodSHA := buildTestReleaseArchive(t, 1024)

	var tamper atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + ver + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", goodSHA, tarName)
		case "/download/" + ver + "/" + tarName:
			if tamper.Load() {
				bad := append([]byte(nil), goodArchive...)
				bad[len(bad)-1] ^= 0xff
				_, _ = w.Write(bad)
				return
			}
			_, _ = w.Write(goodArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	suffix := newID(6)
	workDir := "/tmp/pb-gh-dl-ok-" + suffix
	workDirBad := "/tmp/pb-gh-dl-bad-" + suffix
	t.Cleanup(func() {
		_ = exec.Command(shPath, "-c", "rm -rf "+shellQuote(workDir)+" "+shellQuote(workDirBad)).Run()
	})

	// 1. Valid archive downloads, passes SHA-256 verification, and unpacks portbridge + install.sh.
	scriptOK := buildRemoteGitHubDownloadScript(workDir, srv.URL, ver, arch, 5, 15)
	out, err := exec.Command(shPath, "-c", scriptOK).CombinedOutput()
	if err != nil || parseFacts(string(out))["pb_dl"] != "ok" {
		t.Fatalf("expected valid GitHub download script to succeed, err=%v out=%s", err, string(out))
	}

	// 2. Tampered archive is rejected by SHA-256 guard with pb_dl_err=checksum_mismatch.
	tamper.Store(true)
	scriptBad := buildRemoteGitHubDownloadScript(workDirBad, srv.URL, ver, arch, 5, 15)
	outBad, errBad := exec.Command(shPath, "-c", scriptBad).CombinedOutput()
	if errBad == nil || parseFacts(string(outBad))["pb_dl_err"] != "checksum_mismatch" {
		t.Fatalf("expected tampered archive to fail with checksum_mismatch, err=%v out=%s", errBad, string(outBad))
	}
}

func TestInstallForeignPullsFromGitHubZeroSSHStdin(t *testing.T) {
	prevVer := engine.Version
	engine.Version = "v0.17.75"
	t.Cleanup(func() { engine.Version = prevVer })

	var panelReleaseHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panelReleaseHits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(agent.SetReleaseBaseURLForTest(srv.URL))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	beh := &execSSHBehavior{githubDownloadOK: true}
	sshPort, hostFP := startExecSSHServer(t, signer, "pw123", beh)

	p := newTestPanel(t)
	cfg := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("pw123")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != hostFP {
				return fmt.Errorf("mismatch")
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}
	j := &job{}
	rm, _, err := p.dialSSHRemote(context.Background(), j, "127.0.0.1", sshPort, cfg, GroupForeign, "")
	if err != nil {
		t.Fatalf("dialSSHRemote: %v", err)
	}
	defer rm.close()

	if err := p.install(j, rm, "amd64", GroupForeign); err != nil {
		t.Fatalf("install failed: %v\nlines: %v", err, j.view().Lines)
	}
	if got := beh.stdinBytes.Load(); got != 0 {
		t.Fatalf("expected 0 stdin bytes sent over SSH when GitHub pull succeeds, got %d", got)
	}
	if hits := panelReleaseHits.Load(); hits != 0 {
		t.Fatalf("expected panel not to download release itself when target pulled from GitHub, got %d hits", hits)
	}
	lines := strings.Join(j.view().Lines, "\n")
	if !strings.Contains(lines, "Downloaded & verified v0.17.75 from GitHub.") || strings.Contains(lines, "Copying PortBridge across") {
		t.Fatalf("unexpected job log lines:\n%s", lines)
	}
}

func TestSSHUploadStallAbortsPromptlyAndRetriesViaJump(t *testing.T) {
	agent.SetAllowLoopbackNetProxyForTest(true)
	t.Cleanup(func() { agent.SetAllowLoopbackNetProxyForTest(false) })

	prevVer := engine.Version
	engine.Version = "v0.17.75"
	t.Cleanup(func() { engine.Version = prevVer })

	prevStall := sshUploadStallTimeout
	sshUploadStallTimeout = 500 * time.Millisecond
	t.Cleanup(func() { sshUploadStallTimeout = prevStall })

	// Panel can fetch a 64 KB (> 16 KB chunk) release archive so bulk stall detection engages.
	const ver = "v0.17.75"
	const arch = "amd64"
	tarName := agent.ReleaseArchiveName(ver, arch)
	archive, sum := buildTestReleaseArchive(t, 96*1024)
	relSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + ver + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", sum, tarName)
		case "/download/" + ver + "/" + tarName:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(relSrv.Close)
	t.Cleanup(agent.SetReleaseBaseURLForTest(relSrv.URL))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Direct SSH server accepts handshake & small commands, reports GitHub unreachable,
	// and freezes bulk stdin on `tar -xzf -` (simulating Iran GFW port-22 bulk freeze).
	directBeh := &execSSHBehavior{
		githubDownloadOK: false,
		freezeBulkStdin:  true,
	}
	directPort, hostFP := startExecSSHServer(t, signer, "pw123", directBeh)

	// Healthy SSH server reached via the online Foreign Jump server (same host key!).
	jumpTargetBeh := &execSSHBehavior{
		githubDownloadOK: false,
		freezeBulkStdin:  false,
	}
	jumpTargetPort, _ := startExecSSHServer(t, signer, "pw123", jumpTargetBeh)

	p := newTestPanel(t)
	const jumpTok = "pba_jump_install"
	jumpTS, jumpFP := startPinnedMockAgent(t, jumpTok)
	jumpSrv := addTestServer(t, p, Server{
		ID:          "jump-de",
		Name:        "Germany-Jump",
		Group:       GroupForeign,
		Address:     "198.51.100.77",
		AgentURL:    jumpTS.URL,
		Fingerprint: jumpFP,
	}, jumpTok)
	p.fleet.refresh(jumpSrv)

	sshCfg := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("pw123")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != hostFP {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}

	j := &job{}
	rm, _, err := p.dialSSHRemote(context.Background(), j, "127.0.0.1", directPort, sshCfg, GroupForeign, "")
	if err != nil {
		t.Fatalf("dialSSHRemote direct: %v", err)
	}
	defer rm.close()

	// Point jumpDial to route through Germany-Jump to jumpTargetPort (simulating clean Foreign->Foreign path).
	rm.jumpDial = func() (*ssh.Client, net.Conn, string, error) {
		jconn, viaName, jerr := p.dialTargetJumpOnly(context.Background(), "127.0.0.1", jumpTargetPort, GroupForeign)
		if jerr != nil {
			return nil, nil, "", jerr
		}
		jclient, jerr := sshClientOverConn(jconn, fmt.Sprintf("127.0.0.1:%d", jumpTargetPort), sshCfg)
		if jerr != nil {
			return nil, nil, "", jerr
		}
		return jclient, jconn, viaName, nil
	}

	start := time.Now()
	if err := p.install(j, rm, arch, GroupForeign); err != nil {
		t.Fatalf("install with stall + jump retry failed: %v\nlines:\n%s", err, strings.Join(j.view().Lines, "\n"))
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("stall detection took too long (%s); expected < 5s", elapsed)
	}
	if jumpTargetBeh.stdinBytes.Load() < int64(len(archive)) {
		t.Fatalf("expected jump SSH server to receive full %d byte archive, got %d", len(archive), jumpTargetBeh.stdinBytes.Load())
	}
	lines := strings.Join(j.view().Lines, "\n")
	if !strings.Contains(lines, "Direct SSH transfer stalled") || !strings.Contains(lines, "Reconnected SSH via Germany-Jump") {
		t.Fatalf("expected stall + Germany-Jump recovery in job log, got:\n%s", lines)
	}
	rm.close()
	jumpTS.CloseClientConnections()
}

func TestIsPublicJumpTargetAndForeignAutoJumpFirst(t *testing.T) {
	for _, pub := range []string{"178.162.245.229", "203.0.113.99", "2001:4860:4860::8888", "node1.example.com"} {
		if !isPublicJumpTarget(pub) {
			t.Fatalf("expected %q to be treated as a public jump target", pub)
		}
	}
	for _, nonPub := range []string{"", "localhost", "127.0.0.1", "::1", "10.0.0.5", "192.168.1.20", "172.20.0.1", "100.64.10.2"} {
		if isPublicJumpTarget(nonPub) {
			t.Fatalf("expected %q NOT to be treated as a public jump target", nonPub)
		}
	}
}

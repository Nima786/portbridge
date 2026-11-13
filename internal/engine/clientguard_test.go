package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientGuardLimitsAndCIDRBlock(t *testing.T) {
	if _, err := CheckBlockedIPOrCIDR("0.0.0.0/0"); err == nil {
		t.Fatal("expected /0 CIDR to be rejected")
	}
	if _, err := CheckBlockedIPOrCIDR("10.0.0.0/4"); err == nil {
		t.Fatal("expected overly broad /4 CIDR to be rejected")
	}
	list, err := ParseBlockedIPList("198.51.100.7, 203.0.113.99/24, 2001:db8:abcd::1")
	if err != nil {
		t.Fatalf("ParseBlockedIPList: %v", err)
	}
	if len(list) != 3 || list[1] != "203.0.113.0/24" {
		t.Fatalf("unexpected normalized list: %v", list)
	}

	g := newClientGuard(&Config{
		MaxConnPerIP: 2,
		MaxRatePerIP: 3,
		BlockedIPs:   list,
	})
	tcpAddr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatalf("ResolveTCPAddr(%s): %v", s, err)
		}
		return a
	}

	// Exact blocked IPv4 and CIDR-covered IPv4 and blocked IPv6 must be rejected.
	for _, blocked := range []string{"198.51.100.7:54321", "203.0.113.42:12345", "[2001:db8:abcd::1]:40000"} {
		if _, _, _, reason, ok := g.acquire(tcpAddr(blocked), nil); ok || reason != "blocked_ip" {
			t.Fatalf("expected %s to be rejected by blocklist (ok=%v, reason=%q)", blocked, ok, reason)
		}
	}

	// Clean client IP allowed up to max_per_ip = 2 concurrent sessions.
	var closed1, closed2 atomic.Bool
	ip1, ce1, h1, _, ok1 := g.acquire(tcpAddr("192.0.2.10:50001"), func() { closed1.Store(true) })
	if !ok1 || ce1 == nil {
		t.Fatal("expected first connection from 192.0.2.10 to succeed")
	}
	atomic.AddInt64(&ce1.bytesUp, 1024)
	atomic.AddInt64(&ce1.bytesDown, 2048)

	ip2, _, h2, _, ok2 := g.acquire(tcpAddr("192.0.2.10:50002"), func() { closed2.Store(true) })
	if !ok2 {
		t.Fatal("expected second connection from 192.0.2.10 to succeed")
	}

	// 3rd concurrent connection exceeds max_per_ip = 2.
	if _, _, _, reason, ok3 := g.acquire(tcpAddr("192.0.2.10:50003"), nil); ok3 || reason != "max_per_ip" {
		t.Fatalf("expected 3rd concurrent connection from 192.0.2.10 to be rejected by max_per_ip=2 (ok=%v, reason=%q)", ok3, reason)
	}
	g.release(ip2, h2)

	// Drain remaining initial burst tokens (burstForRate(3) == 20, 2 already consumed) and verify rate_per_ip rejection.
	rateRejected := false
	for i := 0; i < 25; i++ {
		ipN, _, hN, reason, okN := g.acquire(tcpAddr(fmt.Sprintf("192.0.2.10:%d", 51000+i)), nil)
		if !okN {
			if reason == "rate_per_ip" {
				rateRejected = true
			}
			break
		}
		g.release(ipN, hN)
	}
	if !rateRejected {
		t.Fatal("expected rapid connection flood from 192.0.2.10 to be rejected by rate_per_ip")
	}

	// Live rule update adding 192.0.2.0/24 must sever the remaining open session immediately.
	killed := g.updateRules(2, 3, []string{"192.0.2.0/24"})
	if killed != 1 || !closed1.Load() {
		t.Fatalf("expected updateRules to terminate 1 active session (killed=%d, closed1=%v)", killed, closed1.Load())
	}
	g.release(ip1, h1)

	_, drops, snaps := g.snapshot(10)
	if drops < 5 {
		t.Fatalf("expected total rejected drops >= 5, got %d", drops)
	}
	var found *ClientSnapshot
	for i := range snaps {
		if snaps[i].IP == "192.0.2.10" {
			found = &snaps[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected 192.0.2.10 in snapshot, got %+v", snaps)
	}
	if !found.Blocked || found.BytesUp != 1024 || found.BytesDown != 2048 || found.Rejected < 2 {
		t.Fatalf("unexpected client snapshot: %+v", *found)
	}
}

func TestEdgeLiveReloadGuardTerminatesBlockedClient(t *testing.T) {
	shortDir, err := os.MkdirTemp("", "pbg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })

	svc := startService(t)
	defer svc.stop()

	secretPath := filepath.Join(shortDir, "secret")
	if err := os.WriteFile(secretPath, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	tunnelAddr := freeAddr(t)
	userAddr := freeAddr(t)
	statusPath := filepath.Join(shortDir, "t1.json")
	edgeConfPath := filepath.Join(shortDir, "t1.conf")

	writeEdgeConf := func(extra string) {
		body := fmt.Sprintf(`name = t1
mode = direct
role = edge
tunnel_addr = %s
user_listen = %s
transport = plain
mux = on
mux_links = 1
max_conn = 200
secret_file = %s
status_file = %s
%s`, tunnelAddr, userAddr, secretPath, statusPath, extra)
		if err := os.WriteFile(edgeConfPath, []byte(body), 0o600); err != nil {
			t.Fatalf("write edge conf: %v", err)
		}
	}
	writeEdgeConf("max_per_ip = 10\nrate_per_ip = 50\n")

	originCfg := DefaultConfig()
	originCfg.Name = "t1"
	originCfg.Mode = ModeDirect
	originCfg.Role = RoleOrigin
	originCfg.TunnelAddr = tunnelAddr
	originCfg.InboundAddr = svc.addr
	originCfg.Transport = TransportPlain
	originCfg.Mux = true
	originCfg.MuxLinks = 1
	originCfg.MaxConn = 200
	originCfg.Drain = time.Second
	originCfg.SecretFile = secretPath
	originCfg.StatusFile = ""
	if err := originCfg.Validate(); err != nil {
		t.Fatalf("origin validate: %v", err)
	}
	if err := originCfg.LoadSecret(); err != nil {
		t.Fatalf("origin secret: %v", err)
	}

	edgeCfg, err := LoadConfig(edgeConfPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	edgeCfg.Drain = time.Second
	if err := edgeCfg.Validate(); err != nil {
		t.Fatalf("edge validate: %v", err)
	}
	if err := edgeCfg.LoadSecret(); err != nil {
		t.Fatalf("edge secret: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { _ = runOrigin(ctx, originCfg, newStatus(originCfg)); done <- struct{}{} }()
	go func() { _ = runEdge(ctx, edgeCfg, newStatus(edgeCfg)); done <- struct{}{} }()
	defer func() {
		cancel()
		<-done
		<-done
	}()

	// Open a real user connection through the Edge into the Origin echo service.
	var userConn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", userAddr, 300*time.Millisecond)
		if err == nil {
			if _, werr := c.Write([]byte("hello")); werr == nil {
				buf := make([]byte, 5)
				_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				if _, rerr := c.Read(buf); rerr == nil && string(buf) == "HELLO" {
					_ = c.SetReadDeadline(time.Time{})
					userConn = c
					break
				}
			}
			_ = c.Close()
		}
		time.Sleep(60 * time.Millisecond)
	}
	if userConn == nil {
		t.Fatal("could not establish initial user session through tunnel")
	}
	defer userConn.Close()

	// Update edge config to block 127.0.0.1 and hot-reload via Unix control socket.
	writeEdgeConf("max_per_ip = 10\nrate_per_ip = 50\nblocked_ips = 127.0.0.1\n")
	if err := ReloadGuardControl(edgeCfg.ControlSocketPath()); err != nil {
		t.Fatalf("ReloadGuardControl(%s): %v", edgeCfg.ControlSocketPath(), err)
	}

	// Active connection from 127.0.0.1 must be terminated immediately without restarting the tunnel.
	_ = userConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := userConn.Read(buf); err == nil {
		t.Fatal("expected active session from newly blocked 127.0.0.1 to be closed immediately")
	}

	// Subsequent connection from 127.0.0.1 must be dropped by guard and counted in abuse_drops.
	c2, err := net.DialTimeout("tcp", userAddr, 500*time.Millisecond)
	if err == nil {
		_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c2.Write([]byte("hi"))
		if n, rerr := c2.Read(buf); rerr == nil && n > 0 {
			_ = c2.Close()
			t.Fatalf("expected blocked client connection to fail, but got %q", string(buf[:n]))
		}
		_ = c2.Close()
	}

	// Trigger status snapshot refresh and verify statusFile has abuse_drops >= 1 and 127.0.0.1 marked blocked.
	_ = ReloadGuardControl(edgeCfg.ControlSocketPath())
	rawStatus, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	var sf statusFile
	if err := json.Unmarshal(rawStatus, &sf); err != nil {
		t.Fatalf("unmarshal status file: %v", err)
	}
	if sf.AbuseDrops < 1 {
		t.Fatalf("expected abuse_drops >= 1 in status file, got %d (%s)", sf.AbuseDrops, string(rawStatus))
	}
	foundBlocked := false
	for _, cl := range sf.TopClients {
		if cl.IP == "127.0.0.1" && cl.Blocked {
			foundBlocked = true
			break
		}
	}
	if !foundBlocked {
		t.Fatalf("expected 127.0.0.1 marked blocked in top_clients: %+v", sf.TopClients)
	}
}

const fakeAbuseIptables = `#!/usr/bin/env bash
R="$FAKE_STATE/ipt4"
[ "$(basename "$0")" = ip6tables ] && R="$FAKE_STATE/ipt6"
mkdir -p "$R"
touch "$R/INPUT" "$R/OUTPUT" "$R/FORWARD"
if [ "$1" = "-w" ]; then shift 2; fi
cmd=$1; shift
chain=$1; [ $# -gt 0 ] && shift
quote() { sed -E 's/--comment ([^ ]+)/--comment "\1"/'; }
case "$cmd" in
  -N) touch "$R/$chain" ;;
  -F) : > "$R/$chain" ;;
  -X) rm -f "$R/$chain" ;;
  -S)
    if [ -n "$chain" ]; then
      [ -f "$R/$chain" ] || exit 1
      cat "$R/$chain"
    else
      cat "$R"/* 2>/dev/null
    fi
    ;;
  -A)
    echo "-A $chain $*" | quote >> "$R/$chain"
    ;;
  -I)
    case "$1" in [0-9]*) shift ;; esac
    tmp="$R/$chain.new"
    echo "-A $chain $*" | quote > "$tmp"
    cat "$R/$chain" >> "$tmp" 2>/dev/null || true
    mv "$tmp" "$R/$chain"
    ;;
  -D)
    want=$(echo "-A $chain $*" | quote)
    grep -vxF -- "$want" "$R/$chain" > "$R/$chain.new" 2>/dev/null || true
    mv "$R/$chain.new" "$R/$chain"
    ;;
esac
exit 0
`

const fakeAbuseIP = `#!/usr/bin/env bash
case "$*" in
  "-4 route show scope link")
    echo "172.31.1.1 dev eth0 scope link"
    ;;
  "-4 route show default")
    echo "default via 172.31.1.1 dev eth0"
    ;;
esac
exit 0
`

func TestFirewallHelperAbuseShield(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux firewall helper test")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}

	base := t.TempDir()
	confDir := filepath.Join(base, "tunnels")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	binDir := t.TempDir()
	for name, script := range map[string]string{
		"iptables":  fakeAbuseIptables,
		"ip6tables": fakeAbuseIptables,
		"ip":        fakeAbuseIP,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Peer tunnel config with a private peer_ip to verify peer exemption.
	tunConf := "name = main\nmode = direct\nrole = origin\ntunnel_addr = 0.0.0.0:2053\ninbound_addr = 127.0.0.1:8443\npeer_ip = 10.99.92.205\ntransport = plain\n"
	if err := os.WriteFile(filepath.Join(confDir, "main.conf"), []byte(tunConf), 0o600); err != nil {
		t.Fatal(err)
	}

	runHelper := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(bash, append([]string{"../../scripts/portbridge-firewall"}, args...)...)
		cmd.Env = append(os.Environ(),
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FAKE_STATE="+stateDir,
			"PORTBRIDGE_CONF_DIR="+confDir,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("portbridge-firewall %v failed: %v\n%s", args, err, string(out))
		}
		return string(out)
	}

	outOn := runHelper("abuse-on", "torrent")
	if !strings.Contains(outOn, "BitTorrent blocked") {
		t.Fatalf("expected BitTorrent blocked in output, got: %s", outOn)
	}

	chainBytes, err := os.ReadFile(filepath.Join(stateDir, "ipt4", "PORTBRIDGE_ABUSE"))
	if err != nil {
		t.Fatalf("read PORTBRIDGE_ABUSE chain: %v", err)
	}
	chain := string(chainBytes)
	metaIdx := strings.Index(chain, "-d 169.254.169.254/32 -j RETURN")
	linkLocalDropIdx := strings.Index(chain, "-d 169.254.0.0/16 -j DROP")
	peerReturnIdx := strings.Index(chain, "-d 10.99.92.205 -j RETURN")
	rfc10DropIdx := strings.Index(chain, "-d 10.0.0.0/8 -j DROP")
	if metaIdx < 0 || linkLocalDropIdx < 0 || metaIdx > linkLocalDropIdx {
		t.Fatalf("cloud metadata must be exempted before 169.254.0.0/16 drop:\n%s", chain)
	}
	if peerReturnIdx < 0 || rfc10DropIdx < 0 || peerReturnIdx > rfc10DropIdx {
		t.Fatalf("configured peer_ip must be exempted before 10.0.0.0/8 drop:\n%s", chain)
	}
	if !strings.Contains(chain, "--dport 6881:6889 -j DROP") || !strings.Contains(chain, "--dport 445 -j DROP") {
		t.Fatalf("expected BitTorrent and SMB ports dropped:\n%s", chain)
	}

	stOut := runHelper("abuse-status")
	if !strings.HasPrefix(strings.TrimSpace(stOut), "active") {
		t.Fatalf("expected active abuse-status, got: %s", stOut)
	}

	// Switch to notorrent mode and verify BitTorrent rules are omitted while netscan stays active.
	runHelper("abuse-on", "notorrent")
	chainNoTorBytes, err := os.ReadFile(filepath.Join(stateDir, "ipt4", "PORTBRIDGE_ABUSE"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(chainNoTorBytes), "6881:6889") {
		t.Fatalf("expected BitTorrent rules removed in notorrent mode:\n%s", string(chainNoTorBytes))
	}
	if !strings.Contains(string(chainNoTorBytes), "-d 100.64.0.0/10 -j DROP") {
		t.Fatalf("expected CGNAT netscan drop preserved in notorrent mode:\n%s", string(chainNoTorBytes))
	}

	// Turn shield off and verify OUTPUT jump and chain are removed.
	runHelper("abuse-off")
	stOff := runHelper("abuse-status")
	if strings.TrimSpace(stOff) != "off" {
		t.Fatalf("expected off abuse-status after abuse-off, got: %s", stOff)
	}
	outChainBytes, _ := os.ReadFile(filepath.Join(stateDir, "ipt4", "OUTPUT"))
	if strings.Contains(string(outChainBytes), "PORTBRIDGE_ABUSE") {
		t.Fatalf("expected PORTBRIDGE_ABUSE jump removed from OUTPUT:\n%s", string(outChainBytes))
	}
}

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the real helper script against stand-ins for ip, iptables,
// modprobe and ping that only write to a temporary directory, so no network
// setting of the machine running the tests is ever touched. They are skipped
// where there is no bash.

const fakeIP = `#!/usr/bin/env bash
S="$FAKE_STATE"
echo "ip $*" >> "$S/log"
case "$1 $2" in
  "-4 -o")   # ip -4 -o addr show
    cat "$S/addrs" 2>/dev/null; exit 0 ;;
  "-4 addr") # ip -4 addr show dev NAME
    grep -F " $5 " "$S/addrs" 2>/dev/null; exit 0 ;;
  "-o link") # ip -o link show: one line per interface, as the real one prints them
    for f in "$S"/if_*; do [ -e "$f" ] || continue; echo "9: ${f##*/if_}@NONE: <POINTOPOINT,NOARP> mtu 1300"; done; exit 0 ;;
  "link show")
    [ -e "$S/if_$3" ] || exit 1
    echo "$3: <POINTOPOINT,NOARP,$(cat "$S/if_$3")> mtu 1300"; exit 0 ;;
  "tunnel add")
    echo "$*" > "$S/tunnel_$3"; echo DOWN > "$S/if_$3"; exit 0 ;;
  "addr add")
    echo "9: $5 inet $3 scope global" >> "$S/addrs"; exit 0 ;;
  "link set")
    echo UP > "$S/if_$3"; exit 0 ;;
  "link del")
    rm -f "$S/if_$3" "$S/tunnel_$3"
    grep -vF " $3 " "$S/addrs" > "$S/addrs.new" 2>/dev/null; mv "$S/addrs.new" "$S/addrs" 2>/dev/null; exit 0 ;;
esac
exit 0
`

const fakeNoop = `#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "$FAKE_STATE/log"
[ "$(basename "$0")" = iptables ] && [ "$1" = "-C" ] && exit 1
exit 0
`

// fakeIptables remembers its rules and prints them back the way the real tool
// does, with the comment in double quotes. That detail matters: a rule can only
// be deleted by giving its comment without the quotes.
const fakeIptables = `#!/usr/bin/env bash
R="$FAKE_STATE/rules"; [ "$(basename "$0")" = ip6tables ] && R="$FAKE_STATE/rules6"; touch "$R"
echo "iptables $*" >> "$FAKE_STATE/log"
cmd=$1; shift
shift # the chain
quote() { sed -E 's/--comment ([^ ]+)/--comment "\1"/'; }
case "$cmd" in
  -S) cat "$R" ;;
  -I) [ "$1" = 1 ] && shift; echo "-A INPUT $*" | quote >> "$R" ;;
  -C|-D)
    want=$(echo "-A INPUT $*" | quote)
    grep -qxF -- "$want" "$R" || exit 1
    if [ "$cmd" = -D ]; then grep -vxF -- "$want" "$R" > "$R.new"; mv "$R.new" "$R"; fi ;;
esac
exit 0
`

type greRig struct {
	t     *testing.T
	bash  string
	state string
	conf  string
	env   []string
}

func newGRERig(t *testing.T) *greRig {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum on this machine")
	}
	r := &greRig{t: t, bash: bash, state: t.TempDir(), conf: t.TempDir()}
	bin := t.TempDir()
	for name, body := range map[string]string{"ip": fakeIP, "iptables": fakeIptables, "ip6tables": fakeIptables, "modprobe": fakeNoop, "ping": fakeNoop} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// This server holds 87.236.208.145 on its network card.
	r.setAddrs("2: eth0 inet 87.236.208.145/24 scope global eth0\n")
	r.env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_STATE="+r.state,
		"PORTBRIDGE_CONF_DIR="+r.conf,
	)
	return r
}

func (r *greRig) setAddrs(s string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.state, "addrs"), []byte(s), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *greRig) tunnel(name, gre string) {
	r.t.Helper()
	text := "name = " + name + "\nmode = direct\nrole = edge\ntunnel_addr = 10.99.92.205:9443\nuser_listen = 127.0.0.1:18080\n" +
		"peer_ip = 10.99.92.205\nfirewall = off\ntransport = plain\n"
	if gre != "" {
		text += "gre = " + gre + "\ngre_local = 87.236.208.145\ngre_remote = 79.137.202.176\n"
	}
	if err := os.WriteFile(filepath.Join(r.conf, name+".conf"), []byte(text), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *greRig) run(args ...string) (string, int) {
	r.t.Helper()
	helper, _ := filepath.Abs("scripts/portbridge-firewall")
	cmd := exec.Command(r.bash, append([]string{helper}, args...)...)
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatal(err)
	}
	return string(out), code
}

func (r *greRig) linkExists() bool {
	_, err := os.Stat(filepath.Join(r.state, "if_pbgc848d733"))
	return err == nil
}

// rules is what the fake firewall holds that belongs to a GRE link.
func (r *greRig) rules() string {
	b, _ := os.ReadFile(filepath.Join(r.state, "rules"))
	var keep []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "portbridge-gre") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func (r *greRig) tunnelsMade() int {
	b, _ := os.ReadFile(filepath.Join(r.state, "log"))
	return strings.Count(string(b), "ip tunnel add")
}

func TestGREHelperMakesTheLinkOnceAndKeepsItForEveryTunnel(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.tunnel("one", "on")
	r.tunnel("two", "on")

	out, code := r.run("apply", "one")
	if code != 0 || !strings.Contains(out, "pbgc848d733 is up") {
		t.Fatalf("apply failed (%d): %s", code, out)
	}
	if !r.linkExists() {
		t.Fatalf("the link was not made")
	}
	made, _ := os.ReadFile(filepath.Join(r.state, "tunnel_pbgc848d733"))
	if !strings.Contains(string(made), "local 87.236.208.145 remote 79.137.202.176") {
		t.Fatalf("the link joins the wrong addresses: %s", made)
	}
	addrs, _ := os.ReadFile(filepath.Join(r.state, "addrs"))
	if !strings.Contains(string(addrs), "10.99.92.206/30") {
		t.Fatalf("this server did not get its private address: %s", addrs)
	}
	if state, _ := os.ReadFile(filepath.Join(r.state, "if_pbgc848d733")); !strings.Contains(string(state), "UP") {
		t.Fatalf("the link was not brought up")
	}

	// Running it again, as every start of the service does, changes nothing.
	if _, code := r.run("apply", "one"); code != 0 {
		t.Fatalf("a second apply failed")
	}
	if _, code := r.run("apply", "two"); code != 0 {
		t.Fatalf("a second tunnel over the same link failed")
	}
	if n := r.tunnelsMade(); n != 1 {
		t.Fatalf("the link was made %d times, want once", n)
	}
	// The other server's GRE packets are let in, once, however often it is applied.
	if got := r.rules(); strings.Count(got, "\n") != 0 || !strings.Contains(got, `-s 79.137.202.176 -p gre -m comment --comment "portbridge-gre:pbgc848d733" -j ACCEPT`) {
		t.Fatalf("expected exactly one rule letting the other server's GRE in, got:\n%s", got)
	}

	// Deleting one tunnel leaves the link for the other; deleting the last takes it.
	if out, code := r.run("remove", "one"); code != 0 {
		t.Fatalf("remove one: %d %s", code, out)
	}
	if !r.linkExists() {
		t.Fatalf("the link went when one of two tunnels was removed")
	}
	if err := os.Remove(filepath.Join(r.conf, "one.conf")); err != nil {
		t.Fatal(err)
	}
	if out, code := r.run("remove", "two"); code != 0 {
		t.Fatalf("remove two: %d %s", code, out)
	}
	if r.linkExists() {
		t.Fatalf("the link stayed after the last tunnel using it was removed")
	}
	if got := r.rules(); got != "" {
		t.Fatalf("the firewall rule for the link was left behind:\n%s", got)
	}
}

func TestGREHelperLeavesAPlainTunnelAlone(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.tunnel("plain", "")
	if out, code := r.run("apply", "plain"); code != 0 {
		t.Fatalf("apply: %d %s", code, out)
	}
	if r.tunnelsMade() != 0 || r.linkExists() {
		t.Fatalf("a tunnel without GRE got a link")
	}
}

func TestGREHelperDropsTheLinkWhenGREIsTurnedOff(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.tunnel("t", "on")
	if _, code := r.run("apply", "t"); code != 0 || !r.linkExists() {
		t.Fatalf("no link to begin with")
	}
	r.tunnel("t", "off")
	if _, code := r.run("apply", "t"); code != 0 {
		t.Fatalf("apply after turning it off failed")
	}
	if r.linkExists() {
		t.Fatalf("the link stayed after GRE was turned off")
	}
}

// A server that only sees its public address through address translation cannot
// receive GRE on it, and is told so instead of being left with a dead link.
func TestGREHelperRefusesAServerBehindTranslation(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.setAddrs("2: eth0 inet 10.0.0.5/24 scope global eth0\n")
	r.tunnel("t", "on")
	out, code := r.run("apply", "t")
	if code == 0 || !strings.Contains(out, "address translation") {
		t.Fatalf("expected a refusal that names address translation, got (%d): %s", code, out)
	}
	if r.linkExists() {
		t.Fatalf("a link was made on an address the server does not hold")
	}
}

func TestGREHelperRefusesAnAddressAnotherNetworkUses(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.setAddrs("2: eth0 inet 87.236.208.145/24 scope global eth0\n3: docker0 inet 10.99.92.206/24 scope global docker0\n")
	r.tunnel("t", "on")
	out, code := r.run("apply", "t")
	if code == 0 || !strings.Contains(out, "already used by another network card") {
		t.Fatalf("expected a refusal about the clash, got (%d): %s", code, out)
	}
}

func TestGREHelperTestsTheOtherEnd(t *testing.T) {
	if _, err := os.Stat("scripts/portbridge-firewall"); err != nil {
		t.Skip("helper script not available")
	}
	r := newGRERig(t)
	r.tunnel("t", "on")
	if out, code := r.run("gre-test", "t"); code == 0 {
		t.Fatalf("reported a link that is not there: %s", out)
	}
	if _, code := r.run("apply", "t"); code != 0 {
		t.Fatal("apply failed")
	}
	if out, code := r.run("gre-test", "t"); code != 0 || !strings.Contains(out, "answers") {
		t.Fatalf("gre-test: %d %s", code, out)
	}
}

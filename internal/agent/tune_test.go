package agent

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// settings reads "key = value" lines out of a settings text.
func settings(text string) map[string]string {
	re := regexp.MustCompile(`(?m)^([a-z0-9_.]+)\s*=\s*(.+?)\s*$`)
	m := map[string]string{}
	for _, f := range re.FindAllStringSubmatch(text, -1) {
		m[f[1]] = f[2]
	}
	return m
}

// There are two copies of the tuning: the script, and the built-in one used when
// only the program was installed on a server. They must not drift apart.
func TestTheBuiltInTuningMatchesTheScript(t *testing.T) {
	b, err := os.ReadFile("../../scripts/portbridge-tune")
	if err != nil {
		t.Fatal(err)
	}
	script, builtin := settings(string(b)), settings(builtinSysctlConf)
	// Chosen when the script runs, from what the kernel offers.
	delete(script, "net.ipv4.tcp_congestion_control")
	delete(script, "net.core.default_qdisc")
	delete(builtin, "net.ipv4.tcp_congestion_control")
	delete(builtin, "net.core.default_qdisc")
	// Only in the script as a variable, or only where the module is loaded.
	delete(script, "net.netfilter.nf_conntrack_max")

	for k, v := range script {
		if bv, ok := builtin[k]; !ok || bv != v {
			t.Errorf("%s: script has %q, built-in has %q", k, v, bv)
		}
	}
	for k := range builtin {
		if _, ok := script[k]; !ok && k != "net.ipv4.ip_local_port_range" {
			t.Errorf("%s is in the built-in tuning but not in the script", k)
		}
	}
}

func TestTheTuningRaisesTheBufferLimitsThatUDPLinksDependOn(t *testing.T) {
	s := settings(builtinSysctlConf)
	for _, k := range []string{"net.core.rmem_max", "net.core.wmem_max"} {
		if s[k] != "33554432" {
			t.Errorf("%s = %q, want 32 MB so UDP and raw links can keep their 4-8 MB buffers", k, s[k])
		}
	}
	if s["net.ipv4.tcp_mtu_probing"] != "1" {
		t.Errorf("path MTU probing is not on")
	}
	if strings.Contains(builtinSysctlConf, "nf_conntrack") {
		t.Errorf("the fixed built-in text must not name the connection table: it exists only where the module is loaded")
	}
}

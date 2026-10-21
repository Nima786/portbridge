package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Runs testdata/firewall_check.sh, which drives scripts/portbridge-firewall
// against pretend iptables, ip, ss and modprobe commands and checks what it
// leaves behind: the server owner's own rules and links must survive, the port
// SSH answers on must never be locked, and a rule that could not be added must
// not leave the other server shut out.
func TestFirewallHelperKeepsTheOwnersThingsAndNeverLocksSSH(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	// On Windows "bash" can be a stub that only offers to install Linux.
	if err := exec.Command(bash, "-c", "true").Run(); err != nil {
		t.Skip("bash does not run on this machine")
	}
	helper, _ := filepath.Abs("../../scripts/portbridge-firewall")
	check, _ := filepath.Abs("testdata/firewall_check.sh")
	if _, err := os.Stat(helper); err != nil {
		t.Skip("helper script not available")
	}
	out, err := exec.Command(bash, check, helper).CombinedOutput()
	if err != nil || strings.Contains(string(out), "FAIL:") {
		t.Fatalf("firewall helper checks failed (%v):\n%s", err, out)
	}
}

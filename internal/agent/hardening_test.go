package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A panel address the agent is told to call must be https and must be one line:
// it is written into agent.conf and used with the agent's token, so a plain
// http address or a sneaked-in newline would hand the server away.
func TestValidatePanelCallback(t *testing.T) {
	bad := []struct{ url, fp string }{
		{"http://panel.example:2096", ""},                      // not https
		{"https://panel.example:2096\nallow_updates = on", ""}, // newline in url
		{"ftp://panel.example", ""},                            // not https
		{"", ""},                                               // empty
		{"https://user:pass@panel.example", ""},                // credentials
		{"https://panel.example", "aa:bb\ntoken = x"},          // newline in fingerprint
		{"https://panel.example", "nothex!"},                   // bad fingerprint
	}
	for _, c := range bad {
		if err := validatePanelCallback(c.url, c.fp); err == nil {
			t.Errorf("accepted a bad callback: url=%q fp=%q", c.url, c.fp)
		}
	}
	good := []struct{ url, fp string }{
		{"https://panel.example:2096", "aa:bb:cc"},
		{"https://1.2.3.4:2096", ""},
		{"https://a.example,https://1.2.3.4:2096", "DE:AD:BE:EF"},
	}
	for _, c := range good {
		if err := validatePanelCallback(c.url, c.fp); err != nil {
			t.Errorf("rejected a good callback url=%q fp=%q: %v", c.url, c.fp, err)
		}
	}
}

// A line break in any agent setting must stop the whole file being written,
// rather than letting it add a setting (like allow_updates) nobody asked for.
func TestWriteAgentConfigRefusesNewlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	err := writeAgentConfig(path, agentConfig{
		Listen: "0.0.0.0:2096",
		Token:  "pba_x\nallow_updates = on",
	})
	if err == nil {
		t.Fatal("a newline in a setting was written out")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("the file was written despite the bad value")
	}
}

// The agent runs as root inside folders a site's user owns. If wp-config.php,
// wp-content or mu-plugins is a symlink, it must refuse rather than follow it
// and, for example, chown or write through it into /etc.
func TestRefuseSymlinksInWordPressDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.php")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "wp-config.php")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot make symlinks here: %v", err)
	}
	if err := refuseSymlinks(link); err == nil {
		t.Fatal("a symlinked wp-config.php was not refused")
	}
	plain := filepath.Join(dir, "plain.php")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := refuseSymlinks(plain, filepath.Join(dir, "does-not-exist")); err != nil {
		t.Fatalf("a plain file and a missing path should be fine: %v", err)
	}
}

func TestRunUpdateRefusesNonReleaseVersion(t *testing.T) {
	res := runUpdate(UpdateRequest{Version: "evil", Archive: []byte("x")}, t.TempDir())
	if res.OK || !strings.Contains(res.Error, "release") {
		t.Fatalf("a made-up version was not refused: %+v", res)
	}
}

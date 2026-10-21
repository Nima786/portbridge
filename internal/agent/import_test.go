package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
)

const goodImportConf = `name = shop
mode = direct
role = origin
tunnel_addr = 127.0.0.1:18443
inbound_addr = 127.0.0.1:8080
peer_ip = 1.2.3.4
firewall = off
transport = plain
mux = off
pool_size = 4
secret_file = /somewhere/else.secret
`

const importSecret = "0123456789abcdef0123456789abcdef"

// The settings text comes from outside. A setting that names a file, such as
// status_file, must not survive: the engine would write wherever it says.
func TestImportTunnelDropsStatusFileAndPinsPaths(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(t.TempDir(), "elsewhere.json")
	snap := TunnelSnapshot{
		Name:   "shop",
		Conf:   goodImportConf + "status_file = " + filepath.ToSlash(evil) + "\n",
		Secret: importSecret,
	}
	if _, err := ImportTunnel(snap, dir, true, ""); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(dir, "shop.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "status_file") {
		t.Fatalf("status_file survived the import:\n%s", text)
	}
	if !strings.Contains(string(text), filepath.ToSlash(filepath.Join(dir, "shop.secret"))) {
		t.Fatalf("secret_file was not pinned to the tunnel's own place:\n%s", text)
	}
}

// If the restored settings are unusable, the tunnel that was there must be put
// back exactly as it was, not left broken.
func TestImportTunnelPutsTheOldTunnelBackWhenTheNewOneIsUnusable(t *testing.T) {
	dir := t.TempDir()
	good := TunnelSnapshot{Name: "shop", Conf: goodImportConf, Secret: importSecret}
	if _, err := ImportTunnel(good, dir, true, ""); err != nil {
		t.Fatal(err)
	}
	confFile := filepath.Join(dir, "shop.conf")
	secretFile := filepath.Join(dir, "shop.secret")
	beforeConf, _ := os.ReadFile(confFile)
	beforeSecret, _ := os.ReadFile(secretFile)

	bad := TunnelSnapshot{Name: "shop", Conf: goodImportConf + "this_is_not_a_setting = 1\n", Secret: "another-secret-another-secret-ok"}
	if _, err := ImportTunnel(bad, dir, true, ""); err == nil {
		t.Fatal("an unusable config was accepted")
	}
	afterConf, _ := os.ReadFile(confFile)
	afterSecret, _ := os.ReadFile(secretFile)
	if string(afterConf) != string(beforeConf) || string(afterSecret) != string(beforeSecret) {
		t.Fatalf("the working tunnel was not put back:\nconf before:\n%s\nafter:\n%s\nsecret before %q after %q",
			beforeConf, afterConf, beforeSecret, afterSecret)
	}
	if _, err := engine.LoadConfig(confFile); err != nil {
		t.Fatalf("the restored config does not load: %v", err)
	}
}

// A new tunnel that cannot be restored leaves nothing behind.
func TestImportTunnelLeavesNothingBehindWhenANewTunnelIsUnusable(t *testing.T) {
	dir := t.TempDir()
	bad := TunnelSnapshot{Name: "fresh", Conf: goodImportConf + "this_is_not_a_setting = 1\n", Secret: importSecret}
	if _, err := ImportTunnel(bad, dir, false, ""); err == nil {
		t.Fatal("an unusable config was accepted")
	}
	for _, ext := range []string{".conf", ".secret", ".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(dir, "fresh"+ext)); err == nil {
			t.Errorf("fresh%s was left behind", ext)
		}
	}
}

// A plain tunnel set up or removed on a server must not touch the web server:
// it never set anything up there.
func TestPlainTunnelDoesNotTouchTheWebServer(t *testing.T) {
	tmpRoot := t.TempDir()
	hostsFile := filepath.Join(tmpRoot, "hosts")
	// Another tunnel's Website Bridge entry, which must survive.
	hosts := "127.0.0.1 localhost\n127.0.0.1 other.example.com # portbridge-website-loopback:bridge1\n"
	if err := os.WriteFile(hostsFile, []byte(hosts), 0o644); err != nil {
		t.Fatal(err)
	}
	lsws := filepath.Join(tmpRoot, "usr", "local", "lsws", "conf")
	if err := os.MkdirAll(lsws, 0o755); err != nil {
		t.Fatal(err)
	}
	xml := "<httpServerConfig>\n  <useIpInProxyHeader>2</useIpInProxyHeader>\n  <proxyProtocol>127.0.0.1</proxyProtocol>\n</httpServerConfig>\n"
	xmlPath := filepath.Join(lsws, "httpd_config.xml")
	if err := os.WriteFile(xmlPath, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	wpBridgeRootOverride, wpBridgeHostsOverride = tmpRoot, hostsFile
	defer func() { wpBridgeRootOverride, wpBridgeHostsOverride = "", "" }()

	plain := &engine.Config{Name: "plain1", Role: engine.RoleOrigin}
	if notes := syncWebsiteBridgeOrigin(plain, nil, tmpRoot); len(notes) != 0 {
		t.Fatalf("notes for a plain tunnel: %v", notes)
	}
	cleanupWebsiteBridgeOrigin("plain1", plain, tmpRoot)

	gotHosts, _ := os.ReadFile(hostsFile)
	gotXML, _ := os.ReadFile(xmlPath)
	if string(gotHosts) != hosts {
		t.Errorf("/etc/hosts was changed for a plain tunnel:\n%s", gotHosts)
	}
	if string(gotXML) != xml {
		t.Errorf("the web server's settings were changed for a plain tunnel:\n%s", gotXML)
	}
}

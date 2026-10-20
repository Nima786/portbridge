package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
)

func TestWebsiteBridgeOriginLifecycle(t *testing.T) {
	tmpRoot := t.TempDir()
	hostsFile := filepath.Join(tmpRoot, "hosts")
	origHosts := "127.0.0.1 localhost\n::1 localhost\n"
	if err := os.WriteFile(hostsFile, []byte(origHosts), 0o644); err != nil {
		t.Fatal(err)
	}

	wpDir := filepath.Join(tmpRoot, "home", "test.homplast.com", "public_html")
	if err := os.MkdirAll(filepath.Join(wpDir, "wp-content"), 0o755); err != nil {
		t.Fatal(err)
	}

	origWPConfig := strings.Join([]string{
		"<?php",
		"define( 'DB_NAME', 'wp_test' );",
		"define( 'WP_CACHE', true ); // Added by WP Rocket",
		"",
		"/* That's all, stop editing! Happy publishing. */",
		"if ( ! defined( 'ABSPATH' ) ) {",
		"\tdefine( 'ABSPATH', __DIR__ . '/' );",
		"}",
		"require_once ABSPATH . 'wp-settings.php';",
		"",
	}, "\n")
	wpConfigPath := filepath.Join(wpDir, "wp-config.php")
	if err := os.WriteFile(wpConfigPath, []byte(origWPConfig), 0o640); err != nil {
		t.Fatal(err)
	}

	cpSecDir := filepath.Join(tmpRoot, "etc", "cp-security")
	if err := os.MkdirAll(cpSecDir, 0o755); err != nil {
		t.Fatal(err)
	}
	neverFile := filepath.Join(cpSecDir, "never-block.list")
	origNever := "# Never block list\n88.218.16.186 | Iran relay (PortBridge test)\n173.245.48.0/20 | Cloudflare\n"
	if err := os.WriteFile(neverFile, []byte(origNever), 0o644); err != nil {
		t.Fatal(err)
	}

	lswsConfDir := filepath.Join(tmpRoot, "usr", "local", "lsws", "conf")
	if err := os.MkdirAll(lswsConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lswsXMLFile := filepath.Join(lswsConfDir, "httpd_config.xml")
	origXML := strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<httpServerConfig>`,
		`  <useIpInProxyHeader>0</useIpInProxyHeader>`,
		`  <tuning>`,
		`    <maxConnections>10000</maxConnections>`,
		`  </tuning>`,
		`  <security>`,
		`    <accessControl>`,
		`      <allow>`,
		`ALL, 127.0.0.1T`,
		`      </allow>`,
		`    </accessControl>`,
		`  </security>`,
		`</httpServerConfig>`,
		``,
	}, "\n")
	if err := os.WriteFile(lswsXMLFile, []byte(origXML), 0o644); err != nil {
		t.Fatal(err)
	}

	wpBridgeRootOverride = tmpRoot
	wpBridgeHostsOverride = hostsFile
	defer func() {
		wpBridgeRootOverride = ""
		wpBridgeHostsOverride = ""
	}()

	cfg := &engine.Config{
		Name:                  "test",
		Role:                  engine.RoleOrigin,
		PeerIP:                "94.184.11.46",
		LocalIP:               "185.139.7.48",
		ProxyProtocol:         1,
		WebsiteBridge:         true,
		WebsiteDomains:        "test.homplast.com",
		OutboundProxy:         true,
		OutboundProxyPort:     18080,
		OutboundProxyMode:     "split",
		OutboundIranDomains:   ".ir, custombank.ir, custompay.com",
		OutboundBypassDomains: "telegram.org, customapi.io",
	}

	// 1. Sync on creation
	notes := syncWebsiteBridgeOrigin(cfg, nil, tmpRoot)
	if len(notes) > 0 {
		t.Fatalf("unexpected warnings: %v", notes)
	}

	// Verify /etc/hosts loopback entry
	hostsAfter, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hostsAfter), "127.0.0.1 test.homplast.com www.test.homplast.com # portbridge-website-loopback:test") {
		t.Fatalf("expected loopback entry in hosts, got:\n%s", string(hostsAfter))
	}

	// Verify CP-Security never-block.list replaced stale 88.218.16.186 with 94.184.11.46
	neverAfter, err := os.ReadFile(neverFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(neverAfter), "94.184.11.46 | Iran relay (PortBridge test)") ||
		strings.Contains(string(neverAfter), "88.218.16.186") {
		t.Fatalf("expected never-block.list to have 94.184.11.46 and remove stale 88.218.16.186, got:\n%s", string(neverAfter))
	}

	// Verify LiteSpeed httpd_config.xml updated useIpInProxyHeader=2 and proxyProtocol=127.0.0.1
	xmlAfter, err := os.ReadFile(lswsXMLFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xmlAfter), "<useIpInProxyHeader>2</useIpInProxyHeader>") ||
		!strings.Contains(string(xmlAfter), "<proxyProtocol>127.0.0.1</proxyProtocol>") {
		t.Fatalf("expected httpd_config.xml to enable useIpInProxyHeader=2 and proxyProtocol=127.0.0.1, got:\n%s", string(xmlAfter))
	}

	// Verify wp-config.php injection
	wpAfter, err := os.ReadFile(wpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	wpText := string(wpAfter)
	if !strings.Contains(wpText, "/* === PortBridge Smart Outbound Proxy (test) ===") ||
		!strings.Contains(wpText, "define( 'WP_PROXY_PORT', '18080' );") ||
		!strings.Contains(wpText, "customapi.io") ||
		!strings.Contains(wpText, "/* === End PortBridge Smart Outbound Proxy === */") {
		t.Fatalf("wp-config.php missing expected proxy block:\n%s", wpText)
	}
	stopIdx := strings.Index(wpText, "/* That's all, stop editing!")
	proxyIdx := strings.Index(wpText, "/* === PortBridge Smart Outbound Proxy (test) ===")
	if proxyIdx < 0 || stopIdx < 0 || proxyIdx > stopIdx {
		t.Fatalf("expected proxy block before stop-editing marker:\n%s", wpText)
	}

	// Verify mu-plugin creation
	muFile := filepath.Join(wpDir, "wp-content", "mu-plugins", "portbridge-smart-proxy.php")
	muAfter, err := os.ReadFile(muFile)
	if err != nil {
		t.Fatalf("expected mu-plugin to be created: %v", err)
	}
	muText := string(muAfter)
	if !strings.Contains(muText, "pre_http_send_through_proxy") ||
		!strings.Contains(muText, "pre_set_site_transient_update_plugins") ||
		!strings.Contains(muText, "'custompay.com'") ||
		!strings.Contains(muText, "'customapi.io'") {
		t.Fatalf("mu-plugin missing expected filters/domains:\n%s", muText)
	}

	// 2. Delete / cleanup
	cleanupWebsiteBridgeOrigin("test", cfg, tmpRoot)

	hostsCleaned, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(hostsCleaned) != origHosts {
		t.Fatalf("expected hosts file restored to:\n%q\ngot:\n%q", origHosts, string(hostsCleaned))
	}

	neverCleaned, err := os.ReadFile(neverFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(neverCleaned), "PortBridge test") {
		t.Fatalf("expected PortBridge test removed from never-block.list, got:\n%s", string(neverCleaned))
	}

	xmlCleaned, err := os.ReadFile(lswsXMLFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(xmlCleaned), "<proxyProtocol>") {
		t.Fatalf("expected <proxyProtocol> removed from httpd_config.xml on cleanup, got:\n%s", string(xmlCleaned))
	}

	wpCleaned, err := os.ReadFile(wpConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(wpCleaned) != origWPConfig {
		t.Fatalf("expected wp-config.php restored to:\n%q\ngot:\n%q", origWPConfig, string(wpCleaned))
	}

	if _, err := os.Stat(muFile); !os.IsNotExist(err) {
		t.Fatalf("expected mu-plugin %s to be removed, stat err = %v", muFile, err)
	}
}

func TestWebsiteBridgeLegacyCleanup(t *testing.T) {
	tmpRoot := t.TempDir()
	hostsFile := filepath.Join(tmpRoot, "hosts")
	legacyHosts := "127.0.0.1 localhost\n127.0.0.1 test.homplast.com # portbridge-website-loopback\n"
	if err := os.WriteFile(hostsFile, []byte(legacyHosts), 0o644); err != nil {
		t.Fatal(err)
	}

	wpDir := filepath.Join(tmpRoot, "home", "test.homplast.com", "public_html")
	muDir := filepath.Join(wpDir, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0o755); err != nil {
		t.Fatal(err)
	}

	legacyWPConfig := strings.Join([]string{
		"<?php",
		"define( 'WP_CACHE', true ); // Added by WP Rocket",
		"",
		"/* === PortBridge Smart Outbound Proxy (test) ===",
		" * Routes Iranian banks, Shaparak & SMS gateways through Iran IP (94.184.11.46)",
		" * while Telegram & international APIs connect directly from Foreign VPS (185.139.7.48).",
		" */",
		"define( 'WP_PROXY_HOST', '127.0.0.1' );",
		"define( 'WP_PROXY_PORT', '18080' );",
		"define( 'WP_PROXY_BYPASS_HOSTS', 'localhost, 127.0.0.1, *.wordpress.org' );",
		"",
		"/* That's all, stop editing! Happy publishing. */",
		"require_once ABSPATH . 'wp-settings.php';",
		"",
	}, "\n")
	wpConfigPath := filepath.Join(wpDir, "wp-config.php")
	if err := os.WriteFile(wpConfigPath, []byte(legacyWPConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	muFile := filepath.Join(muDir, "portbridge-smart-proxy.php")
	if err := os.WriteFile(muFile, []byte("<?php // legacy untagged"), 0o644); err != nil {
		t.Fatal(err)
	}

	wpBridgeRootOverride = tmpRoot
	wpBridgeHostsOverride = hostsFile
	defer func() {
		wpBridgeRootOverride = ""
		wpBridgeHostsOverride = ""
	}()

	oldCfg := &engine.Config{
		Name:           "test",
		Role:           engine.RoleOrigin,
		WebsiteBridge:  true,
		WebsiteDomains: "test.homplast.com",
	}
	cleanupWebsiteBridgeOrigin("test", oldCfg, tmpRoot)

	hostsCleaned, _ := os.ReadFile(hostsFile)
	if strings.Contains(string(hostsCleaned), "test.homplast.com") {
		t.Fatalf("expected legacy loopback removed from hosts, got:\n%s", string(hostsCleaned))
	}

	wpCleaned, _ := os.ReadFile(wpConfigPath)
	if strings.Contains(string(wpCleaned), "WP_PROXY_HOST") || strings.Contains(string(wpCleaned), "PortBridge") {
		t.Fatalf("expected legacy block removed from wp-config.php, got:\n%s", string(wpCleaned))
	}

	if _, err := os.Stat(muFile); !os.IsNotExist(err) {
		t.Fatalf("expected legacy mu-plugin to be removed")
	}
}

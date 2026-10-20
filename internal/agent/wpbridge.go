package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Nima786/portbridge/internal/engine"
)

// Test overrides so unit tests can verify /etc/hosts, wp-config.php, and
// mu-plugin management inside a temporary directory without touching the host.
var (
	wpBridgeRootOverride  string
	wpBridgeHostsOverride string
)

func wpBridgeEnabled(confDir string) bool {
	if wpBridgeRootOverride != "" || wpBridgeHostsOverride != "" {
		return true
	}
	return filepath.ToSlash(filepath.Clean(confDir)) == defaultTunnelsDir
}

func wpRoot() string {
	if wpBridgeRootOverride != "" {
		return wpBridgeRootOverride
	}
	return "/"
}

func wpHostsPath() string {
	if wpBridgeHostsOverride != "" {
		return wpBridgeHostsOverride
	}
	return "/etc/hosts"
}

// syncWebsiteBridgeOrigin configures (or cleans up) /etc/hosts loopback entries,
// wp-config.php proxy constants, and wp-content/mu-plugins/portbridge-smart-proxy.php
// on the Foreign (Origin) server for a Website Bridge tunnel.
func syncWebsiteBridgeOrigin(cfg *engine.Config, oldCfg *engine.Config, confDir string) []string {
	if !wpBridgeEnabled(confDir) {
		return nil
	}
	if (cfg == nil || cfg.Role != engine.RoleOrigin) && (oldCfg == nil || oldCfg.Role != engine.RoleOrigin) {
		return nil
	}

	name := ""
	if cfg != nil && cfg.Name != "" {
		name = cfg.Name
	} else if oldCfg != nil {
		name = oldCfg.Name
	}
	if name == "" {
		return nil
	}

	if err := syncCPSecurityNeverBlock(name, cfg); err != nil {
		log.Printf("[%s] updating CP-Security never-block list: %v", name, err)
	}

	if cfg == nil || !cfg.WebsiteBridge {
		cleanupWebsiteBridgeOrigin(name, oldCfg, confDir)
		return nil
	}

	wantProxyProto := cfg.ProxyProtocol > 0 || anyOtherWebsiteProxyProto(confDir, name)
	if err := syncLiteSpeedProxyProtocol(wantProxyProto); err != nil {
		log.Printf("[%s] updating LiteSpeed PROXY protocol settings: %v", name, err)
	}

	domains := parseWebsiteDomains(cfg.WebsiteDomains)
	var oldDomains []string
	if oldCfg != nil {
		oldDomains = parseWebsiteDomains(oldCfg.WebsiteDomains)
	}

	// Clean up any WordPress directories belonging to domains removed during an edit.
	if len(oldDomains) > 0 {
		var removed []string
		for _, od := range oldDomains {
			if !domainSliceContains(domains, od) {
				removed = append(removed, od)
			}
		}
		if len(removed) > 0 {
			for _, wpDir := range findWordPressDirs(removed, false) {
				removeWordPressProxy(wpDir, name)
			}
		}
	}

	var notes []string
	if err := syncHostsLoopback(name, domains, oldDomains); err != nil {
		log.Printf("[%s] updating /etc/hosts loopback: %v", name, err)
	}

	wpDirs := findWordPressDirs(domains, true)
	for _, wpDir := range wpDirs {
		if cfg.OutboundProxy {
			if err := applyWordPressProxy(wpDir, cfg); err != nil {
				log.Printf("[%s] configuring WordPress outbound proxy in %s: %v", name, wpDir, err)
				notes = append(notes, fmt.Sprintf("could not auto-configure WordPress in %s: %v", wpDir, err))
			} else {
				log.Printf("[%s] configured WordPress Smart Outbound Proxy in %s", name, wpDir)
			}
		} else {
			removeWordPressProxy(wpDir, name)
		}
	}

	return notes
}

// cleanupWebsiteBridgeOrigin removes /etc/hosts loopback entries, wp-config.php
// proxy constants, the PortBridge mu-plugin, CP-Security relay entry, and
// LiteSpeed PROXY protocol entry when a Website Bridge tunnel is deleted or
// disabled on the Foreign (Origin) server.
func cleanupWebsiteBridgeOrigin(name string, oldCfg *engine.Config, confDir string) {
	if !wpBridgeEnabled(confDir) || name == "" {
		return
	}
	if confDir != "" {
		if _, err := os.Stat(filepath.Join(confDir, name+".conf")); os.IsNotExist(err) {
			if err := syncCPSecurityNeverBlock(name, nil); err != nil {
				log.Printf("[%s] cleaning CP-Security never-block list: %v", name, err)
			}
		}
	}
	wantProxyProto := anyOtherWebsiteProxyProto(confDir, name)
	if err := syncLiteSpeedProxyProtocol(wantProxyProto); err != nil {
		log.Printf("[%s] cleaning LiteSpeed PROXY protocol settings: %v", name, err)
	}
	var oldDomains []string
	if oldCfg != nil {
		oldDomains = parseWebsiteDomains(oldCfg.WebsiteDomains)
	}
	if err := syncHostsLoopback(name, nil, oldDomains); err != nil {
		log.Printf("[%s] cleaning /etc/hosts loopback: %v", name, err)
	}

	seen := make(map[string]bool)
	var wpDirs []string
	addDir := func(d string) {
		clean := filepath.Clean(d)
		if !seen[clean] {
			seen[clean] = true
			wpDirs = append(wpDirs, clean)
		}
	}
	for _, d := range findWordPressDirs(oldDomains, true) {
		addDir(d)
	}
	for _, d := range findWordPressDirs(nil, true) {
		addDir(d)
	}
	for _, wpDir := range wpDirs {
		removeWordPressProxy(wpDir, name)
	}
}

func parseWebsiteDomains(raw string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	}) {
		d := strings.ToLower(strings.TrimSpace(part))
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		if idx := strings.IndexByte(d, '/'); idx >= 0 {
			d = d[:idx]
		}
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimPrefix(d, ".")
		d = strings.TrimSuffix(d, ".")
		if d == "" || d == "*" || !engine.HostnameRe.MatchString(d) {
			continue
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func domainSliceContains(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

// syncHostsLoopback updates /etc/hosts so the Foreign server resolves its own
// bridged website domain(s) to 127.0.0.1 instead of hair-pinning through the
// Iran server IP (which breaks WordPress's 10ms wp-cron.php loopback timeout and
// REST API Site Health checks).
func syncHostsLoopback(tunnelName string, activeDomains []string, oldDomains []string) error {
	hostsFile := wpHostsPath()
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		if os.IsNotExist(err) && len(activeDomains) == 0 {
			return nil
		}
		return err
	}

	tagExact := "# portbridge-website-loopback:" + tunnelName
	tagLegacy := "# portbridge-website-loopback"

	matchDomainSet := make(map[string]bool)
	for _, d := range activeDomains {
		matchDomainSet[strings.ToLower(d)] = true
		matchDomainSet["www."+strings.TrimPrefix(strings.ToLower(d), "www.")] = true
	}
	for _, d := range oldDomains {
		matchDomainSet[strings.ToLower(d)] = true
		matchDomainSet["www."+strings.TrimPrefix(strings.ToLower(d), "www.")] = true
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var kept []string
	changed := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, tagExact) {
			changed = true
			continue
		}
		if strings.Contains(trimmed, tagLegacy) && !strings.Contains(trimmed, "# portbridge-website-loopback:") {
			// Legacy untagged loopback entry: remove if it matches any domain of this tunnel
			// or if no domains were specified on cleanup.
			fields := strings.Fields(trimmed)
			matched := len(matchDomainSet) == 0 && len(activeDomains) == 0
			for _, f := range fields {
				if strings.HasPrefix(f, "#") {
					break
				}
				if matchDomainSet[strings.ToLower(f)] {
					matched = true
					break
				}
			}
			if matched {
				changed = true
				continue
			}
		}
		kept = append(kept, line)
	}

	if len(activeDomains) > 0 {
		// Trim trailing empty lines before appending so we keep a clean file.
		for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
			kept = kept[:len(kept)-1]
		}
		for _, d := range activeDomains {
			var entry string
			if strings.HasPrefix(d, "www.") {
				base := strings.TrimPrefix(d, "www.")
				entry = fmt.Sprintf("127.0.0.1 %s %s %s", base, d, tagExact)
			} else {
				entry = fmt.Sprintf("127.0.0.1 %s www.%s %s", d, d, tagExact)
			}
			kept = append(kept, entry)
		}
		kept = append(kept, "")
		changed = true
	}

	if !changed {
		return nil
	}

	newContent := strings.Join(kept, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	return writeFilePreservingOwner(hostsFile, []byte(newContent), 0o644)
}

// findWordPressDirs locates WordPress installations (directories containing
// wp-config.php) for the given domains under common Linux hosting layouts
// (CyberPanel, cPanel, DirectAdmin, Plesk, aaPanel, Nginx/Apache /var/www).
func findWordPressDirs(domains []string, fallbackAll bool) []string {
	root := wpRoot()
	seen := make(map[string]bool)
	var out []string

	addIfWP := func(dir string) {
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if seen[clean] {
			return
		}
		info, err := os.Stat(filepath.Join(clean, "wp-config.php"))
		if err == nil && !info.IsDir() {
			seen[clean] = true
			out = append(out, clean)
		}
	}

	var candidates []string
	for _, rawDom := range domains {
		domVariants := []string{rawDom}
		if strings.HasPrefix(rawDom, "www.") {
			domVariants = append(domVariants, strings.TrimPrefix(rawDom, "www."))
		}
		for _, d := range domVariants {
			candidates = append(candidates,
				filepath.Join(root, "home", d, "public_html"),
				filepath.Join(root, "var", "www", d, "public_html"),
				filepath.Join(root, "var", "www", d, "htdocs"),
				filepath.Join(root, "var", "www", d),
				filepath.Join(root, "var", "www", "html", d),
				filepath.Join(root, "www", "wwwroot", d),
				filepath.Join(root, "var", "www", "vhosts", d, "httpdocs"),
			)
			for _, pattern := range []string{
				filepath.Join(root, "home", "*", "domains", d, "public_html"),
				filepath.Join(root, "home", "*", "domains", d, "private_html"),
				filepath.Join(root, "home", "*", "public_html", d),
				filepath.Join(root, "home", "*", d),
			} {
				if matches, err := filepath.Glob(pattern); err == nil {
					candidates = append(candidates, matches...)
				}
			}
		}
	}

	for _, c := range candidates {
		addIfWP(c)
	}

	if len(out) == 0 && (len(domains) == 0 || fallbackAll) && len(domains) == 0 {
		for _, pattern := range []string{
			filepath.Join(root, "home", "*", "public_html"),
			filepath.Join(root, "home", "*", "domains", "*", "public_html"),
			filepath.Join(root, "var", "www", "*", "public_html"),
			filepath.Join(root, "var", "www", "*", "htdocs"),
			filepath.Join(root, "var", "www", "html"),
			filepath.Join(root, "www", "wwwroot", "*"),
			filepath.Join(root, "var", "www", "vhosts", "*", "httpdocs"),
		} {
			if matches, err := filepath.Glob(pattern); err == nil {
				for _, m := range matches {
					addIfWP(m)
				}
			}
		}
	}

	return out
}

func applyWordPressProxy(wpDir string, cfg *engine.Config) error {
	wpConfigPath := filepath.Join(wpDir, "wp-config.php")
	rawBytes, err := os.ReadFile(wpConfigPath)
	if err != nil {
		return err
	}

	st, err := os.Stat(wpConfigPath)
	mode := os.FileMode(0o640)
	if err == nil {
		mode = st.Mode().Perm()
	}

	cleaned, _ := stripWPConfigProxyBlock(string(rawBytes), "")
	block := buildWPConfigProxyBlock(cfg)
	updated := injectWPConfigProxyBlock(cleaned, block)

	if updated != string(rawBytes) {
		if err := writeFilePreservingOwner(wpConfigPath, []byte(updated), mode); err != nil {
			return fmt.Errorf("updating wp-config.php: %w", err)
		}
	}

	muDir := filepath.Join(wpDir, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0o755); err != nil {
		return fmt.Errorf("creating mu-plugins directory: %w", err)
	}
	copyFileOwner(wpConfigPath, muDir)

	muFile := filepath.Join(muDir, "portbridge-smart-proxy.php")
	muContent := buildWPMUPlugin(cfg)
	existingMU, err := os.ReadFile(muFile)
	if err != nil || string(existingMU) != muContent {
		if err := writeFileAtomic(muFile, []byte(muContent), 0o644); err != nil {
			return fmt.Errorf("writing mu-plugin: %w", err)
		}
	}
	copyFileOwner(wpConfigPath, muFile)

	// Clean up any older manual filename if present.
	_ = os.Remove(filepath.Join(muDir, "portbridge-proxy.php"))
	return nil
}

func removeWordPressProxy(wpDir string, tunnelName string) {
	wpConfigPath := filepath.Join(wpDir, "wp-config.php")
	if rawBytes, err := os.ReadFile(wpConfigPath); err == nil {
		st, statErr := os.Stat(wpConfigPath)
		mode := os.FileMode(0o640)
		if statErr == nil {
			mode = st.Mode().Perm()
		}
		if cleaned, changed := stripWPConfigProxyBlock(string(rawBytes), tunnelName); changed {
			if err := writeFilePreservingOwner(wpConfigPath, []byte(cleaned), mode); err != nil {
				log.Printf("[%s] cleaning wp-config.php in %s: %v", tunnelName, wpDir, err)
			} else {
				log.Printf("[%s] removed PortBridge block from %s", tunnelName, wpConfigPath)
			}
		}
	}

	muDir := filepath.Join(wpDir, "wp-content", "mu-plugins")
	for _, fn := range []string{"portbridge-smart-proxy.php", "portbridge-proxy.php"} {
		p := filepath.Join(muDir, fn)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(data)
		// If the file is tagged for another tunnel, leave it alone.
		if tunnelName != "" && strings.Contains(text, "PortBridge Tunnel:") && !strings.Contains(text, "PortBridge Tunnel: "+tunnelName+"\n") {
			continue
		}
		if err := os.Remove(p); err == nil {
			log.Printf("[%s] removed WordPress mu-plugin %s", tunnelName, p)
		}
	}
}

func buildWPConfigProxyBlock(cfg *engine.Config) string {
	port := cfg.OutboundProxyPort
	if port <= 0 {
		port = 18080
	}
	peerIP := cfg.PeerIP
	if peerIP == "" {
		peerIP = "Iran Entry Server"
	}
	localIP := cfg.LocalIP
	if localIP == "" {
		localIP = "Foreign Hosting Server"
	}

	bypass := defaultWPBypassHosts(cfg.OutboundBypassDomains)
	return strings.Join([]string{
		fmt.Sprintf("/* === PortBridge Smart Outbound Proxy (%s) ===", cfg.Name),
		" * Managed automatically by PortBridge Website Bridge.",
		fmt.Sprintf(" * Routes Iranian banks, Shaparak & SMS gateways through Iran IP (%s)", peerIP),
		fmt.Sprintf(" * while Telegram & international APIs connect directly from Foreign VPS (%s).", localIP),
		" */",
		"define( 'WP_PROXY_HOST', '127.0.0.1' );",
		fmt.Sprintf("define( 'WP_PROXY_PORT', '%d' );", port),
		fmt.Sprintf("define( 'WP_PROXY_BYPASS_HOSTS', '%s' );", bypass),
		"/* === End PortBridge Smart Outbound Proxy === */",
	}, "\n")
}

func defaultWPBypassHosts(customBypassCSV string) string {
	base := []string{
		"localhost", "127.0.0.1",
		"*.wordpress.org", "*.w.org",
		"*.telegram.org", "api.telegram.org",
		"*.stripe.com", "*.paypal.com",
		"*.googleapis.com", "*.gstatic.com",
		"*.cloudflare.com", "*.github.com", "*.githubusercontent.com",
		"*.freemius.com", "*.envato.com", "*.yoast.com", "*.elementor.com",
		"*.rankmath.com", "*.wpml.org", "*.gravityforms.com", "*.woocommerce.com",
		"*.jetpack.com", "*.akismet.com",
		"*.bricksextras.com", "bricksextras.com",
		"*.bricksbuilder.io", "bricksbuilder.io",
		"*.crocoblock.com", "api.crocoblock.com",
		"*.admincolumns.com", "api.admincolumns.com",
		"*.acfpro.com", "*.advancedcustomfields.com",
		"*.wp-rocket.me", "*.ShortPixel.com", "*.imagify.io",
		"*.updraftplus.com", "*.wordfence.com", "*.ithemes.com", "*.sucuri.net",
		"*.mailchimp.com", "*.sendgrid.com", "*.mailgun.net",
		"*.amazonaws.com", "*.digitaloceanspaces.com", "*.bunnycdn.com",
	}
	seen := make(map[string]bool, len(base))
	var out []string
	for _, h := range base {
		key := strings.ToLower(h)
		if !seen[key] {
			seen[key] = true
			out = append(out, h)
		}
	}
	for _, d := range parseWebsiteDomains(customBypassCSV) {
		for _, candidate := range []string{d, "*." + d} {
			key := strings.ToLower(candidate)
			if !seen[key] {
				seen[key] = true
				out = append(out, candidate)
			}
		}
	}
	return strings.Join(out, ", ")
}

// stripWPConfigProxyBlock removes both the bounded PortBridge block and any
// legacy untagged PortBridge WP_PROXY_* block from wp-config.php content.
func stripWPConfigProxyBlock(content string, tunnelName string) (string, bool) {
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var out []string
	changed := false

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "/* === PortBridge Smart Outbound Proxy") {
			if tunnelName != "" && strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")") &&
				!strings.Contains(trimmed, "("+tunnelName+")") {
				out = append(out, lines[i])
				continue
			}
			changed = true
			// Skip through the end of the opening comment block.
			for i < len(lines) {
				t := strings.TrimSpace(lines[i])
				if strings.Contains(t, "/* === End PortBridge Smart Outbound Proxy") {
					break
				}
				if strings.Contains(t, "*/") {
					i++
					break
				}
				i++
			}
			// Skip WP_PROXY_* defines and optional End marker.
			for i < len(lines) {
				t := strings.TrimSpace(lines[i])
				if strings.Contains(t, "/* === End PortBridge Smart Outbound Proxy") {
					i++
					break
				}
				if strings.HasPrefix(t, "define(") &&
					(strings.Contains(t, "WP_PROXY_HOST") ||
						strings.Contains(t, "WP_PROXY_PORT") ||
						strings.Contains(t, "WP_PROXY_BYPASS_HOSTS")) {
					i++
					continue
				}
				break
			}
			// If one blank line immediately follows the removed block, consume it so
			// we don't leave extra blank lines behind.
			if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
				i++
			}
			i-- // compensate for outer loop i++
			continue
		}
		out = append(out, lines[i])
	}

	if !changed {
		return content, false
	}
	return strings.Join(out, lineEnding), true
}

func injectWPConfigProxyBlock(content string, block string) string {
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	insertIdx := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.Contains(t, "That's all, stop editing") ||
			(strings.Contains(t, "wp-settings.php") && (strings.HasPrefix(t, "require") || strings.HasPrefix(t, "include"))) {
			insertIdx = i
			break
		}
	}

	blockLines := strings.Split(block, "\n")
	var out []string
	if insertIdx >= 0 {
		out = append(out, lines[:insertIdx]...)
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, blockLines...)
		out = append(out, "")
		out = append(out, lines[insertIdx:]...)
	} else {
		out = append(out, lines...)
		for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			out = out[:len(out)-1]
		}
		out = append(out, "")
		out = append(out, blockLines...)
		out = append(out, "")
	}
	return strings.Join(out, lineEnding)
}

func buildWPMUPlugin(cfg *engine.Config) string {
	port := cfg.OutboundProxyPort
	if port <= 0 {
		port = 18080
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.OutboundProxyMode))
	if mode == "" {
		mode = "split"
	}

	iranHosts := []string{
		"shaparak.ir", "zarinpal.com", "kavenegar.com", "melipayamak.com",
		"sms.ir", "farazsms.com", "ippanel.com", "payping.ir", "zibal.ir",
		"idpay.ir", "nextpay.org", "vandar.io", "jibit.ir", "asanpardakht.com",
		"sadadpsp.ir", "behpardakht.com", "sep.ir", "pep.co.ir", "sizpay.ir",
		"parsiangp.com", "snapppay.ir", "torob.com", "digikala.com", "emalls.ir",
		"bale.ai", "eitaa.com", "rubika.ir", "gap.im", "soroush-app.ir",
		"neshan.org", "balad.ir", "parspack.com", "arvancloud.ir",
		"abrarpay.com", "aqayepardakht.ir", "bitpay.ir", "bahamta.com",
		"pay.ir", "yekpay.com", "zarin.link", "mediana.ir", "niksms.com",
		"parsgreen.com", "ghasedak.me", "ghasedaksms.com", "limoosms.com",
		"amootsms.com", "payamak-panel.com", "raygansms.com", "0098sms.com",
		"najva.com", "pushe.co", "chabok.io", "postex.ir", "tipaxco.com",
		"tapin.ir", "alopeyk.com", "miare.ir", "snapp-box.com",
	}
	seenIran := make(map[string]bool, len(iranHosts))
	var finalIran []string
	for _, h := range iranHosts {
		seenIran[h] = true
		finalIran = append(finalIran, "'"+h+"'")
	}
	for _, d := range parseWebsiteDomains(cfg.OutboundIranDomains) {
		if d != "ir" && !seenIran[d] {
			seenIran[d] = true
			finalIran = append(finalIran, "'"+d+"'")
		}
	}

	var customBypass []string
	seenBypass := make(map[string]bool)
	for _, d := range parseWebsiteDomains(cfg.OutboundBypassDomains) {
		if !seenBypass[d] {
			seenBypass[d] = true
			customBypass = append(customBypass, "'"+d+"'")
		}
	}

	iranArrayPHP := strings.Join(finalIran, ", ")
	bypassArrayPHP := strings.Join(customBypass, ", ")
	proxyPortStr := strconv.Itoa(port)

	return `<?php
/**
 * Plugin Name: PortBridge Smart Iran Outbound Proxy
 * Description: Managed automatically by PortBridge Website Bridge (` + cfg.Name + `). Routes Iranian payment, Shaparak, and SMS gateway requests through the local PortBridge Iran proxy (127.0.0.1:` + proxyPortStr + `) while keeping all international plugin/theme updates, licensing APIs, and Telegram direct.
 * Version: 1.1.0
 * PortBridge Tunnel: ` + cfg.Name + `
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 1. Only send Iranian domains (.ir and configured Iranian payment/SMS gateways)
 *    through WP_PROXY_HOST (127.0.0.1:` + proxyPortStr + `). All international plugins, themes,
 *    and APIs connect directly from the Foreign server for maximum speed & reliability.
 */
add_filter( 'pre_http_send_through_proxy', function( $send, $uri, $check, $home ) {
	$host = isset( $check['host'] ) ? strtolower( (string) $check['host'] ) : '';
	if ( $host === '' || $host === 'localhost' || $host === '127.0.0.1' ) {
		return false;
	}
	$site_host = isset( $home['host'] ) ? strtolower( (string) $home['host'] ) : '';
	if ( $site_host !== '' && $host === $site_host ) {
		return false;
	}
	$bypass_domains = array( ` + bypassArrayPHP + ` );
	foreach ( $bypass_domains as $bd ) {
		if ( $bd !== '' && ( $host === $bd || substr( $host, -strlen( '.' . $bd ) ) === '.' . $bd ) ) {
			return false;
		}
	}
	if ( '` + mode + `' === 'all' ) {
		return true;
	}
	if ( substr( $host, -3 ) === '.ir' ) {
		return true;
	}
	$iran_domains = array( ` + iranArrayPHP + ` );
	foreach ( $iran_domains as $d ) {
		if ( $host === $d || substr( $host, -strlen( '.' . $d ) ) === '.' . $d ) {
			return true;
		}
	}
	return false;
}, 10, 4 );

/**
 * 2. Preserve third-party commercial plugin & theme update notifications when
 *    background wp-cron.php or WP-CLI runs wp_update_plugins() / wp_update_themes()
 *    outside wp-admin (where commercial updaters that gate on is_admin() do not
 *    register their transient filters).
 */
add_filter( 'pre_set_site_transient_update_plugins', function( $value ) {
	if ( ! is_object( $value ) || ! isset( $value->response ) || ! is_array( $value->response ) ) {
		return $value;
	}
	if ( function_exists( 'is_admin' ) && is_admin() ) {
		return $value;
	}
	$old = get_site_transient( 'update_plugins' );
	if ( ! is_object( $old ) || empty( $old->response ) || ! is_array( $old->response ) ) {
		return $value;
	}
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$installed = get_plugins();
	foreach ( $old->response as $file => $data ) {
		if ( isset( $value->response[ $file ] ) ) {
			continue;
		}
		if ( isset( $value->no_update[ $file ] ) ) {
			continue;
		}
		if ( ! isset( $installed[ $file ] ) ) {
			continue;
		}
		$cur_ver = isset( $installed[ $file ]['Version'] ) ? $installed[ $file ]['Version'] : '';
		$new_ver = is_object( $data ) && isset( $data->new_version ) ? $data->new_version : '';
		if ( $cur_ver !== '' && $new_ver !== '' && version_compare( $cur_ver, $new_ver, '<' ) ) {
			$value->response[ $file ] = $data;
		}
	}
	return $value;
}, 9999, 1 );

add_filter( 'pre_set_site_transient_update_themes', function( $value ) {
	if ( ! is_object( $value ) || ! isset( $value->response ) || ! is_array( $value->response ) ) {
		return $value;
	}
	if ( function_exists( 'is_admin' ) && is_admin() ) {
		return $value;
	}
	$old = get_site_transient( 'update_themes' );
	if ( ! is_object( $old ) || empty( $old->response ) || ! is_array( $old->response ) ) {
		return $value;
	}
	foreach ( $old->response as $slug => $data ) {
		if ( isset( $value->response[ $slug ] ) || isset( $value->no_update[ $slug ] ) ) {
			continue;
		}
		$theme = wp_get_theme( $slug );
		if ( ! $theme->exists() ) {
			continue;
		}
		$cur_ver = $theme->get( 'Version' );
		$new_ver = is_array( $data ) && isset( $data['new_version'] ) ? $data['new_version'] : '';
		if ( $cur_ver !== '' && $new_ver !== '' && version_compare( $cur_ver, $new_ver, '<' ) ) {
			$value->response[ $slug ] = $data;
		}
	}
	return $value;
}, 9999, 1 );
`
}

func writeFilePreservingOwner(path string, data []byte, defaultPerm os.FileMode) error {
	perm := defaultPerm
	hasExisting := false
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
		hasExisting = true
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := os.Chmod(tmpName, perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if hasExisting {
		copyFileOwner(path, tmpName)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func copyFileOwner(refPath string, targetPath string) {
	if runtime.GOOS != "linux" {
		return
	}
	_ = exec.Command("chown", "--reference="+refPath, targetPath).Run()
}

// anyOtherWebsiteProxyProto checks whether any other tunnel in confDir is an
// active Origin Website Bridge with proxy_protocol enabled.
func anyOtherWebsiteProxyProto(confDir, excludeName string) bool {
	if confDir == "" {
		return false
	}
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		tName := strings.TrimSuffix(e.Name(), ".conf")
		if tName == excludeName {
			continue
		}
		c, err := engine.LoadConfig(filepath.Join(confDir, e.Name()))
		if err != nil || c == nil {
			continue
		}
		if c.Role == engine.RoleOrigin && c.WebsiteBridge && c.ProxyProtocol > 0 {
			return true
		}
	}
	return false
}

// syncCPSecurityNeverBlock keeps /etc/cp-security/never-block.list (if CP-Security
// is installed on the Foreign server) in sync with the tunnel's Relay IP so the
// attack blocker never bans the Iran relay.
func syncCPSecurityNeverBlock(tunnelName string, cfg *engine.Config) error {
	if tunnelName == "" {
		return nil
	}
	neverFile := filepath.Join(wpRoot(), "etc", "cp-security", "never-block.list")
	data, err := os.ReadFile(neverFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	relayIP := ""
	if cfg != nil && cfg.Role == engine.RoleOrigin {
		relayIP = strings.TrimSpace(cfg.PeerIP)
		if cfg.GRE && strings.TrimSpace(cfg.GRERemote) != "" {
			relayIP = strings.TrimSpace(cfg.GRERemote)
		} else if cfg.SIT && strings.TrimSpace(cfg.SITRemote) != "" {
			relayIP = strings.TrimSpace(cfg.SITRemote)
		}
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	tagNeedle := "portbridge " + strings.ToLower(tunnelName) + ")"
	targetLine := ""
	if relayIP != "" {
		targetLine = fmt.Sprintf("%s | Iran relay (PortBridge %s)", relayIP, tunnelName)
	}

	var kept []string
	changed := false
	alreadyPresent := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if idx := strings.IndexByte(trimmed, '|'); idx >= 0 {
			addrPart := strings.TrimSpace(trimmed[:idx])
			labelPart := strings.ToLower(strings.TrimSpace(trimmed[idx+1:]))
			if strings.Contains(labelPart, tagNeedle) {
				if targetLine != "" && addrPart == relayIP && !alreadyPresent {
					kept = append(kept, targetLine)
					if line != targetLine {
						changed = true
					}
					alreadyPresent = true
				} else {
					changed = true
				}
				continue
			}
		}
		kept = append(kept, line)
	}

	if targetLine != "" && !alreadyPresent {
		insertIdx := 0
		for insertIdx < len(kept) {
			t := strings.TrimSpace(kept[insertIdx])
			if strings.HasPrefix(t, "#") {
				insertIdx++
				continue
			}
			break
		}
		updated := make([]string, 0, len(kept)+1)
		updated = append(updated, kept[:insertIdx]...)
		updated = append(updated, targetLine)
		updated = append(updated, kept[insertIdx:]...)
		kept = updated
		changed = true
	}

	if !changed {
		return nil
	}

	newContent := strings.Join(kept, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	if err := writeFilePreservingOwner(neverFile, []byte(newContent), 0o644); err != nil {
		return err
	}

	if wpBridgeRootOverride == "" && runtime.GOOS == "linux" {
		if _, err := os.Stat("/opt/cp-security/cpsec"); err == nil {
			_ = exec.Command("python3", "-c", "import sys; sys.path.insert(0, '/opt/cp-security'); from cpsec import access; access.apply()").Run()
		}
	}
	return nil
}

// syncLiteSpeedProxyProtocol automatically configures LiteSpeed Enterprise
// (/usr/local/lsws/conf/httpd_config.xml) on the Foreign server so it accepts
// PROXY protocol v1/v2 headers from 127.0.0.1 on HTTP (:80) and HTTPS (:443)
// when a Website Bridge tunnel has proxy_protocol enabled, and cleans up the
// entry when no Website Bridge tunnel uses proxy_protocol.
func syncLiteSpeedProxyProtocol(enable bool) error {
	xmlPath := filepath.Join(wpRoot(), "usr", "local", "lsws", "conf", "httpd_config.xml")
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	orig := string(data)
	content := strings.ReplaceAll(orig, "\r\n", "\n")
	changed := false

	if enable {
		if strings.Contains(content, "<useIpInProxyHeader>0</useIpInProxyHeader>") {
			content = strings.Replace(content, "<useIpInProxyHeader>0</useIpInProxyHeader>", "<useIpInProxyHeader>2</useIpInProxyHeader>", 1)
			changed = true
		}

		// Ensure 127.0.0.1T is trusted in <accessControl><allow>...</allow></accessControl>.
		if allowStart := strings.Index(content, "<allow>"); allowStart >= 0 {
			if allowEnd := strings.Index(content[allowStart:], "</allow>"); allowEnd >= 0 {
				allowBody := content[allowStart+len("<allow>") : allowStart+allowEnd]
				if !strings.Contains(allowBody, "127.0.0.1T") {
					trimmedBody := strings.TrimSpace(allowBody)
					var newBody string
					if trimmedBody == "" {
						newBody = "ALL, 127.0.0.1T"
					} else {
						newBody = trimmedBody + ", 127.0.0.1T"
					}
					content = content[:allowStart+len("<allow>")] + "\n" + newBody + "\n      " + content[allowStart+allowEnd:]
					changed = true
				}
			}
		}

		// Ensure <proxyProtocol> inside <tuning> contains 127.0.0.1.
		if ppStart := strings.Index(content, "<proxyProtocol>"); ppStart >= 0 {
			if ppEnd := strings.Index(content[ppStart:], "</proxyProtocol>"); ppEnd >= 0 {
				ppBody := content[ppStart+len("<proxyProtocol>") : ppStart+ppEnd]
				items := splitCSVTokens(ppBody)
				if !stringSliceContains(items, "127.0.0.1") {
					items = append(items, "127.0.0.1")
					newPP := "<proxyProtocol>" + strings.Join(items, ", ") + "</proxyProtocol>"
					content = content[:ppStart] + newPP + content[ppStart+ppEnd+len("</proxyProtocol>"):]
					changed = true
				}
			}
		} else if tuneIdx := strings.Index(content, "<tuning>"); tuneIdx >= 0 {
			insertAt := tuneIdx + len("<tuning>")
			if insertAt < len(content) && content[insertAt] == '\n' {
				insertAt++
			}
			content = content[:insertAt] + "    <proxyProtocol>127.0.0.1</proxyProtocol>\n" + content[insertAt:]
			changed = true
		}
	} else {
		if ppStart := strings.Index(content, "<proxyProtocol>"); ppStart >= 0 {
			if ppEnd := strings.Index(content[ppStart:], "</proxyProtocol>"); ppEnd >= 0 {
				ppBody := content[ppStart+len("<proxyProtocol>") : ppStart+ppEnd]
				items := splitCSVTokens(ppBody)
				var remaining []string
				removed := false
				for _, it := range items {
					if it == "127.0.0.1" {
						removed = true
						continue
					}
					remaining = append(remaining, it)
				}
				if removed {
					if len(remaining) == 0 {
						lineStart := ppStart
						for lineStart > 0 && (content[lineStart-1] == ' ' || content[lineStart-1] == '\t') {
							lineStart--
						}
						lineEnd := ppStart + ppEnd + len("</proxyProtocol>")
						if lineEnd < len(content) && content[lineEnd] == '\n' {
							lineEnd++
						}
						content = content[:lineStart] + content[lineEnd:]
					} else {
						newPP := "<proxyProtocol>" + strings.Join(remaining, ", ") + "</proxyProtocol>"
						content = content[:ppStart] + newPP + content[ppStart+ppEnd+len("</proxyProtocol>"):]
					}
					changed = true
				}
			}
		}
	}

	if !changed {
		return nil
	}

	if err := writeFilePreservingOwner(xmlPath, []byte(content), 0o644); err != nil {
		return err
	}

	if wpBridgeRootOverride == "" && runtime.GOOS == "linux" {
		if _, err := os.Stat("/usr/local/lsws/bin/lswsctrl"); err == nil {
			_ = exec.Command("/usr/local/lsws/bin/lswsctrl", "restart").Run()
		}
	}
	return nil
}

func splitCSVTokens(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func stringSliceContains(list []string, target string) bool {
	for _, it := range list {
		if it == target {
			return true
		}
	}
	return false
}

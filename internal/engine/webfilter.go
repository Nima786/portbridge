package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ParseRouteHostPatterns validates and normalizes a comma- or whitespace-separated
// list of SNI / HTTP Host routing patterns (such as "de.example.com" or "*.example.com").
func ParseRouteHostPatterns(raw string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	}) {
		orig := strings.TrimSpace(part)
		if orig == "" {
			continue
		}
		d := strings.ToLower(orig)
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		if idx := strings.IndexByte(d, '/'); idx >= 0 {
			d = d[:idx]
		}
		if d == "*" {
			return nil, fmt.Errorf("route_hosts cannot use \"*\"; enable route_default = on for a catch-all fallback route")
		}
		wildcard := false
		if strings.HasPrefix(d, "*.") {
			wildcard = true
			d = strings.TrimPrefix(d, "*.")
		} else if strings.HasPrefix(d, ".") {
			wildcard = true
			d = strings.TrimPrefix(d, ".")
		}
		base := normalizeWebsiteHost(d)
		if base == "" || strings.Contains(base, "*") {
			return nil, fmt.Errorf("invalid routing domain %q", orig)
		}
		if net.ParseIP(base) != nil || strings.Contains(base, ":") {
			return nil, fmt.Errorf("routing domain %q is an IP address; SNI/Host routing requires a domain or subdomain", orig)
		}
		if !isValidRouteDomainBase(base) {
			return nil, fmt.Errorf("invalid routing domain %q (use a full domain or subdomain such as sub.example.com or *.example.com)", orig)
		}
		canon := base
		if wildcard {
			canon = "*." + base
		}
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, nil
}

func isValidRouteDomainBase(base string) bool {
	if len(base) == 0 || len(base) > 253 || !strings.Contains(base, ".") {
		return false
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return false
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// EffectiveRouteHosts returns the normalized SNI / HTTP Host routing patterns
// for this edge tunnel. When RouteHosts is explicitly set, it takes precedence;
// otherwise a Website Bridge with specific WebsiteDomains automatically uses
// those domains so multiple Website Bridges and VPN tunnels can share :80/:443.
func (cfg *Config) EffectiveRouteHosts() []string {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(cfg.RouteHosts) != "" {
		list, err := ParseRouteHostPatterns(cfg.RouteHosts)
		if err == nil {
			return list
		}
	}
	if cfg.WebsiteBridge && strings.TrimSpace(cfg.WebsiteDomains) != "" {
		rawPatterns := parseWebsiteDomainPatterns(cfg.WebsiteDomains)
		for _, p := range rawPatterns {
			if p == "*" {
				return nil
			}
		}
		list, err := ParseRouteHostPatterns(cfg.WebsiteDomains)
		if err == nil {
			return list
		}
	}
	return nil
}

// UsesSharedPort reports whether this edge tunnel participates in shared-port
// TLS SNI / HTTP Host routing on its TCP user_listen ports.
func (cfg *Config) UsesSharedPort() bool {
	if cfg == nil || cfg.Role != RoleEdge || !cfg.ForwardsTCP() || cfg.ForwardsUDP() {
		return false
	}
	return len(cfg.EffectiveRouteHosts()) > 0 || cfg.RouteDefault
}

// MatchRouteHost checks whether host matches any pattern in patterns and returns
// a specificity score so exact hostnames (e.g. "vpn.example.com") always take
// priority over wildcard domains (e.g. "*.example.com") on the same shared port.
func MatchRouteHost(host string, patterns []string, websiteAutoWWW bool) (bool, int) {
	h := normalizeWebsiteHost(host)
	if h == "" || len(patterns) == 0 {
		return false, 0
	}
	best := 0
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			base := strings.TrimPrefix(p, "*.")
			suffix := "." + base
			if h == base || strings.HasSuffix(h, suffix) {
				score := 1000 + len(base)
				if score > best {
					best = score
				}
			}
			continue
		}
		if strings.HasPrefix(p, ".") {
			base := strings.TrimPrefix(p, ".")
			if h == base || strings.HasSuffix(h, p) {
				score := 1000 + len(base)
				if score > best {
					best = score
				}
			}
			continue
		}
		if h == p {
			score := 10000 + len(p)
			if score > best {
				best = score
			}
			continue
		}
		if websiteAutoWWW {
			base := strings.TrimPrefix(p, "www.")
			if h == base || h == "www."+base {
				score := 5000 + len(base)
				if score > best {
					best = score
				}
			}
		}
	}
	return best > 0, best
}

// RouteHostPatternsConflict reports whether two sets of normalized routing
// patterns claim the exact same canonical pattern on the same port.
func RouteHostPatternsConflict(a, b []string) (string, bool) {
	if len(a) == 0 || len(b) == 0 {
		return "", false
	}
	seen := make(map[string]bool, len(a))
	for _, p := range a {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			seen[p] = true
		}
	}
	for _, p := range b {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && seen[p] {
			return p, true
		}
	}
	return "", false
}

// AllowsWebsiteDomain reports whether host is permitted by cfg.WebsiteDomains.
// When WebsiteBridge is false or WebsiteDomains is empty (or contains "*"),
// all domains are permitted. Otherwise only the configured domain(s) (and their
// "www." counterparts, or wildcard subdomains if "*.example.com" is specified)
// are permitted.
func (cfg *Config) AllowsWebsiteDomain(host string) bool {
	if cfg == nil || !cfg.WebsiteBridge {
		return true
	}
	raw := strings.TrimSpace(cfg.WebsiteDomains)
	if raw == "" {
		return true
	}

	patterns := parseWebsiteDomainPatterns(raw)
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" {
			return true
		}
	}

	h := normalizeWebsiteHost(host)
	if h == "" {
		return false
	}

	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			suffix := strings.TrimPrefix(p, "*") // ".example.com"
			base := strings.TrimPrefix(p, "*.")  // "example.com"
			if h == base || strings.HasSuffix(h, suffix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(p, ".") {
			base := strings.TrimPrefix(p, ".")
			if h == base || strings.HasSuffix(h, p) {
				return true
			}
			continue
		}
		base := strings.TrimPrefix(p, "www.")
		if h == base || h == "www."+base {
			return true
		}
	}
	return false
}

// AllowsWebsitePayload inspects the opening bytes of an incoming HTTP (:80) or
// HTTPS/TLS (:443) connection and reports whether its target domain is allowed
// by cfg.WebsiteDomains.
func (cfg *Config) AllowsWebsitePayload(head []byte) bool {
	if cfg == nil || !cfg.WebsiteBridge || strings.TrimSpace(cfg.WebsiteDomains) == "" {
		return true
	}
	if len(head) == 0 {
		return false
	}

	// 1. Check TLS ClientHello (0x16 = Handshake)
	if sni, isTLS := extractTLSClientHelloSNI(head); isTLS {
		if sni == "" {
			// Direct HTTPS connection to raw IP without SNI or unparseable ClientHello.
			return false
		}
		return cfg.AllowsWebsiteDomain(sni)
	}

	// 2. Check plain HTTP request Host header
	if host, isHTTP := extractHTTPHostHeader(head); isHTTP {
		if host == "" {
			return false
		}
		return cfg.AllowsWebsiteDomain(host)
	}

	// Non-HTTP / non-TLS traffic on a domain-restricted Website Bridge is rejected.
	return false
}

func parseWebsiteDomainPatterns(raw string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	}) {
		d := strings.ToLower(strings.TrimSpace(part))
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		if idx := strings.IndexByte(d, '/'); idx >= 0 {
			d = d[:idx]
		}
		d = normalizeWebsiteHostKeepWildcard(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func normalizeWebsiteHostKeepWildcard(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "*" {
		return "*"
	}
	prefix := ""
	if strings.HasPrefix(h, "*.") {
		prefix = "*."
		h = strings.TrimPrefix(h, "*.")
	} else if strings.HasPrefix(h, ".") {
		prefix = "."
		h = strings.TrimPrefix(h, ".")
	}
	h = normalizeWebsiteHost(h)
	if h == "" {
		return ""
	}
	return prefix + h
}

func normalizeWebsiteHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return ""
	}
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	} else if idx := strings.LastIndexByte(h, ':'); idx >= 0 && !strings.Contains(h[:idx], ":") {
		h = h[:idx]
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	return h
}

// extractTLSClientHelloSNI parses a TLS record (possibly spanning multiple TLS
// record fragments inside b) and extracts the server_name (SNI) extension from
// a TLS ClientHello message.
func extractTLSClientHelloSNI(b []byte) (sni string, isTLS bool) {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return "", false
	}

	// Reassemble consecutive TLS Handshake (0x16) records present in b in case
	// the ClientHello was fragmented across multiple TLS records.
	var hs []byte
	pos := 0
	for pos+5 <= len(b) && b[pos] == 0x16 && b[pos+1] == 0x03 {
		recLen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		pos += 5
		end := pos + recLen
		if end > len(b) {
			end = len(b)
		}
		hs = append(hs, b[pos:end]...)
		pos = end
		if len(hs) >= 4 {
			msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+msgLen {
				break
			}
		}
	}

	// Handshake type 0x01 = ClientHello
	if len(hs) < 42 || hs[0] != 0x01 {
		return "", true
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if len(body) > msgLen {
		body = body[:msgLen]
	}

	// ClientVersion (2) + Random (32) = 34 bytes
	if len(body) < 35 {
		return "", true
	}
	p := 34

	// SessionID
	sidLen := int(body[p])
	p += 1 + sidLen
	if p+2 > len(body) {
		return "", true
	}

	// CipherSuites
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2 + csLen
	if p+1 > len(body) {
		return "", true
	}

	// CompressionMethods
	cmLen := int(body[p])
	p += 1 + cmLen
	if p+2 > len(body) {
		return "", true
	}

	// Extensions
	extTotalLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	extEnd := p + extTotalLen
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for p+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[p : p+2])
		extLen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+extLen > extEnd {
			break
		}
		if extType == 0x0000 { // server_name extension
			extData := body[p : p+extLen]
			if len(extData) < 2 {
				return "", true
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			ep := 2
			listEnd := 2 + listLen
			if listEnd > len(extData) {
				listEnd = len(extData)
			}
			for ep+3 <= listEnd {
				nameType := extData[ep]
				nameLen := int(binary.BigEndian.Uint16(extData[ep+1 : ep+3]))
				ep += 3
				if ep+nameLen > listEnd {
					break
				}
				if nameType == 0x00 { // host_name
					return strings.ToLower(strings.TrimSpace(string(extData[ep : ep+nameLen]))), true
				}
				ep += nameLen
			}
			return "", true
		}
		p += extLen
	}
	return "", true
}

var httpMethodPrefixes = []string{
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
}

func extractHTTPHostHeader(b []byte) (host string, isHTTP bool) {
	s := string(b)
	upperPrefix := s
	if len(upperPrefix) > 12 {
		upperPrefix = upperPrefix[:12]
	}
	upperPrefix = strings.ToUpper(upperPrefix)
	matchedMethod := false
	for _, m := range httpMethodPrefixes {
		if strings.HasPrefix(upperPrefix, m) {
			matchedMethod = true
			break
		}
	}
	if !matchedMethod {
		return "", false
	}

	lines := strings.Split(s, "\n")
	found := ""
	seen := false
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "Host") {
			if seen {
				// Two Host headers: the filter and the web server behind it
				// could each read a different one. Refuse rather than guess.
				return "", true
			}
			seen = true
			found = strings.TrimSpace(v)
		}
	}
	if seen {
		return found, true
	}
	return "", true
}

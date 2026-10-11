package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// defaultCloudflareECHBase64 is Cloudflare's universal ECHConfigList for the
// "cloudflare-ech.com" public outer name. When a live DNS HTTPS (type 65) query
// is blocked or returns nothing, this key lets the handshake proceed, and if
// Cloudflare has rotated its key, the edge's TLS rejection carries the updated
// RetryConfigList directly inside the handshake.
const defaultCloudflareECHBase64 = "AEX+DQBBGwAgACBCOhVoK5ks84Ldl9vZiTEM+2Nwk0WK+X/U40mYjONwZAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

const (
	dnsTypeHTTPS = 65
	svcParamECH  = 5

	echCacheTTL  = 1 * time.Hour
	echBypassTTL = 15 * time.Minute
)

var echFallbackLog = newThrottled()

type echCacheEntry struct {
	configList  []byte
	expiresAt   time.Time
	bypassUntil time.Time
}

var echCache = struct {
	sync.RWMutex
	entries map[string]echCacheEntry
}{
	entries: make(map[string]echCacheEntry),
}

// echLookupOverride replaces the network DNS lookup in tests.
var echLookupOverride func(domain string) []byte

func defaultCloudflareECHList() []byte {
	b, _ := base64.StdEncoding.DecodeString(defaultCloudflareECHBase64)
	return b
}

// useECH says whether Encrypted Client Hello (ECH) applies to a connection made
// with this configuration: when asked for, or by default for a CDN unless the
// choice was made explicitly.
func (c *Config) useECH() bool {
	return c.ECH || (c.CDN && !c.echSet)
}

// withoutECH returns a shallow copy of this configuration with ECH turned off,
// used when retrying a connection after the remote server rejected or dropped ECH.
func (c *Config) withoutECH() *Config {
	cp := *c
	cp.ECH = false
	cp.echSet = true
	cp.ECHConfig = ""
	return &cp
}

func cacheECHConfigList(domain string, list []byte) {
	if domain == "" || len(list) == 0 {
		return
	}
	echCache.Lock()
	echCache.entries[strings.ToLower(domain)] = echCacheEntry{
		configList: append([]byte(nil), list...),
		expiresAt:  time.Now().Add(echCacheTTL),
	}
	echCache.Unlock()
}

func markECHBypass(domain string) {
	if domain == "" {
		return
	}
	key := strings.ToLower(domain)
	echCache.Lock()
	entry := echCache.entries[key]
	entry.bypassUntil = time.Now().Add(echBypassTTL)
	echCache.entries[key] = entry
	echCache.Unlock()
}

func clearECHCache() {
	echCache.Lock()
	echCache.entries = make(map[string]echCacheEntry)
	echCache.Unlock()
}

func isLoopbackAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// resolveECHConfigList returns the raw ECHConfigList bytes to use for this dial,
// or nil when ECH is off, bypassed, or not applicable to the target name.
func resolveECHConfigList(cfg *Config, peerAddr net.Addr) ([]byte, error) {
	if !cfg.useECH() {
		return nil, nil
	}
	if cfg.ECHConfig != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.ECHConfig))
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("decoding ech_config: %w", err)
		}
		return raw, nil
	}

	domain := cfg.effectiveClientName()
	if domain == "" || domain == "localhost" || net.ParseIP(domain) != nil {
		return nil, nil
	}

	key := strings.ToLower(domain)
	now := time.Now()
	echCache.RLock()
	entry, ok := echCache.entries[key]
	echCache.RUnlock()
	if ok {
		if now.Before(entry.bypassUntil) {
			return nil, nil
		}
		if len(entry.configList) > 0 && now.Before(entry.expiresAt) {
			return entry.configList, nil
		}
	}

	if echLookupOverride != nil {
		list := echLookupOverride(domain)
		if len(list) > 0 {
			cacheECHConfigList(domain, list)
		}
		return list, nil
	}

	// Avoid external network DNS queries when dialling a local loopback test listener.
	if isLoopbackAddr(peerAddr) {
		return defaultCloudflareECHList(), nil
	}

	// Every Cloudflare site shares one ECH key, so the tunnel's own domain is
	// never looked up: that question would go out as plain DNS naming the very
	// domain ECH is meant to hide. A key for another CDN is set by hand with
	// ech_config.
	return currentCloudflareECH(), nil
}

// cloudflareECH is the key shared by every Cloudflare site. It starts as the
// copy built into the program and is refreshed in the background from the
// record Cloudflare publishes under its own ECH name, which says nothing about
// this tunnel. A key that has since changed is also corrected by the server
// during the handshake (RetryConfigList).
var cloudflareECH = struct {
	sync.RWMutex
	list       []byte
	checkedAt  time.Time
	refreshing bool
}{}

// currentCloudflareECH returns the best known Cloudflare ECH key right away and
// starts a refresh in the background when it is due. A dial never waits for DNS.
func currentCloudflareECH() []byte {
	cloudflareECH.RLock()
	list, checkedAt, busy := cloudflareECH.list, cloudflareECH.checkedAt, cloudflareECH.refreshing
	cloudflareECH.RUnlock()

	if time.Since(checkedAt) > echCacheTTL && !busy {
		cloudflareECH.Lock()
		if !cloudflareECH.refreshing && time.Since(cloudflareECH.checkedAt) > echCacheTTL {
			cloudflareECH.refreshing = true
			go refreshCloudflareECH()
		}
		cloudflareECH.Unlock()
	}
	if len(list) == 0 {
		return defaultCloudflareECHList()
	}
	return list
}

func refreshCloudflareECH() {
	list := fetchCloudflareECHConfigList()
	cloudflareECH.Lock()
	if len(list) > 0 {
		cloudflareECH.list = list
	}
	// Also stamped when nothing came back, so a blocked DNS is retried after
	// the usual interval rather than on every connection.
	cloudflareECH.checkedAt = time.Now()
	cloudflareECH.refreshing = false
	cloudflareECH.Unlock()
}

// fetchCloudflareECHConfigList reads the HTTPS (type 65) record Cloudflare
// publishes for its shared ECH name. Returns nil if DNS is blocked or stripped.
func fetchCloudflareECHConfigList() []byte {
	const target = "cloudflare-ech.com"
	for _, srv := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		if list := queryDNSHTTPSUDP(target, srv, 1200*time.Millisecond); len(list) > 0 {
			return list
		}
	}
	return queryDNSHTTPSDoH(target, "https://1.1.1.1/dns-query", 2000*time.Millisecond)
}

func queryDNSHTTPSUDP(domain, server string, timeout time.Duration) []byte {
	q, err := buildDNSHTTPSQuery(domain)
	if err != nil {
		return nil
	}
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}
	if buf[0] != q[0] || buf[1] != q[1] {
		return nil
	}
	return parseDNSHTTPSResponse(buf[:n])
}

func queryDNSHTTPSDoH(domain, endpoint string, timeout time.Duration) []byte {
	q, err := buildDNSHTTPSQuery(domain)
	if err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(q))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}
	return parseDNSHTTPSResponse(body)
}

func buildDNSHTTPSQuery(domain string) ([]byte, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, errors.New("empty domain")
	}
	var id [2]byte
	_, _ = rand.Read(id[:])

	var buf bytes.Buffer
	buf.Write(id[:])
	// Flags: Standard query with Recursion Desired (0x0100)
	buf.Write([]byte{0x01, 0x00})
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // root label

	var qtypeClass [4]byte
	binary.BigEndian.PutUint16(qtypeClass[0:2], dnsTypeHTTPS)
	binary.BigEndian.PutUint16(qtypeClass[2:4], 1) // IN
	buf.Write(qtypeClass[:])

	return buf.Bytes(), nil
}

func skipDNSName(msg []byte, offset int) (int, bool) {
	for {
		if offset >= len(msg) {
			return 0, false
		}
		b := msg[offset]
		if b == 0 {
			return offset + 1, true
		}
		// Compression pointer (top two bits 11)
		if b&0xC0 == 0xC0 {
			if offset+2 > len(msg) {
				return 0, false
			}
			return offset + 2, true
		}
		if b&0xC0 != 0 {
			return 0, false
		}
		offset += 1 + int(b)
	}
}

func parseDNSHTTPSResponse(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	// Check RCODE == 0
	if msg[3]&0x0F != 0 {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	offset := 12
	for i := 0; i < qdCount; i++ {
		next, ok := skipDNSName(msg, offset)
		if !ok || next+4 > len(msg) {
			return nil
		}
		offset = next + 4
	}

	for i := 0; i < anCount; i++ {
		next, ok := skipDNSName(msg, offset)
		if !ok || next+10 > len(msg) {
			return nil
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		offset = next + 10
		if offset+rdLen > len(msg) {
			return nil
		}
		rdata := msg[offset : offset+rdLen]
		offset += rdLen

		if rrType == dnsTypeHTTPS {
			if ech := extractECHFromHTTPSRDATA(rdata); len(ech) > 0 {
				return ech
			}
		}
	}
	return nil
}

func extractECHFromHTTPSRDATA(rdata []byte) []byte {
	if len(rdata) < 3 {
		return nil
	}
	priority := binary.BigEndian.Uint16(rdata[0:2])
	if priority == 0 {
		// AliasMode record has no SvcParams
		return nil
	}
	offset, ok := skipDNSName(rdata, 2)
	if !ok {
		return nil
	}
	for offset+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[offset : offset+2])
		valLen := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if offset+valLen > len(rdata) {
			return nil
		}
		if key == svcParamECH && valLen > 0 {
			return append([]byte(nil), rdata[offset:offset+valLen]...)
		}
		offset += valLen
	}
	return nil
}

// extractECHRetryConfigs checks whether a TLS/uTLS handshake error is an ECH
// rejection carrying updated RetryConfigList bytes from the server.
func extractECHRetryConfigs(err error) ([]byte, bool) {
	var uRej *utls.ECHRejectionError
	if errors.As(err, &uRej) {
		return uRej.RetryConfigList, true
	}
	var stdRej *tls.ECHRejectionError
	if errors.As(err, &stdRej) {
		return stdRej.RetryConfigList, true
	}
	return nil, false
}

// redialPeer opens a fresh TCP connection to the same remote endpoint as raw,
// so wrapDialPurpose can seamlessly retry without ECH (or with an updated ECH
// RetryConfigList) when the initial ECH handshake is rejected.
func redialPeer(raw net.Conn) (net.Conn, error) {
	if raw == nil || raw.RemoteAddr() == nil {
		return nil, errors.New("cannot redial connection without remote address")
	}
	network := raw.RemoteAddr().Network()
	if network == "" {
		network = "tcp"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	// Leave from the same address as the first attempt. The original dial may
	// have been bound to a chosen source address (local_ip), and the other
	// server's firewall may only accept that one.
	if la, ok := raw.LocalAddr().(*net.TCPAddr); ok && la != nil && la.IP != nil {
		d.LocalAddr = &net.TCPAddr{IP: la.IP}
	}
	fresh, err := d.Dial(network, raw.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	tuneSocket(fresh)
	return fresh, nil
}

// tlsStageError marks a failure of the TLS handshake itself, as opposed to
// what happens after it (the websocket upgrade, HTTP/2 setup). Only a
// handshake failure says anything about ECH; an origin that is down, or a
// wrong path, must not be mistaken for an ECH problem, or the link would be
// quietly redone with the real site name in plain view.
type tlsStageError struct{ err error }

func (e *tlsStageError) Error() string { return e.err.Error() }
func (e *tlsStageError) Unwrap() error { return e.err }

func isTLSStageError(err error) bool {
	var t *tlsStageError
	return errors.As(err, &t)
}

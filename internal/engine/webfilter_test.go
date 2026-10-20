package engine

import (
	"encoding/binary"
	"testing"
)

func buildTestClientHello(sni string) []byte {
	var ext []byte
	if sni != "" {
		hostBytes := []byte(sni)
		// server_name extension (0x0000)
		nameEntry := make([]byte, 3+len(hostBytes))
		nameEntry[0] = 0x00 // host_name
		binary.BigEndian.PutUint16(nameEntry[1:3], uint16(len(hostBytes)))
		copy(nameEntry[3:], hostBytes)

		listPayload := make([]byte, 2+len(nameEntry))
		binary.BigEndian.PutUint16(listPayload[0:2], uint16(len(nameEntry)))
		copy(listPayload[2:], nameEntry)

		ext = make([]byte, 4+len(listPayload))
		binary.BigEndian.PutUint16(ext[0:2], 0x0000)
		binary.BigEndian.PutUint16(ext[2:4], uint16(len(listPayload)))
		copy(ext[4:], listPayload)
	}

	// ClientVersion (2) + Random (32) + SessionIDLen (1) + CipherSuitesLen (2) + CipherSuite (2) + CompLen (1) + Comp (1) + ExtLen (2)
	bodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + len(ext)
	body := make([]byte, bodyLen)
	body[0], body[1] = 0x03, 0x03 // TLS 1.2
	p := 34
	body[p] = 0 // Session ID len = 0
	p++
	binary.BigEndian.PutUint16(body[p:p+2], 2) // CipherSuites len = 2
	p += 2
	binary.BigEndian.PutUint16(body[p:p+2], 0x1301)
	p += 2
	body[p] = 1 // CompressionMethods len = 1
	p++
	body[p] = 0 // null compression
	p++
	binary.BigEndian.PutUint16(body[p:p+2], uint16(len(ext)))
	p += 2
	copy(body[p:], ext)

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // Handshake
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestAllowsWebsiteDomainAndPayload(t *testing.T) {
	cfg := &Config{
		WebsiteBridge:  true,
		WebsiteDomains: "test.homplast.com",
	}

	if !cfg.AllowsWebsiteDomain("test.homplast.com") {
		t.Fatal("expected test.homplast.com to be allowed")
	}
	if !cfg.AllowsWebsiteDomain("www.test.homplast.com:443") {
		t.Fatal("expected www.test.homplast.com:443 to be allowed")
	}
	if cfg.AllowsWebsiteDomain("noorejan.com") {
		t.Fatal("expected noorejan.com to be blocked")
	}
	if cfg.AllowsWebsiteDomain("homplast.com") {
		t.Fatal("expected homplast.com to be blocked when only test.homplast.com is configured")
	}

	// TLS ClientHello SNI checks
	if !cfg.AllowsWebsitePayload(buildTestClientHello("test.homplast.com")) {
		t.Fatal("expected TLS ClientHello for test.homplast.com to be allowed")
	}
	if !cfg.AllowsWebsitePayload(buildTestClientHello("www.test.homplast.com")) {
		t.Fatal("expected TLS ClientHello for www.test.homplast.com to be allowed")
	}
	if cfg.AllowsWebsitePayload(buildTestClientHello("noorejan.com")) {
		t.Fatal("expected TLS ClientHello for noorejan.com to be blocked")
	}
	if cfg.AllowsWebsitePayload(buildTestClientHello("")) {
		t.Fatal("expected TLS ClientHello without SNI to be blocked")
	}

	// Plain HTTP Host header checks
	httpAllowed := []byte("GET / HTTP/1.1\r\nHost: test.homplast.com\r\nUser-Agent: curl/8.0\r\n\r\n")
	if !cfg.AllowsWebsitePayload(httpAllowed) {
		t.Fatal("expected HTTP request for test.homplast.com to be allowed")
	}
	httpBlocked := []byte("GET / HTTP/1.1\r\nHost: noorejan.com\r\nUser-Agent: curl/8.0\r\n\r\n")
	if cfg.AllowsWebsitePayload(httpBlocked) {
		t.Fatal("expected HTTP request for noorejan.com to be blocked")
	}
}

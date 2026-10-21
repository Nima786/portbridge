package engine

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"
)

// A stranger states a frame length before proving who it is. Claiming 64 MB and
// sending nothing must not be given 64 MB.
func TestWSPayloadIsNotAllocatedBeforeItArrives(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := readWSPayload(bytes.NewReader([]byte("only ten b")), 60<<20)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a payload that never arrived was reported as read")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("a 60 MB claim with 10 bytes behind it allocated %d bytes", grew)
	}
	// And a real payload of each kind still comes through whole.
	for _, n := range []int{0, 1, 1000, wsPreallocMax, wsPreallocMax + 1, 3 * wsPreallocMax} {
		data := bytes.Repeat([]byte{'x'}, n)
		got, err := readWSPayload(bytes.NewReader(data), uint64(n))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("payload of %d bytes: err=%v, len=%d", n, err, len(got))
		}
	}
}

func TestSecondHostHeaderIsRefused(t *testing.T) {
	one := []byte("GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
	if host, ok := extractHTTPHostHeader(one); !ok || host != "allowed.example.com" {
		t.Fatalf("one Host header: %q %v", host, ok)
	}
	two := []byte("GET / HTTP/1.1\r\nHost: allowed.example.com\r\nHost: evil.example.net\r\n\r\n")
	if host, ok := extractHTTPHostHeader(two); !ok || host != "" {
		t.Fatalf("two Host headers were read as %q (isHTTP=%v), not refused", host, ok)
	}
	cfg := &Config{WebsiteBridge: true, WebsiteDomains: "allowed.example.com"}
	if cfg.AllowsWebsitePayload(two) {
		t.Fatal("a request with two Host headers got through the filter")
	}
	if !cfg.AllowsWebsitePayload(one) {
		t.Fatal("a normal request was refused")
	}
}

func TestOutboundProxyRefusesSharedAndSpecialRanges(t *testing.T) {
	for _, s := range []string{"100.64.0.1", "100.127.255.254", "198.18.0.5", "192.0.0.8", "224.0.0.1", "240.0.0.1",
		"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "::1", "fe80::1", "64:ff9b::a00:1"} {
		if !isBlockedOutboundIP(net.ParseIP(s)) {
			t.Errorf("%s was not blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if isBlockedOutboundIP(net.ParseIP(s)) {
			t.Errorf("%s, a public address, was blocked", s)
		}
	}
}

// A spare being tested still holds its place, so refilling does not build a
// replacement for it and the healthy one is not thrown away when it comes back.
func TestSpareBeingCheckedKeepsItsPlace(t *testing.T) {
	p := newPool(2, time.Minute, time.Second, nil)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	p.items = append(p.items, parked{conn: c1, at: time.Now(), lastPing: time.Now()})
	p.checking = 1 // the second spare is out being tested
	d1, d2 := net.Pipe()
	defer d1.Close()
	defer d2.Close()
	if p.offerLocal(d1) {
		t.Fatal("a new connection was parked into the place a spare under test is holding")
	}
	p.finishCheck()
	if p.checking != 0 {
		t.Fatalf("checking = %d after the check ended", p.checking)
	}
	if !p.offerLocal(d1) {
		t.Fatal("the place was not free after the check ended")
	}
}

func TestIdleFakeTCPPeersAndICMPClientsArePruned(t *testing.T) {
	old := time.Now().Add(-2 * peerIdleLimit).UnixNano()
	fresh := time.Now().UnixNano()

	f := &fakeTCPPacketConn{}
	stale, live := &fakeTCPPeerState{}, &fakeTCPPeerState{}
	stale.lastSeen.Store(old)
	live.lastSeen.Store(fresh)
	f.peers.Store("1.1.1.1:1", stale)
	f.peers.Store("2.2.2.2:2", live)
	f.pruneIdlePeers()
	if _, ok := f.peers.Load("1.1.1.1:1"); ok {
		t.Error("a long-silent faketcp peer was kept")
	}
	if _, ok := f.peers.Load("2.2.2.2:2"); !ok {
		t.Error("an active faketcp peer was dropped")
	}

	c := &icmpPacketConn{}
	sm, lm := &icmpClientMeta{}, &icmpClientMeta{}
	sm.lastSeen.Store(old)
	lm.lastSeen.Store(fresh)
	c.clients.Store("1.1.1.1:1", sm)
	c.clients.Store("2.2.2.2:2", lm)
	c.pruneIdleClients()
	if _, ok := c.clients.Load("1.1.1.1:1"); ok {
		t.Error("a long-silent icmp client was kept")
	}
	if _, ok := c.clients.Load("2.2.2.2:2"); !ok {
		t.Error("an active icmp client was dropped")
	}
}

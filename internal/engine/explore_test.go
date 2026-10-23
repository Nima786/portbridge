package engine

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// freePort finds a port that is free for both TCP and UDP right now.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

func TestExploreFindsWhatGetsAcrossAndWhatDoesNot(t *testing.T) {
	good := freePort(t)
	closed := freePort(t) // nothing is made to listen here

	// A port something else already uses, over TCP.
	busy := freePort(t)
	other, err := net.Listen("tcp", ":"+strconv.Itoa(busy))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	const token = "tok-abc123"
	r, infos, err := StartExploreResponder([]int{good, busy}, token, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	byPort := map[int]ExplorePortInfo{}
	for _, in := range infos {
		byPort[in.Port] = in
	}
	if byPort[good].TCP != "listening" || byPort[good].UDP != "listening" {
		t.Fatalf("the free port was not opened: %+v", byPort[good])
	}
	if byPort[busy].TCP != "busy" {
		t.Fatalf("a port in use was not left alone: %+v", byPort[busy])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	specs := []ExplorePortSpec{
		{Port: good, TCP: "listening", UDP: "listening"},
		{Port: busy, TCP: "busy", UDP: byPort[busy].UDP},
		{Port: closed, TCP: "listening", UDP: "listening"}, // claimed open, but nothing is there
	}
	res := ExplorePorts(ctx, "127.0.0.1", specs, token)
	got := map[int]ExplorePortResult{}
	for _, x := range res {
		got[x.Port] = x
	}
	if got[good].TCP != "data" || got[good].UDP != "data" {
		t.Errorf("good port: %+v, want data over both", got[good])
	}
	if got[busy].TCP != "open" {
		t.Errorf("busy port: tcp = %q, want open (a connection only)", got[busy].TCP)
	}
	if got[closed].TCP != "blocked" || got[closed].UDP != "blocked" {
		t.Errorf("closed port: %+v, want blocked both ways", got[closed])
	}

	// A TLS handshake gets through on the same port, whatever name it carries.
	names := ScanWhitelistedSNIs(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(good)), []string{"one.example", "two.example", "  "})
	if len(names) != 2 {
		t.Fatalf("expected two names tested (the blank one dropped), got %d", len(names))
	}
	for _, n := range names {
		if !n.Reachable {
			t.Errorf("name %q did not get through to the responder: %s", n.SNI, n.Error)
		}
	}
}

// A connection that opens but never gets an answer is what a filter that cuts a
// connection after it starts looks like; it must not be called working.
func TestExploreCallsAnUnansweredConnectionStalled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(5 * time.Second); _ = c.Close() }() // takes the bytes, says nothing
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := ExplorePorts(context.Background(), "127.0.0.1", []ExplorePortSpec{{Port: port, TCP: "listening", UDP: "failed"}}, "tok")
	if res[0].TCP != "stalled" {
		t.Fatalf("tcp = %q, want stalled", res[0].TCP)
	}
	if res[0].UDP != "untested" {
		t.Fatalf("udp = %q, want untested", res[0].UDP)
	}
}

func TestExploreReachTellsAWorkingEndpointFromACutOffOne(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closed := freePort(t)
	res := ExploreReach(context.Background(), []ExploreTarget{
		{"Test", "up", ln.Addr().String()},
		{"Test", "down", "127.0.0.1:" + strconv.Itoa(closed)},
		{"Test", "no such name", "no-such-name.invalid:443"},
	})
	if !res[0].OK {
		t.Errorf("a listening endpoint was reported unreachable: %+v", res[0])
	}
	if res[1].OK || res[1].Stage != "connect" {
		t.Errorf("a closed port: %+v, want a connect failure", res[1])
	}
	if res[2].OK || res[2].Stage != "dns" {
		t.Errorf("an unknown name: %+v, want a dns failure", res[2])
	}
}

func TestExplorePicksAWebPortForTheNameTest(t *testing.T) {
	res := []ExplorePortResult{{Port: 8080, TCP: "data"}, {Port: 8443, TCP: "data"}, {Port: 443, TCP: "stalled"}, {Port: 9001, TCP: "data"}}
	if p := pickNamesPort(res); p != 8443 {
		t.Fatalf("picked %d, want 8443 (443 did not answer)", p)
	}
	if p := pickNamesPort([]ExplorePortResult{{Port: 443, TCP: "open"}, {Port: 53, TCP: "blocked"}}); p != 0 {
		t.Fatalf("picked %d with no port answering, want none", p)
	}
	if p := pickNamesPort([]ExplorePortResult{{Port: 9001, TCP: "data"}, {Port: 853, TCP: "data"}}); p != 853 {
		t.Fatalf("picked %d, want the lowest of the unusual ports", p)
	}
}

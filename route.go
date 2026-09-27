package main

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// A second way to reach the other server, used when the first one stops working.
//
// The failure this exists for is specific and common: a tunnel runs happily for
// months and then the foreign server's address is blocked, at which point the
// link cannot be established at all while both servers are perfectly healthy.
// Nothing in the tunnel is wrong, so nothing in the tunnel can fix it. What fixes
// it is reaching the same server by a different route, and the obvious different
// route is through a CDN, which resolves to addresses that are not worth blocking.
//
// Only the side that dials needs to know about this. The side that accepts sees
// the same disguised connection arriving either way, so it needs no setting and
// no new version of anything.
const (
	// How long before the preferred route is tried again after falling back. A
	// block is usually not permanent, and the direct route is normally the
	// faster of the two, so it is worth going back to when it returns.
	routeRecheck = 2 * time.Minute
)

// route is one way to reach the other server: an address, and the hostname to
// claim while using it.
//
// The name belongs to the route rather than to the tunnel because the two routes
// are seen differently. Going through a CDN means naming the real domain, since
// that is how the CDN knows whose server to forward to. Going straight to the
// server, that same domain would not match the address, and a name that does not
// match where the traffic is going is worth more to an onlooker than either fact
// on its own.
type route struct {
	addr string
	name string
}

// router holds the routes to try, in order of preference, and remembers which
// one last worked.
type router struct {
	targets []route

	mu       sync.Mutex
	current  int
	lastGood time.Time

	log *throttled
}

func newRouter(cfg *Config) *router {
	targets := []route{{addr: cfg.dialTarget(), name: cfg.ServerName}}
	if alt := cfg.AltTarget; alt != "" && alt != targets[0].addr {
		name := cfg.AltServerName
		if name == "" {
			name = cfg.ServerName
		}
		targets = append(targets, route{addr: alt, name: name})
	}
	return &router{targets: targets, log: newThrottled()}
}

// pick decides which route to start from. After a while on a fallback route it
// starts from the preferred one again, so a block that has been lifted is
// noticed rather than waited out for ever.
func (r *router) pick() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != 0 && time.Since(r.lastGood) > routeRecheck {
		r.current = 0
	}
	return r.current
}

func (r *router) settle(i int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = i
	r.lastGood = time.Now()
}

// inUse is the route connections are being made over at the moment, and whether
// it is the preferred one.
//
// Published rather than left to be guessed at from the log. Working it out by
// reading log lines gets it wrong the moment a tunnel recovers: it would still
// be reporting the fallback long after the direct route came back.
func (r *router) inUse() (addr string, preferred bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current >= len(r.targets) {
		return "", true
	}
	return r.targets[r.current].addr, r.current == 0
}

// hasFallback reports whether there is a second route at all.
func (r *router) hasFallback() bool {
	return len(r.targets) > 1
}

// dial tries each route in turn, beginning with whichever is currently preferred,
// and reports the hostname the caller should claim on the connection it gets.
func (r *router) dial(timeout time.Duration) (net.Conn, string, error) {
	start := r.pick()
	var lastErr error

	for n := 0; n < len(r.targets); n++ {
		i := (start + n) % len(r.targets)
		d := net.Dialer{Timeout: timeout}
		c, err := d.Dial("tcp", r.targets[i].addr)
		if err != nil {
			lastErr = err
			continue
		}
		if i != start {
			// Worth a log line every time: which route is carrying the tunnel
			// is exactly what someone looking into a slow or missing tunnel
			// needs to know, and it changes rarely.
			log.Printf("reaching the other server via %s instead of %s",
				r.targets[i].addr, r.targets[start].addr)
		}
		r.settle(i)
		return c, r.targets[i].name, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no route to the other server is configured")
	}
	if len(r.targets) > 1 {
		r.log.printf("none of the %d routes to the other server worked; last error: %v",
			len(r.targets), lastErr)
	}
	return nil, "", lastErr
}

// describe is what the startup log says, so the second route is visible without
// reading the settings file.
func (r *router) describe() string {
	if len(r.targets) < 2 {
		return r.targets[0].addr
	}
	return r.targets[0].addr + ", falling back to " + r.targets[1].addr
}

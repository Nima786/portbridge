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

// router holds the addresses to try, in order of preference, and remembers which
// one last worked.
type router struct {
	targets []string

	mu       sync.Mutex
	current  int
	lastGood time.Time

	log *throttled
}

func newRouter(cfg *Config) *router {
	targets := []string{cfg.dialTarget()}
	if alt := cfg.AltTarget; alt != "" && alt != targets[0] {
		targets = append(targets, alt)
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

// dial tries each route in turn, beginning with whichever is currently preferred.
func (r *router) dial(timeout time.Duration) (net.Conn, error) {
	start := r.pick()
	var lastErr error

	for n := 0; n < len(r.targets); n++ {
		i := (start + n) % len(r.targets)
		d := net.Dialer{Timeout: timeout}
		c, err := d.Dial("tcp", r.targets[i])
		if err != nil {
			lastErr = err
			continue
		}
		if i != start {
			// Worth a log line every time: which route is carrying the tunnel
			// is exactly what someone looking into a slow or missing tunnel
			// needs to know, and it changes rarely.
			log.Printf("reaching the other server via %s instead of %s",
				r.targets[i], r.targets[start])
		}
		r.settle(i)
		return c, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no route to the other server is configured")
	}
	if len(r.targets) > 1 {
		r.log.printf("none of the %d routes to the other server worked; last error: %v",
			len(r.targets), lastErr)
	}
	return nil, lastErr
}

// describeRoutes is what the startup log says, so the second route is visible
// without reading the settings file.
func (r *router) describe() string {
	if len(r.targets) < 2 {
		return r.targets[0]
	}
	return r.targets[0] + ", falling back to " + r.targets[1]
}

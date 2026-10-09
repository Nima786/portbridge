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
// months and then the foreign server's address is blocked. There are two shapes
// of block, and they need different detection:
//
//	the address cannot be reached at all. The connection is refused or times out.
//	That is easy to see: the dial fails.
//
//	the address can be reached, but the route cuts a connection off after a few
//	packets. The connection opens, the handshake may even finish, and then
//	nothing more gets through. Every dial succeeds, so a router that only reacts
//	to a failed dial never notices, and a tunnel in this state reports itself
//	ready while carrying nothing. This is what filtering of a whole address
//	tends to look like in practice.
//
// Nothing in the tunnel is wrong in either case, so nothing in the tunnel can fix
// it. What fixes it is reaching the same server by a different route, and the
// obvious different route is through a CDN, which resolves to addresses that are
// not worth blocking.
//
// A route is therefore set aside not only when it cannot be dialled but also when
// a real transfer over it stalls (see pathProbe) or when its secure handshake
// keeps failing. A route set aside is left alone for a while and then given
// another chance, so a block that has been lifted is noticed.
//
// Only the side that dials needs to know about this. The side that accepts sees
// the same disguised connection arriving either way, so it needs no setting and
// no new version of anything.
const (
	// How long before the preferred route is tried again after falling back. A
	// block is usually not permanent, and the direct route is normally the
	// faster of the two, so it is worth going back to when it returns.
	routeRecheck = 2 * time.Minute

	// How long a route stays set aside after its handshake keeps failing. Short:
	// a refused handshake is more often a hiccup than a block.
	routeHandshakeHold = 20 * time.Second

	// How long a route stays set aside after a real transfer over it stalled.
	// Long enough not to flap, short enough to notice when the block lifts.
	routeStallHold = 3 * time.Minute

	// Longest a route is ever held for, however many times in a row it failed.
	routeHoldMax = 15 * time.Minute
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
//
// cdn says whether the route actually goes through a CDN. The defaults that make
// sense only there, the browser fingerprint and the split hello, follow the
// route rather than the tunnel, so that a backup route through a CDN gets them
// even when the preferred route, going straight to the server, does not.
type route struct {
	addr  string
	name  string
	cdn   bool
	clean bool // one of the clean addresses, which take turns
}

// router holds the routes to try, in order of preference, and remembers which
// one last worked.
type router struct {
	cfg     *Config
	targets []route

	mu       sync.Mutex
	current  int
	lastGood time.Time // when it settled on the current route

	badUntil  []time.Time // per route: set aside until then
	badCount  []int       // per route: how many times in a row it was set aside
	hsFails   []int       // per route: consecutive failed handshakes
	lastTrial []time.Time // per route: when a more preferred route was last tried out
	rot       int         // rotates among the clean addresses

	log *throttled
}

func newRouter(cfg *Config) *router {
	var targets []route

	port := "443"
	if _, p, err := net.SplitHostPort(cfg.TunnelAddr); err == nil && p != "" {
		port = p
	}

	// 1. Clean IPs (if configured) take top priority for dialing. They are
	// different addresses that all lead to the same place, so they take turns.
	if len(cfg.CleanIPs) > 0 {
		seen := map[string]bool{}
		for _, ip := range cfg.CleanIPs {
			addr := cleanAddr(ip, port)
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			targets = append(targets, route{addr: addr, name: cfg.effectiveServerName(), cdn: cfg.CDN, clean: true})
		}
	}

	// 2. Standard dialTarget
	std := cfg.dialTarget()
	alreadyPresent := false
	for _, t := range targets {
		if t.addr == std {
			alreadyPresent = true
			break
		}
	}
	if !alreadyPresent {
		targets = append(targets, route{addr: std, name: cfg.ServerName, cdn: cfg.CDN})
	}

	// 3. Fallback route (if configured). A fallback that claims its own name is
	// the CDN route: naming the real domain is how a CDN knows whose server to
	// forward to, so that is what the separate name is for.
	if alt := cfg.AltTarget; alt != "" {
		name := cfg.AltServerName
		if name == "" {
			name = cfg.ServerName
		}
		alreadyAlt := false
		for _, t := range targets {
			if t.addr == alt {
				alreadyAlt = true
				break
			}
		}
		if !alreadyAlt {
			targets = append(targets, route{addr: alt, name: name, cdn: cfg.CDN || cfg.AltServerName != ""})
		}
	}

	n := len(targets)
	return &router{
		cfg:       cfg,
		targets:   targets,
		badUntil:  make([]time.Time, n),
		badCount:  make([]int, n),
		hsFails:   make([]int, n),
		lastTrial: make([]time.Time, n),
		log:       newThrottled(),
	}
}

// routeTrialEvery is how often a more preferred route than the one in use is
// tried out with a real transfer, to find out whether it works again.
const routeTrialEvery = 60 * time.Second

// dueForTrial lists the routes more preferred than the one in use that are due
// another try. Going back to one is only ever done on the strength of a transfer
// that succeeded over it, never because enough time has passed.
func (r *router) dueForTrial() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var due []int
	now := time.Now()
	for j := 0; j < r.current && j < len(r.targets); j++ {
		if now.Sub(r.lastTrial[j]) >= routeTrialEvery {
			r.lastTrial[j] = now
			due = append(due, j)
		}
	}
	return due
}

// extendHold keeps route j set aside for at least hold more, after it failed
// another trial.
func (r *router) extendHold(j int, hold time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j < 0 || j >= len(r.targets) {
		return
	}
	if until := time.Now().Add(hold); until.After(r.badUntil[j]) {
		r.badUntil[j] = until
	}
}

// cleanAddr turns one entry of the clean address list into something dialable,
// or "" if it cannot be one. An address may carry its own port; otherwise it
// takes the tunnel's. IPv6 addresses may be written bare or in brackets.
func cleanAddr(entry, defaultPort string) string {
	entry = trimSpaceQuotes(entry)
	if entry == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		if host == "" || port == "" {
			return ""
		}
		return net.JoinHostPort(host, port)
	}
	host := entry
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, defaultPort)
}

func trimSpaceQuotes(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '"' || s[0] == '\'') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '"' || s[len(s)-1] == '\'') {
		s = s[:len(s)-1]
	}
	return s
}

// usable reports whether route i may be used right now. Called with mu held.
func (r *router) usable(i int) bool {
	return !time.Now().Before(r.badUntil[i])
}

// pick decides which route to start from. After a while on a fallback route it
// starts from the preferred one again, so a block that has been lifted is
// noticed rather than waited out for ever. A route that has been set aside is
// never picked while another one is available.
func (r *router) pick() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != 0 && time.Since(r.lastGood) > routeRecheck {
		r.current = 0
		r.lastGood = time.Now()
	}
	return r.firstUsableFrom(r.current)
}

// firstUsableFrom finds the first route at or after start that is not set aside,
// wrapping round. If every route is set aside it gives start back, because
// trying something is better than trying nothing.
func (r *router) firstUsableFrom(start int) int {
	n := len(r.targets)
	for k := 0; k < n; k++ {
		i := (start + k) % n
		if r.usable(i) {
			return i
		}
	}
	return start
}

// settle records that route i is the one now in use. It only notes when it moved
// there: refreshing the time on every successful dial would mean that a tunnel
// busy enough to be dialling all the time never got round to trying its
// preferred route again.
func (r *router) settle(i int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != i || r.lastGood.IsZero() {
		r.current = i
		r.lastGood = time.Now()
	}
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

// count is how many routes there are.
func (r *router) count() int { return len(r.targets) }

// current route index, without the recheck pick() does.
func (r *router) currentIndex() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// isSetAside reports whether route i is currently being avoided.
func (r *router) isSetAside(i int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i < 0 || i >= len(r.targets) {
		return false
	}
	return !r.usable(i)
}

// setAside stops using route i for a while. If it was the route in use, the next
// usable one takes over. hold is how long for; repeated failures in a row make it
// longer, up to routeHoldMax.
func (r *router) setAside(i int, hold time.Duration, why string) {
	r.mu.Lock()
	if i < 0 || i >= len(r.targets) {
		r.mu.Unlock()
		return
	}
	r.badCount[i]++
	// Each repeat doubles the hold, so a route that keeps failing stops being
	// retried as often, but one that failed once is retried soon.
	for k := 1; k < r.badCount[i] && hold < routeHoldMax; k++ {
		hold *= 2
	}
	if hold > routeHoldMax {
		hold = routeHoldMax
	}
	r.badUntil[i] = time.Now().Add(hold)
	r.hsFails[i] = 0
	addr := r.targets[i].addr
	moved := ""
	wasInUse := r.current == i
	if wasInUse {
		next := r.firstUsableFrom((i + 1) % len(r.targets))
		if next != i {
			r.current = next
			r.lastGood = time.Now()
			moved = r.targets[next].addr
		}
	}
	r.mu.Unlock()

	if moved != "" {
		log.Printf("the route to the other server via %s is not carrying data (%s); using %s instead", addr, why, moved)
	} else if wasInUse {
		r.log.printf("the route to the other server via %s is not carrying data (%s) and there is no other route to use", addr, why)
	}
}

// restore marks route i good again and, if it is more preferred than the one in
// use, goes back to it. Returns true if the route in use changed.
func (r *router) restore(i int) bool {
	r.mu.Lock()
	if i < 0 || i >= len(r.targets) {
		r.mu.Unlock()
		return false
	}
	r.badUntil[i] = time.Time{}
	r.badCount[i] = 0
	r.hsFails[i] = 0
	changed := false
	addr := r.targets[i].addr
	if i < r.current {
		r.current = i
		r.lastGood = time.Now()
		changed = true
	}
	r.mu.Unlock()
	if changed {
		log.Printf("the route to the other server via %s is carrying data again; going back to it", addr)
	}
	return changed
}

// handshakeFailed notes that a connection over route i could not complete its
// secure handshake or authentication. One failure is a hiccup; several in a row
// mean the route is not usable, which is set aside briefly.
func (r *router) handshakeFailed(i int, err error) {
	r.mu.Lock()
	if i < 0 || i >= len(r.targets) {
		r.mu.Unlock()
		return
	}
	r.hsFails[i]++
	fails := r.hsFails[i]
	r.mu.Unlock()
	if fails >= 3 && len(r.targets) > 1 {
		r.setAside(i, routeHandshakeHold, "its handshake keeps failing: "+err.Error())
	}
}

// handshakeOK notes that a connection over route i completed its handshake.
func (r *router) handshakeOK(i int) {
	r.mu.Lock()
	if i >= 0 && i < len(r.targets) {
		r.hsFails[i] = 0
	}
	r.mu.Unlock()
}

// rotation picks which clean address to start from, taking turns among the ones
// that are not set aside. Returns -1 when there is nothing to rotate among.
func (r *router) rotation() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ready []int
	for i, t := range r.targets {
		if t.clean && r.usable(i) {
			ready = append(ready, i)
		}
	}
	if len(ready) < 2 {
		return -1
	}
	r.rot++
	return ready[r.rot%len(ready)]
}

// order is the sequence of routes to try for one dial: the preferred start first,
// then the rest, with any that are set aside pushed to the back so they are only
// tried when nothing else works.
func (r *router) order() []int {
	start := r.pick()
	if rot := r.rotation(); rot >= 0 {
		// Only take turns while the route in use is itself one of the clean
		// addresses; otherwise it has already fallen back past them.
		r.mu.Lock()
		if r.targets[start].clean {
			start = rot
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.targets)
	var good, aside []int
	for k := 0; k < n; k++ {
		i := (start + k) % n
		if r.usable(i) {
			good = append(good, i)
		} else {
			aside = append(aside, i)
		}
	}
	return append(good, aside...)
}

// dialRoute opens a connection to one specific route.
func (r *router) dialRoute(i int, timeout time.Duration) (net.Conn, error) {
	if i < 0 || i >= len(r.targets) {
		return nil, errors.New("no such route")
	}
	if r.cfg != nil && r.cfg.Transport == TransportKCP {
		return kcpDial(r.targets[i].addr, r.cfg)
	}
	d := net.Dialer{Timeout: timeout}
	if r.cfg != nil {
		d.LocalAddr = r.cfg.sourceFor(r.targets[i].addr)
	}
	return d.Dial("tcp", r.targets[i].addr)
}

// sourceFor is the address to connect from when the other server is reached over
// IPv6: this server's own IPv6 address from the settings. A server with several
// IPv6 addresses would otherwise pick one itself, and the other side's firewall
// lets in only the one it was told. Nothing is chosen for IPv4, for a name, or
// when the two are not the same kind of address, so those connect as always.
func (c *Config) sourceFor(target string) net.Addr {
	local := net.ParseIP(c.LocalIP)
	if local == nil || local.To4() != nil {
		return nil
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	dst := net.ParseIP(host)
	if dst == nil || dst.To4() != nil {
		return nil
	}
	return &net.TCPAddr{IP: local}
}

// dialIdx tries each route in turn, beginning with the preferred one, and
// reports which route it reached. The caller needs the index to tell the router
// how the handshake went, which is what tells a route that merely accepts
// connections apart from one that works.
func (r *router) dialIdx(timeout time.Duration) (net.Conn, int, error) {
	order := r.order()
	first := order[0]
	var lastErr error

	for _, i := range order {
		c, err := r.dialRoute(i, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		if i != first {
			// Worth a log line every time: which route is carrying the tunnel
			// is exactly what someone looking into a slow or missing tunnel
			// needs to know, and it changes rarely.
			log.Printf("reaching the other server via %s instead of %s",
				r.targets[i].addr, r.targets[first].addr)
		}
		r.settle(i)
		return c, i, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no route to the other server is configured")
	}
	if len(r.targets) > 1 {
		r.log.printf("none of the %d routes to the other server worked; last error: %v",
			len(r.targets), lastErr)
	}
	return nil, -1, lastErr
}

// dial tries each route in turn and reports the hostname the caller should claim
// on the connection it gets.
func (r *router) dial(timeout time.Duration) (net.Conn, string, error) {
	c, i, err := r.dialIdx(timeout)
	if err != nil {
		return nil, "", err
	}
	return c, r.targets[i].name, nil
}

// describe is what the startup log says, so the second route is visible without
// reading the settings file.
func (r *router) describe() string {
	if len(r.targets) < 2 {
		return r.targets[0].addr
	}
	return r.targets[0].addr + ", falling back to " + r.targets[1].addr
}

// routeConfig returns the configuration to dial route i with: the name that route
// claims, and the CDN defaults that go with it.
func (r *router) routeConfig(i int) *Config {
	if i < 0 || i >= len(r.targets) {
		return r.cfg
	}
	return r.cfg.withRoute(r.targets[i].name, r.targets[i].cdn)
}

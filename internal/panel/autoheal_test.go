package panel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

func TestHealBackoffDoublesAndStopsAtThirtyMinutes(t *testing.T) {
	want := []time.Duration{0, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for failures, w := range want {
		if got := healBackoff(failures); got != w {
			t.Errorf("after %d failures: waited %v, want %v", failures, got, w)
		}
	}
}

// Two different pairs of servers can each have a tunnel with the same name.
// Their Auto-Heal settings must not be shared.
func TestAutoHealSettingsOfSameNamedTunnelsAreSeparate(t *testing.T) {
	tunnels := []tunnelView{
		{Name: "main", Edge: &half{ServerID: "tehran1"}, Origin: &half{ServerID: "f1"}},
		{Name: "main", Edge: &half{ServerID: "tehran2"}, Origin: &half{ServerID: "f2"}},
		{Name: "solo", Edge: &half{ServerID: "tehran1"}, Origin: &half{ServerID: "f1"}},
		{Name: "half", Edge: &half{ServerID: "tehran1"}}, // only one half in the panel
	}
	counts := healableNameCounts(tunnels)
	if counts["main"] != 2 || counts["solo"] != 1 || counts["half"] != 0 {
		t.Fatalf("counts: %v", counts)
	}

	st := State{AutoHeal: map[string]AutoHealConfig{
		"tehran1/main": {Enabled: true, CDNDomain: "a.example.com"},
		"solo":         {Enabled: true}, // saved before the key carried the relay
	}}
	if c, ok := resolveHealConfig(st, "tehran1", "main", counts); !ok || c.CDNDomain != "a.example.com" {
		t.Errorf("tehran1's main: %+v %v", c, ok)
	}
	if _, ok := resolveHealConfig(st, "tehran2", "main", counts); ok {
		t.Error("tehran2's main picked up tehran1's settings")
	}
	// An old bare-name entry still counts while the name is not shared...
	if c, ok := resolveHealConfig(st, "tehran1", "solo", counts); !ok || !c.Enabled {
		t.Errorf("old entry for a unique name was lost: %+v %v", c, ok)
	}
	// ...but not once two tunnels have it: nobody can say whose it is.
	st.AutoHeal["main"] = AutoHealConfig{Enabled: true}
	if _, ok := resolveHealConfig(st, "tehran2", "main", counts); ok {
		t.Error("an old bare-name entry was handed to one of two same-named tunnels")
	}
}

func TestLegacyAutoHealKeyIsMovedOnlyWhenTheNameIsUnique(t *testing.T) {
	st := &State{AutoHeal: map[string]AutoHealConfig{"solo": {Enabled: true, CDNDomain: "x.example.com"}}}
	moveLegacyHealKey(st, "tehran1", "solo", map[string]int{"solo": 1})
	if _, still := st.AutoHeal["solo"]; still {
		t.Error("the old entry was left behind")
	}
	if c := st.AutoHeal["tehran1/solo"]; !c.Enabled || c.CDNDomain != "x.example.com" {
		t.Errorf("not carried over: %+v", c)
	}

	st = &State{AutoHeal: map[string]AutoHealConfig{"main": {Enabled: true}}}
	moveLegacyHealKey(st, "tehran1", "main", map[string]int{"main": 2})
	if _, ok := st.AutoHeal["main"]; !ok || len(st.AutoHeal) != 1 {
		t.Errorf("an entry two tunnels could claim was moved: %v", st.AutoHeal)
	}
}

// Heals that need the same servers, in opposite orders, must not deadlock.
func TestLockServersInAnyOrderDoesNotDeadlock(t *testing.T) {
	ah := &autoHealer{serverMu: map[string]*sync.Mutex{}}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			unlock := ah.lockServers("a", "b")
			time.Sleep(time.Millisecond)
			unlock()
		}()
		go func() {
			defer wg.Done()
			unlock := ah.lockServers("b", "a", "a")
			time.Sleep(time.Millisecond)
			unlock()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heals waiting on each other's servers never finished")
	}
}

func blockedTunnel() tunnelView {
	live := &agent.TunnelLive{UptimeSeconds: 600, PathState: "blocked", PathNote: "test", Links: 1}
	return tunnelView{
		Name:   "main",
		Edge:   &half{ServerID: "e", Info: agent.TunnelInfo{Role: "edge", Running: true, Live: live}},
		Origin: &half{ServerID: "o", Info: agent.TunnelInfo{Role: "origin", Running: true, Live: live}},
	}
}

// After a failed heal the automatic attempt waits; it does not start again at the
// next check.
func TestAutoHealWaitsAfterAFailedAttempt(t *testing.T) {
	ah := &autoHealer{
		rt:       map[string]*tunnelHealRuntime{},
		slots:    make(chan struct{}, 2),
		serverMu: map[string]*sync.Mutex{},
	}
	key := "e/main"
	ah.rt[key] = &tunnelHealRuntime{state: "error", failCount: autoHealThreshold, failures: 1, nextTry: time.Now().Add(time.Minute)}
	ah.evaluateTunnel(context.Background(), blockedTunnel(), key, AutoHealConfig{Enabled: true})
	r := ah.rt[key]
	if r.running || r.state != "backoff" || len(ah.slots) != 0 {
		t.Fatalf("a heal started during the back-off: running=%v state=%q slots=%d", r.running, r.state, len(ah.slots))
	}
}

// With every slot busy, another unhealthy tunnel waits for the next check.
func TestAutoHealQueuesWhenOtherHealsFillTheSlots(t *testing.T) {
	ah := &autoHealer{
		rt:       map[string]*tunnelHealRuntime{},
		slots:    make(chan struct{}, 1),
		serverMu: map[string]*sync.Mutex{},
	}
	ah.slots <- struct{}{} // another heal is running
	key := "e/main"
	ah.rt[key] = &tunnelHealRuntime{state: "monitoring", failCount: autoHealThreshold}
	ah.evaluateTunnel(context.Background(), blockedTunnel(), key, AutoHealConfig{Enabled: true})
	r := ah.rt[key]
	if r.running || r.state != "queued" {
		t.Fatalf("it started anyway or did not say it was waiting: running=%v state=%q", r.running, r.state)
	}
}

// ---------------------------------------------------------------------------
// The switch itself, with servers that answer from a script.

type scripted struct {
	mu    sync.Mutex
	calls []string
	// failOn makes the call to (server, path[#stage]) fail. For update calls
	// the code sent is told apart: "update:new" or "update:old".
	failOn map[string]error
	// notOK answers with ok=false for a call.
	notOK map[string]bool
}

func (s *scripted) call(_ context.Context, id, path string, in, out any) (int, error) {
	key := id + path
	switch path {
	case "/api/tunnel/edit-edge":
		spec := in.(agent.EditSpec)
		key += "#" + spec.Stage
	case "/api/tunnel/update":
		code := in.(map[string]string)["code"]
		if code == "OLD" {
			key += "#old"
		} else {
			key += "#new"
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, key)
	s.mu.Unlock()
	if err := s.failOn[key]; err != nil {
		return 0, err
	}
	ok := !s.notOK[key]
	switch o := out.(type) {
	case *agent.EdgeResult:
		o.OK = ok
		o.Code = "NEW"
		o.OldConf = "name = main\n"
	case *struct {
		OK    bool   `json:"ok"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}:
		o.OK, o.Code = ok, "OLD"
	case *struct {
		OK       bool     `json:"ok"`
		Error    string   `json:"error"`
		Warnings []string `json:"warnings"`
	}:
		o.OK = ok
	case *struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}:
		o.OK = ok
	default:
		panic(fmt.Sprintf("unexpected reply type %T for %s", out, key))
	}
	return 200, nil
}

func (s *scripted) did(want string) bool {
	for _, c := range s.calls {
		if c == want {
			return true
		}
	}
	return false
}

func runSwitch(s *scripted) error {
	return switchBothHalves(context.Background(), s.call, func(string, ...any) {},
		"main", "R", "F", "Relay", "Foreign", "DIRECT · TLS · IPv4", 8443, agent.EditSpec{Name: "main"})
}

func TestSwitchSucceedsWithoutAnyRollback(t *testing.T) {
	s := &scripted{}
	if err := runSwitch(s); err != nil {
		t.Fatal(err)
	}
	if s.did("R/api/tunnel/edit-edge#rollback") || s.did("F/api/tunnel/update#old") {
		t.Fatalf("a good switch was rolled back: %v", s.calls)
	}
	for _, want := range []string{"R/api/tunnel/code", "R/api/tunnel/edit-edge#prepare", "F/api/tunnel/update#new", "R/api/tunnel/edit-edge#commit", "F/api/tunnel/service"} {
		if !s.did(want) {
			t.Errorf("never did %s: %v", want, s.calls)
		}
	}
}

// The foreign server may have applied the new settings even though the answer
// never came back. Both ends must go back, not just the relay.
func TestSwitchPutsBothBackWhenTheForeignAnswerNeverArrives(t *testing.T) {
	s := &scripted{failOn: map[string]error{"F/api/tunnel/update#new": errors.New("context deadline exceeded")}}
	err := runSwitch(s)
	if err == nil || !strings.Contains(err.Error(), "put back as they were") {
		t.Fatalf("error: %v", err)
	}
	if !s.did("R/api/tunnel/edit-edge#rollback") || !s.did("F/api/tunnel/update#old") {
		t.Fatalf("not both put back: %v", s.calls)
	}
	if s.did("R/api/tunnel/edit-edge#commit") {
		t.Fatalf("the relay was restarted on settings the foreign server may not have: %v", s.calls)
	}
}

// If the relay cannot restart on the new mode, the foreign server (already
// switched) must be put back too, or the tunnel stays broken.
func TestSwitchRestoresTheForeignServerWhenTheRelayCannotCommit(t *testing.T) {
	s := &scripted{notOK: map[string]bool{"R/api/tunnel/edit-edge#commit": true}}
	err := runSwitch(s)
	if err == nil {
		t.Fatal("a failed commit was reported as success")
	}
	if !s.did("F/api/tunnel/update#old") || !s.did("R/api/tunnel/edit-edge#rollback") {
		t.Fatalf("the foreign server was left on the new mode: %v", s.calls)
	}
}

func TestSwitchSaysSoWhenItCouldNotPutAServerBack(t *testing.T) {
	s := &scripted{
		failOn: map[string]error{
			"F/api/tunnel/update#new": errors.New("timed out"),
			"F/api/tunnel/update#old": errors.New("still unreachable"),
		},
	}
	err := runSwitch(s)
	if err == nil || !strings.Contains(err.Error(), "WARNING") || !strings.Contains(err.Error(), "Foreign could not be put back") {
		t.Fatalf("the failure to restore was not reported: %v", err)
	}
}

// If the current settings cannot be read, nothing may be changed: there would be
// nothing to go back to.
func TestSwitchChangesNothingWithoutTheCurrentSettings(t *testing.T) {
	s := &scripted{failOn: map[string]error{"R/api/tunnel/code": errors.New("unreachable")}}
	if err := runSwitch(s); err == nil {
		t.Fatal("it went ahead without being able to go back")
	}
	if len(s.calls) != 1 {
		t.Fatalf("it changed something anyway: %v", s.calls)
	}
}

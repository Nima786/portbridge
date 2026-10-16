package panel

import (
	"testing"

	"github.com/Nima786/portbridge/internal/agent"
)

func viewWith(id, name string, online bool, tunnels ...agent.TunnelInfo) serverView {
	return serverView{ID: id, Name: name, Online: online, Overview: &agent.Overview{Tunnels: tunnels}}
}

func TestHalvesArePairedByTheirPassword(t *testing.T) {
	servers := []serverView{
		viewWith("this", "Tehran", true,
			agent.TunnelInfo{Name: "shop", Role: "edge", PairID: "aaa"},
			agent.TunnelInfo{Name: "alone", Role: "edge", PairID: "bbb"}),
		viewWith("f1", "Aeza", true,
			agent.TunnelInfo{Name: "shop", Role: "origin", PairID: "aaa"},
			agent.TunnelInfo{Name: "other", Role: "origin", PairID: "ccc"}),
		viewWith("f2", "Down", false,
			agent.TunnelInfo{Name: "copy", Role: "origin", PairID: "aaa"}),
		{ID: "f3", Name: "never answered"},
	}
	got := pairTunnels(servers)
	byName := map[string]tunnelView{}
	for _, tv := range got {
		byName[tv.Name] = tv
	}
	if len(got) != 4 {
		t.Fatalf("want 4 tunnels, got %d: %+v", len(got), got)
	}
	shop := byName["shop"]
	if shop.Edge == nil || shop.Origin == nil || shop.Edge.ServerID != "this" || shop.Origin.ServerID != "f1" {
		t.Fatalf("the two halves of shop were not put together: %+v", shop)
	}
	// A third half with the same password cannot join a tunnel that already
	// has both; it is shown on its own.
	if c := byName["copy"]; c.Origin == nil || c.Edge != nil || !c.Stale {
		t.Fatalf("a spare half was not shown on its own, as out of date: %+v", c)
	}
	if a := byName["alone"]; a.Edge == nil || a.Origin != nil {
		t.Fatalf("a half with no partner: %+v", a)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Fatalf("not sorted by name: %v then %v", got[i-1].Name, got[i].Name)
		}
	}
}

func TestHalvesWithoutAPasswordAreNeverPaired(t *testing.T) {
	got := pairTunnels([]serverView{
		viewWith("a", "A", true, agent.TunnelInfo{Name: "x", Role: "edge"}),
		viewWith("b", "B", true, agent.TunnelInfo{Name: "x", Role: "origin"}),
	})
	if len(got) != 2 {
		t.Fatalf("two halves that cannot be told apart were paired: %+v", got)
	}
}

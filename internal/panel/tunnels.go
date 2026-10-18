package panel

// Putting the two halves of each tunnel together.
//
// Each server only knows its own half. The two halves of one tunnel share a
// password, and each reports the same short fingerprint of it, so halves with
// the same fingerprint are the same tunnel. A half whose other side is on a
// server the panel does not manage is shown on its own, and says so.

import (
	"sort"

	"github.com/Nima786/portbridge/internal/agent"
)

// half is one side of a tunnel and the server it is on.
type half struct {
	ServerID   string           `json:"server_id"`
	ServerName string           `json:"server_name"`
	Address    string           `json:"address"`
	Info       agent.TunnelInfo `json:"info"`
}

// tunnelView is one tunnel as the page draws it.
type tunnelView struct {
	Name   string `json:"name"`
	Edge   *half  `json:"edge,omitempty"`   // the relay (Iran) side
	Origin *half  `json:"origin,omitempty"` // the foreign side
	// Stale is set when a server's picture is old because it cannot be reached.
	Stale    bool            `json:"stale,omitempty"`
	AutoHeal *AutoHealConfig `json:"auto_heal,omitempty"`
}

func pairTunnels(servers []serverView) []tunnelView {
	byPair := map[string]*tunnelView{}
	var out []*tunnelView
	for _, s := range servers {
		if s.Overview == nil {
			continue
		}
		for _, ti := range s.Overview.Tunnels {
			h := &half{ServerID: s.ID, ServerName: s.Name, Address: s.Address, Info: ti}
			var tv *tunnelView
			if ti.PairID != "" {
				tv = byPair[ti.PairID]
			}
			// Two halves of the same role cannot be one tunnel, whatever their
			// fingerprints say.
			if tv != nil && ((ti.Role == "edge" && tv.Edge != nil) || (ti.Role != "edge" && tv.Origin != nil)) {
				tv = nil
			}
			if tv == nil {
				tv = &tunnelView{Name: ti.Name}
				out = append(out, tv)
				if ti.PairID != "" {
					byPair[ti.PairID] = tv
				}
			}
			if ti.Role == "edge" {
				tv.Edge = h
			} else {
				tv.Origin = h
			}
			if !s.Online {
				tv.Stale = true
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	res := make([]tunnelView, len(out))
	for i, t := range out {
		res[i] = *t
	}
	return res
}

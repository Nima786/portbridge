package panel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

// jsonCaller sends a JSON request to a server's agent and reads the answer. It is
// Panel.callJSON; a parameter so the switch below can be tested without servers.
type jsonCaller func(ctx context.Context, id, path string, in, out any) (int, error)

// switchBothHalves moves a tunnel to a new mode on both servers, and puts both
// back if anything goes wrong part-way. The relay's new settings are staged
// first, then the foreign server is switched, then the relay is restarted on
// them. Whatever fails after the foreign server was asked, it is asked to go back
// too: leaving it on the new mode while the relay returned to the old one would
// break the tunnel.
func switchBothHalves(ctx context.Context, call jsonCaller, say func(string, ...any),
	name, relayID, foreignID, relayName, foreignName, toDesc string, linkPort int, spec agent.EditSpec) error {
	// How the tunnel is set up now, kept so that if anything goes wrong part-way
	// both servers can be put back. Without it a failure after the foreign
	// server had already switched would leave the two ends on different modes.
	// Nothing has been changed yet, so failing to read it stops the heal here.
	var cur struct {
		OK    bool   `json:"ok"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if _, err := call(ctx, relayID, "/api/tunnel/code", map[string]string{"name": name}, &cur); err != nil {
		return fmt.Errorf("could not read the tunnel's current settings from %s, so nothing was changed: %s", relayName, plainAgentError(err))
	}
	if !cur.OK || cur.Code == "" {
		return fmt.Errorf("could not read the tunnel's current settings from %s, so nothing was changed: %s", relayName, cur.Error)
	}
	oldCode := cur.Code

	say("Preparing new configuration (%s on port %d) on %s...", toDesc, linkPort, relayName)
	spec.Stage = "prepare"
	var prep agent.EdgeResult
	status, err := call(ctx, relayID, "/api/tunnel/edit-edge", spec, &prep)
	if err != nil {
		return fmt.Errorf("%s could not prepare new mode: %s", relayName, plainAgentError(err))
	}
	if !prep.OK {
		if prep.Error == "" {
			prep.Error = fmt.Sprintf("HTTP %d", status)
		}
		return fmt.Errorf("%s rejected new mode: %s", relayName, prep.Error)
	}

	// restoreBoth puts the relay's old settings back and re-applies the old
	// code on the foreign server. It uses its own time limit, because the
	// heal's may already have run out, and says what it could and could not do.
	restoreBoth := func() string {
		rctx, rcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer rcancel()
		var problems []string
		var rb agent.EdgeResult
		if _, err := call(rctx, relayID, "/api/tunnel/edit-edge", agent.EditSpec{
			Name:    name,
			Stage:   "rollback",
			OldConf: prep.OldConf,
		}, &rb); err != nil || !rb.OK {
			problems = append(problems, relayName+" could not be put back automatically")
		}
		var back struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if _, err := call(rctx, foreignID, "/api/tunnel/update", map[string]string{"code": oldCode}, &back); err != nil || !back.OK {
			problems = append(problems, foreignName+" could not be put back automatically")
		}
		if len(problems) > 0 {
			return "WARNING: " + strings.Join(problems, " and ") + "; check both servers' tunnel settings"
		}
		return "both servers were put back as they were"
	}

	say("Applying new mode to %s (using active control channel)...", foreignName)
	var upd struct {
		OK       bool     `json:"ok"`
		Error    string   `json:"error"`
		Warnings []string `json:"warnings"`
	}
	_, uerr := call(ctx, foreignID, "/api/tunnel/update", map[string]string{"code": prep.Code}, &upd)
	if uerr == nil && !upd.OK {
		uerr = errors.New(upd.Error)
	}
	if uerr != nil {
		// A request that timed out may still have been carried out, so the
		// foreign server is put back as well as the relay.
		reason := plainAgentError(uerr)
		say("%s could not apply new mode (%s); putting both servers back...", foreignName, reason)
		return fmt.Errorf("%s could not switch modes: %s (%s)", foreignName, reason, restoreBoth())
	}

	say("Committing firewall rules and restarting %s...", relayName)
	var commit agent.EdgeResult
	cstatus, cerr := call(ctx, relayID, "/api/tunnel/edit-edge", agent.EditSpec{
		Name:    name,
		Stage:   "commit",
		OldConf: prep.OldConf,
	}, &commit)
	if cerr == nil && !commit.OK {
		if commit.Error == "" {
			commit.Error = fmt.Sprintf("HTTP %d", cstatus)
		}
		cerr = errors.New(commit.Error)
	}
	if cerr != nil {
		// The foreign server is already on the new mode; leaving it there while
		// the relay goes back would break the tunnel.
		reason := plainAgentError(cerr)
		say("%s could not restart on the new mode (%s); putting both servers back...", relayName, reason)
		return fmt.Errorf("%s could not restart on new mode: %s (%s)", relayName, reason, restoreBoth())
	}

	var reSync struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if _, err := call(ctx, foreignID, "/api/tunnel/service", map[string]string{
		"name":   name,
		"action": "restart",
	}, &reSync); err != nil || !reSync.OK {
		// The new settings were already applied and restarted there; this
		// restart only makes sure. Worth saying, not worth undoing.
		say("Note: %s did not confirm the final restart; the tunnel may need a moment to reconnect.", foreignName)
	}

	return nil
}

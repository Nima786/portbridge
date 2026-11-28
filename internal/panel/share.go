package panel

// Multi-panel server sharing: export a server's pinned agent link code
// (pbpanel://...) from one panel and import it into another panel without SSH.
//
// Because PortBridge agents (v0.17.79+) maintain independent callback loops for
// multiple panels simultaneously, importing a shared server into Panel #2 lets
// both Panel #1 and Panel #2 manage that server concurrently.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

const (
	panelSharePrefix       = "pbpanel://"
	firstMultiPanelVersion = "v0.17.79"
)

type serverSharePayload struct {
	V           int      `json:"v"`
	Name        string   `json:"n,omitempty"`
	Group       string   `json:"g,omitempty"`
	Address     string   `json:"a"`
	AgentURL    string   `json:"u"`
	Fingerprint string   `json:"f"`
	Token       string   `json:"t"`
	IPv6        []string `json:"v6,omitempty"`
}

func supportsMultiPanelVersion(v string) bool {
	if _, ok := parseVersion(v); !ok {
		return true
	}
	return compareVersions(v, firstMultiPanelVersion) >= 0
}

func encodeServerShare(sp serverSharePayload) (string, error) {
	sp.V = 1
	raw, err := json.Marshal(sp)
	if err != nil {
		return "", err
	}
	return panelSharePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeServerShare(raw string) (serverSharePayload, error) {
	var sp serverSharePayload
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "\"'`")
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, panelSharePrefix) {
		return sp, errors.New("invalid link code: it must start with pbpanel://")
	}
	enc := strings.TrimSpace(strings.TrimPrefix(s, panelSharePrefix))
	if enc == "" {
		return sp, errors.New("link code is empty")
	}
	data, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(enc)
		if err != nil {
			return sp, errors.New("could not decode link code; make sure you copied the full pbpanel:// string")
		}
	}
	if err := json.Unmarshal(data, &sp); err != nil {
		return sp, errors.New("link code is corrupted or incomplete")
	}
	if sp.V != 1 {
		return sp, fmt.Errorf("unsupported link code version (%d); update PortBridge on both panels", sp.V)
	}
	sp.Name = strings.TrimSpace(sp.Name)
	sp.Group = strings.TrimSpace(sp.Group)
	sp.Address = strings.TrimSpace(sp.Address)
	sp.AgentURL = strings.TrimSpace(sp.AgentURL)
	sp.Fingerprint = strings.TrimSpace(sp.Fingerprint)
	sp.Token = strings.TrimSpace(sp.Token)
	if sp.Address == "" || sp.AgentURL == "" || sp.Fingerprint == "" || sp.Token == "" {
		return sp, errors.New("link code is missing required server credentials")
	}
	u, err := url.Parse(sp.AgentURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return sp, errors.New("link code has an invalid agent HTTPS address")
	}
	if u.Path != "" && u.Path != "/" {
		return sp, errors.New("link code has an invalid agent URL path")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return sp, errors.New("link code is missing a valid agent host and port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return sp, errors.New("link code has an invalid agent port")
	}
	sp.AgentURL = "https://" + net.JoinHostPort(host, strconv.Itoa(port))

	var cleanV6 []string
	for _, v6 := range sp.IPv6 {
		v6 = strings.TrimSpace(v6)
		if ip := net.ParseIP(v6); ip != nil && ip.To4() == nil {
			if !slices.Contains(cleanV6, v6) {
				cleanV6 = append(cleanV6, v6)
			}
		}
	}
	sp.IPv6 = cleanV6
	return sp, nil
}

// handleShareServer exports a pbpanel:// link code for an already-managed
// server (or this panel host when its standalone agent is configured) so
// another PortBridge panel can add it without SSH credentials.
func (p *Panel) handleShareServer(w http.ResponseWriter, r *http.Request, _ authed) {
	id := strings.TrimSpace(r.PathValue("id"))
	var sp serverSharePayload

	if id == "this" {
		port, tok, fp, err := agent.ReadLocalAgentShareInfo(p.localAgentConf)
		if err != nil {
			writeErr(w, http.StatusBadRequest,
				"This panel host does not have a standalone management agent enabled yet. "+
					"To add this server to another panel, run 'portbridge agent setup' on it or use the 1-Line Join Command on the other panel.")
			return
		}
		st := p.store.get()
		ov := agent.LocalOverview(p.tunnelsDir)
		addr := ""
		if len(ov.IPv4) > 0 {
			addr = ov.IPv4[0]
		} else if len(ov.IPv6) > 0 {
			addr = ov.IPv6[0]
		} else if dom := p.getConfig().Domain; dom != "" {
			addr = dom
		} else if pu, perr := url.Parse(p.publicURL()); perr == nil && pu.Hostname() != "" {
			addr = pu.Hostname()
		}
		if addr == "" {
			writeErr(w, http.StatusBadRequest, "Could not determine this server's public IP address or domain.")
			return
		}
		name := st.ThisName
		if name == "" {
			name = ov.Hostname
		}
		if name == "" {
			name = addr
		}
		sp = serverSharePayload{
			V:           1,
			Name:        name,
			Group:       st.ThisGroup,
			Address:     addr,
			AgentURL:    "https://" + net.JoinHostPort(addr, strconv.Itoa(port)),
			Fingerprint: fp,
			Token:       tok,
			IPv6:        append([]string(nil), ov.IPv6...),
		}
	} else {
		srv, ok := p.serverByID(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "That server is not in the panel.")
			return
		}
		tok, err := p.store.open(srv.TokenEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "Could not read that server's agent token.")
			return
		}
		sp = serverSharePayload{
			V:           1,
			Name:        srv.Name,
			Group:       srv.Group,
			Address:     srv.Address,
			AgentURL:    srv.AgentURL,
			Fingerprint: srv.Fingerprint,
			Token:       tok,
			IPv6:        append([]string(nil), srv.IPv6...),
		}
	}

	code, err := encodeServerShare(sp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Could not generate link code: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"code":    code,
		"name":    sp.Name,
		"address": sp.Address,
		"group":   sp.Group,
	})
}

// handleLinkServer imports a pbpanel:// link code exported from another
// PortBridge panel, verifies live connectivity to the pinned agent without SSH,
// registers this panel's standby callback alongside any existing panels, and
// saves the server.
func (p *Panel) handleLinkServer(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Code      string `json:"code"`
		Name      string `json:"name"`
		Group     string `json:"group"`
		ViaServer string `json:"via_server"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	sp, err := decodeServerShare(req.Code)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}

	group := strings.TrimSpace(req.Group)
	if group == "" {
		group = sp.Group
	}
	if !validGroup(group) {
		writeErr(w, http.StatusBadRequest, "Choose whether this is a Relay (Iran) or Foreign server.")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = sp.Name
	}
	if len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "The server name can be at most 64 characters.")
		return
	}

	// Refuse linking this panel's own public IP back to itself.
	if ip := net.ParseIP(sp.Address); ip != nil && !ip.IsLoopback() {
		v4, v6 := agent.PublicAddresses()
		if slices.Contains(v4, sp.Address) || slices.Contains(v6, sp.Address) {
			writeErr(w, http.StatusBadRequest, "That link code belongs to this panel's own server, which is already here.")
			return
		}
	}

	for _, existing := range p.store.get().Servers {
		if strings.EqualFold(existing.Address, sp.Address) || strings.EqualFold(existing.AgentURL, sp.AgentURL) {
			writeErr(w, http.StatusConflict, fmt.Sprintf("%s is already in this panel as %q.", sp.Address, existing.Name))
			return
		}
	}

	tokEnc, err := p.store.seal(sp.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Could not encrypt the server's agent token.")
		return
	}

	srv := Server{
		ID:          newID(9),
		Name:        name,
		Group:       group,
		Address:     sp.Address,
		IPv6:        append([]string(nil), sp.IPv6...),
		AgentURL:    sp.AgentURL,
		Fingerprint: sp.Fingerprint,
		TokenEnc:    tokEnc,
		Added:       time.Now().UTC(),
	}

	via := strings.TrimSpace(req.ViaServer)
	var ov *agent.Overview
	var connErr error
	switch {
	case via == "direct":
		ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
		ov, connErr = p.fleet.overview(withNoJump(ctx), srv)
		cancel()
	case via != "" && via != "auto":
		ov, _, connErr = p.tryJumpOverview(srv, via)
		if connErr == nil {
			srv.JumpAllowed = true
		}
	default:
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 {
				time.Sleep(500 * time.Millisecond)
			}
			ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
			ov, connErr = p.fleet.overview(ctx, srv)
			cancel()
			if connErr == nil {
				break
			}
			// Do not retry auth or certificate mismatch errors.
			if strings.Contains(connErr.Error(), "fingerprint") || strings.Contains(connErr.Error(), "token") {
				break
			}
		}
		if connErr == nil {
			if _, _, _, jumpID := p.fleet.preferredPath(srv.ID); jumpID != "" {
				srv.JumpAllowed = true
			}
		}
	}

	if connErr != nil || ov == nil {
		p.fleet.forget(srv.ID)
		plain := plainAgentError(connErr)
		if strings.Contains(connErr.Error(), "fingerprint") || strings.Contains(connErr.Error(), "token") {
			writeErr(w, http.StatusBadRequest,
				"Could not link "+sp.Address+": "+plain+" Export a fresh Share Link Code from the other panel and try again.")
			return
		}
		writeErr(w, http.StatusBadGateway,
			fmt.Sprintf("Could not reach %s from this panel (%s). If its agent port is blocked or firewalled from here, "+
				"use the 1-Line Join Command on that server instead — PortBridge supports multiple panels simultaneously, so other panels stay connected.",
				sp.Address, plain))
		return
	}

	if len(ov.IPv6) > 0 {
		srv.IPv6 = append([]string(nil), ov.IPv6...)
	}
	if srv.Name == "" {
		srv.Name = strings.TrimSpace(ov.Hostname)
	}
	if srv.Name == "" {
		srv.Name = srv.Address
	}

	multiPanel := supportsMultiPanelVersion(ov.Version)
	var note string
	if multiPanel {
		if cbURLs, fp := p.allCallbackURLs(), p.ownFingerprint(); cbURLs != "" && fp != "" {
			cctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			body, _ := json.Marshal(map[string]string{
				"panel_url":         cbURLs,
				"panel_fingerprint": fp,
			})
			status, _, cerr := p.fleet.call(cctx, srv, http.MethodPost, "/api/callhome", body)
			cancel()
			if cerr == nil && status == http.StatusOK {
				srv.StandbyHub = true
			}
		}
	} else {
		note = fmt.Sprintf("Linked directly (%s). Update PortBridge on this server to %s+ so it can also maintain simultaneous standby callbacks to multiple panels.",
			ov.Version, firstMultiPanelVersion)
	}

	var dupName string
	err = p.store.update(func(st *State) error {
		for _, existing := range st.Servers {
			if strings.EqualFold(existing.Address, srv.Address) || strings.EqualFold(existing.AgentURL, srv.AgentURL) {
				dupName = existing.Name
				return errors.New("duplicate")
			}
		}
		st.Servers = append(st.Servers, srv)
		return nil
	})
	if err != nil {
		p.fleet.forget(srv.ID)
		if dupName != "" {
			writeErr(w, http.StatusConflict, fmt.Sprintf("%s is already in this panel as %q.", srv.Address, dupName))
			return
		}
		writeErr(w, http.StatusInternalServerError, "Could not save linked server: "+err.Error())
		return
	}

	p.fleet.mu.Lock()
	h := p.fleet.by[srv.ID]
	if h == nil {
		h = &heard{}
		p.fleet.by[srv.ID] = h
	}
	h.overview = ov
	h.err = nil
	h.at = time.Now()
	h.tried = h.at
	h.seededHome = srv.StandbyHub || !multiPanel
	p.fleet.mu.Unlock()

	logf("linked server %q (%s) from another panel without SSH", srv.Name, srv.Address)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"server_id": srv.ID,
		"name":      srv.Name,
		"address":   srv.Address,
		"group":     srv.Group,
		"tunnels":   len(ov.Tunnels),
		"version":   ov.Version,
		"note":      note,
	})
}

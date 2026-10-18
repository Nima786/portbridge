package panel

// What the panel's page asks of it, and the rules every request goes through.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

const (
	cookieName = "__Host-pb_session"
	csrfHeader = "X-PB-CSRF"
	apiBodyMax = 1 << 20
	// An agent's answer can carry a release it downloaded for the panel.
	hubBodyMax = agent.HubBodyLimit
)

// The page loads nothing from anywhere else and runs no script that is not one
// of its own files, so a value that somehow got into the page could not run.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func (p *Panel) routes() http.Handler {
	mux := http.NewServeMux()

	static := staticHandler()
	mux.Handle("GET /{$}", static)
	mux.Handle("GET /app.js", static)
	mux.Handle("GET /app.css", static)
	mux.Handle("GET /icon.svg", static)

	mux.HandleFunc("GET /hub/poll", p.hub.handlePoll)
	mux.HandleFunc("POST /hub/reply", p.hub.handleReply)
	mux.HandleFunc("GET /hub/release/{id}", p.handleRelease)

	mux.HandleFunc("POST /api/login", p.handleLogin)
	mux.HandleFunc("POST /api/logout", p.withAuth(p.handleLogout))
	mux.HandleFunc("GET /api/me", p.withAuth(p.handleMe))
	mux.HandleFunc("POST /api/account", p.withAuth(p.handleAccount))
	mux.HandleFunc("GET /api/servers", p.withAuth(p.handleServers))
	mux.HandleFunc("POST /api/servers", p.withAuth(p.handleAddServer))
	mux.HandleFunc("PATCH /api/servers/{id}", p.withAuth(p.handleEditServer))
	mux.HandleFunc("DELETE /api/servers/{id}", p.withAuth(p.handleRemoveServer))
	mux.HandleFunc("GET /api/jobs/{id}", p.withAuth(p.handleJob))
	mux.HandleFunc("GET /api/tunnels", p.withAuth(p.handleTunnels))
	mux.HandleFunc("POST /api/tunnels", p.withAuth(p.handleCreateTunnel))
	mux.HandleFunc("POST /api/tunnels/edit", p.withAuth(p.handleEditTunnel))
	mux.HandleFunc("POST /api/tunnels/delete", p.withAuth(p.handleDeleteTunnel))
	mux.HandleFunc("POST /api/tunnels/service", p.withAuth(p.handleServiceTunnel))
	mux.HandleFunc("POST /api/tunnels/code", p.withAuth(p.handleTunnelCode))
	mux.HandleFunc("POST /api/tunnels/logs", p.withAuth(p.handleTunnelLogs))
	mux.HandleFunc("POST /api/tunnels/check", p.withAuth(p.handleCheckTunnel))
	mux.HandleFunc("POST /api/tunnels/speedtest", p.withAuth(p.handleSpeedtestTunnel))
	mux.HandleFunc("POST /api/tunnels/probe", p.withAuth(p.handleProbeTunnel))
	mux.HandleFunc("POST /api/tunnels/autoheal", p.withAuth(p.handleSetTunnelAutoHeal))
	mux.HandleFunc("POST /api/tunnels/autoheal/trigger", p.withAuth(p.handleTriggerTunnelAutoHeal))
	mux.HandleFunc("POST /api/ports", p.withAuth(p.handlePorts))
	mux.HandleFunc("GET /api/servers/{id}/tune", p.withAuth(p.handleGetServerTune))
	mux.HandleFunc("POST /api/servers/{id}/tune", p.withAuth(p.handleSetServerTune))
	mux.HandleFunc("GET /api/servers/{id}/firewall", p.withAuth(p.handleGetServerFirewall))
	mux.HandleFunc("POST /api/servers/{id}/firewall", p.withAuth(p.handleSetServerFirewall))
	mux.HandleFunc("GET /api/updates", p.withAuth(p.handleUpdates))
	mux.HandleFunc("POST /api/updates", p.withAuth(p.handleStartUpdate))
	mux.HandleFunc("POST /api/updates/check", p.withAuth(p.handleCheckUpdates))
	mux.HandleFunc("POST /api/servers/{id}/ssh-update", p.withAuth(p.handleSSHUpdate))
	mux.HandleFunc("GET /api/panel", p.withAuth(p.handlePanelInfo))

	mux.HandleFunc("GET /api/cf/accounts", p.withAuth(p.handleGetCFAccounts))
	mux.HandleFunc("POST /api/cf/accounts", p.withAuth(p.handleAddCFAccount))
	mux.HandleFunc("DELETE /api/cf/accounts/{id}", p.withAuth(p.handleDeleteCFAccount))
	mux.HandleFunc("GET /api/cf/zones", p.withAuth(p.handleGetCFZones))
	mux.HandleFunc("GET /api/cf/zones/{zoneID}/records", p.withAuth(p.handleGetCFRecords))
	mux.HandleFunc("POST /api/cf/zones/{zoneID}/records", p.withAuth(p.handleCreateCFRecord))
	mux.HandleFunc("PUT /api/cf/zones/{zoneID}/records/{recordID}", p.withAuth(p.handleUpdateCFRecord))
	mux.HandleFunc("PATCH /api/cf/zones/{zoneID}/records/{recordID}", p.withAuth(p.handlePatchCFRecord))
	mux.HandleFunc("DELETE /api/cf/zones/{zoneID}/records/{recordID}", p.withAuth(p.handleDeleteCFRecord))

	mux.HandleFunc("POST /api/backup/create", p.withAuth(p.handleBackupCreate))
	mux.HandleFunc("POST /api/backup/inspect", p.withAuth(p.handleBackupInspect))
	mux.HandleFunc("POST /api/backup/restore", p.withAuth(p.handleBackupRestore))

	return secureHeaders(mux)
}

// secureHeaders adds what every answer carries, and caps how much can be sent.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/backup/"):
			h.Set("Cache-Control", "no-store")
			r.Body = http.MaxBytesReader(w, r.Body, backupMaxBytes)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			h.Set("Cache-Control", "no-store")
			r.Body = http.MaxBytesReader(w, r.Body, apiBodyMax)
		case strings.HasPrefix(r.URL.Path, "/hub/"):
			h.Set("Cache-Control", "no-store")
			r.Body = http.MaxBytesReader(w, r.Body, hubBodyMax)
		}
		next.ServeHTTP(w, r)
	})
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	types := map[string]string{
		".html": "text/html; charset=utf-8",
		".js":   "text/javascript; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".svg":  "image/svg+xml",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if name == "index.html" && engine.Version != "" {
			ver := url.QueryEscape(engine.Version)
			html := string(data)
			html = strings.Replace(html, `href="app.css"`, `href="app.css?v=`+ver+`"`, 1)
			html = strings.Replace(html, `src="app.js"`, `src="app.js?v=`+ver+`"`, 1)
			data = []byte(html)
		}
		w.Header().Set("Content-Type", types[path.Ext(name)])
		// Always checked again, so an update shows at once.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		_, _ = w.Write(data)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a JSON body. Only JSON is accepted: an ordinary form on
// another site cannot send it, which is one more thing standing between such a
// site and the panel.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "The request must be JSON.")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "That is too much to send at once.")
		} else {
			writeErr(w, http.StatusBadRequest, "The request could not be read.")
		}
		return false
	}
	return true
}

// sameOrigin says whether a request came from the panel's own page, as far as
// the browser says. A request with neither header is not from a browser page.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type authed struct {
	id string
	s  *session
}

// withAuth lets a request through only with a live session, and, for anything
// that changes something, only from the panel's own page with the session's
// anti-forgery token.
func (p *Panel) withAuth(h func(http.ResponseWriter, *http.Request, authed)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var a authed
		if c, err := r.Cookie(cookieName); err == nil {
			a.id = c.Value
			a.s = p.sessions.lookup(c.Value)
		}
		if a.s == nil {
			writeErr(w, http.StatusUnauthorized, "Please log in.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			tok := r.Header.Get(csrfHeader)
			if !sameOrigin(r) || tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.s.csrf)) != 1 {
				writeErr(w, http.StatusForbidden, "This request did not come from the panel's own page. Reload the page and try again.")
				return
			}
		}
		h(w, r, a)
	}
}

func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(sessionLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// checkLogin compares a username and password with the account's. The password
// is always checked, even for a wrong username, so the time taken does not say
// which of the two was wrong.
func (p *Panel) checkLogin(user, pw string) bool {
	admin := p.store.get().Admin
	if len(pw) > maxPasswordLen || len(user) > maxUsernameLen {
		return false
	}
	p.loginSem <- struct{}{}
	pwOK := checkPassword(pw, admin.Hash)
	<-p.loginSem
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(admin.User)) == 1
	return pwOK && userOK && admin.Hash != ""
}

func lockedMessage(wait time.Duration) string {
	m := int(math.Ceil(wait.Minutes()))
	if m <= 1 {
		return "Too many wrong tries. Try again in a minute."
	}
	return fmt.Sprintf("Too many wrong tries. Try again in %d minutes.", m)
}

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "This request did not come from the panel's own page.")
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := clientIP(r)
	if locked, wait := p.sessions.locked(ip); locked {
		writeErr(w, http.StatusTooManyRequests, lockedMessage(wait))
		return
	}
	if !p.checkLogin(strings.TrimSpace(req.User), req.Password) {
		time.Sleep(failureDelay)
		p.sessions.failed(ip)
		logf("wrong login from %s", ip)
		if locked, wait := p.sessions.locked(ip); locked {
			writeErr(w, http.StatusTooManyRequests, lockedMessage(wait))
			return
		}
		writeErr(w, http.StatusUnauthorized, "Wrong username or password.")
		return
	}
	p.sessions.succeeded(ip)
	id, s := p.sessions.create(p.store.get().Admin.User)
	setSessionCookie(w, id)
	logf("logged in from %s", ip)
	writeJSON(w, http.StatusOK, map[string]string{"user": s.user, "csrf": s.csrf, "version": engine.Version})
}

func (p *Panel) handleLogout(w http.ResponseWriter, _ *http.Request, a authed) {
	p.sessions.end(a.id)
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *Panel) handleMe(w http.ResponseWriter, _ *http.Request, a authed) {
	writeJSON(w, http.StatusOK, map[string]string{"user": a.s.user, "csrf": a.s.csrf, "version": engine.Version})
}

func (p *Panel) handleAccount(w http.ResponseWriter, r *http.Request, a authed) {
	var req struct {
		Current     string `json:"current_password"`
		NewUser     string `json:"new_user"`
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := clientIP(r)
	if locked, wait := p.sessions.locked(ip); locked {
		writeErr(w, http.StatusTooManyRequests, lockedMessage(wait))
		return
	}
	admin := p.store.get().Admin
	if !p.checkLogin(admin.User, req.Current) {
		time.Sleep(failureDelay)
		p.sessions.failed(ip)
		writeErr(w, http.StatusForbidden, "The current password is wrong.")
		return
	}
	user := strings.TrimSpace(req.NewUser)
	if user == "" {
		user = admin.User
	}
	hash := admin.Hash
	if req.NewPassword != "" {
		if err := checkNewCredentials(user, req.NewPassword); err != nil {
			writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
			return
		}
		h, err := hashPassword(req.NewPassword)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "The new password could not be saved.")
			return
		}
		hash = h
	} else if err := checkUsername(user); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	if err := p.store.update(func(st *State) error {
		st.Admin = Admin{User: user, Hash: hash}
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "The change could not be saved: "+err.Error())
		return
	}
	// Everyone else is logged out; this browser carries on with a new session.
	p.sessions.endAll()
	id, s := p.sessions.create(user)
	setSessionCookie(w, id)
	logf("the login was changed, from %s", ip)
	writeJSON(w, http.StatusOK, map[string]string{"user": s.user, "csrf": s.csrf})
}

func (p *Panel) handleServers(w http.ResponseWriter, _ *http.Request, _ authed) {
	writeJSON(w, http.StatusOK, map[string]any{"servers": p.fleet.views()})
}

func (p *Panel) handleAddServer(w http.ResponseWriter, r *http.Request, _ authed) {
	var req addRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := p.startAdd(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": id})
}

func (p *Panel) handleJob(w http.ResponseWriter, r *http.Request, _ authed) {
	p.jobsMu.Lock()
	j := p.jobs[r.PathValue("id")]
	p.jobsMu.Unlock()
	if j == nil {
		writeErr(w, http.StatusNotFound, "That job is not known; the panel may have restarted.")
		return
	}
	writeJSON(w, http.StatusOK, j.view())
}

func (p *Panel) handleEditServer(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Name  *string `json:"name"`
		Group *string `json:"group"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	var name, group string
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
		if len(name) > 64 {
			writeErr(w, http.StatusBadRequest, "The name can be at most 64 characters.")
			return
		}
		if name == "" && id != "this" {
			writeErr(w, http.StatusBadRequest, "Give it a name.")
			return
		}
	}
	if req.Group != nil {
		group = *req.Group
		if !validGroup(group) && !(id == "this" && group == "") {
			writeErr(w, http.StatusBadRequest, "The group must be relay or foreign.")
			return
		}
	}
	err := p.store.update(func(st *State) error {
		if id == "this" {
			if req.Name != nil {
				st.ThisName = name
			}
			if req.Group != nil {
				st.ThisGroup = group
			}
			return nil
		}
		for i := range st.Servers {
			if st.Servers[i].ID == id {
				if req.Name != nil {
					st.Servers[i].Name = name
				}
				if req.Group != nil {
					st.Servers[i].Group = group
				}
				return nil
			}
		}
		return errNoServer
	})
	switch {
	case errors.Is(err, errNoServer):
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "The change could not be saved: "+err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

var errNoServer = errors.New("no such server")

func (p *Panel) handleRemoveServer(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	if id == "this" {
		writeErr(w, http.StatusBadRequest, "The panel's own server cannot be removed from it.")
		return
	}
	var gone Server
	err := p.store.update(func(st *State) error {
		for i, s := range st.Servers {
			if s.ID == id {
				gone = s
				st.Servers = append(st.Servers[:i], st.Servers[i+1:]...)
				return nil
			}
		}
		return errNoServer
	})
	switch {
	case errors.Is(err, errNoServer):
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "It could not be removed: "+err.Error())
	default:
		p.fleet.forget(id)
		logf("removed %q (%s) from the panel", gone.Name, gone.Address)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (p *Panel) handleTunnels(w http.ResponseWriter, _ *http.Request, _ authed) {
	tunnels := pairTunnels(p.fleet.views())
	p.healer.attachViews(tunnels)
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": tunnels})
}

func (p *Panel) handlePanelInfo(w http.ResponseWriter, _ *http.Request, _ authed) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     engine.Version,
		"listen":      p.cfg.Listen,
		"addresses":   p.addresses(),
		"public_url":  p.publicURL(),
		"fingerprint": p.ownFingerprint(),
		"certificate": p.certStatus(),
	})
}

func (p *Panel) handleCreateTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := p.startCreate(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": id})
}

// knownTarget refuses a tunnel whose servers are not in the panel.
func (p *Panel) knownTarget(t tunnelTarget) error {
	if err := checkTunnelName(t.Name); err != nil {
		return err
	}
	if len(t.servers()) == 0 {
		return errors.New("say which servers the tunnel is on")
	}
	for _, id := range t.servers() {
		if _, ok := p.viewOf(id); !ok {
			return errors.New("one of those servers is not in the panel")
		}
	}
	return nil
}

func checkTunnelName(name string) error {
	if name == "" || len(name) > 40 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return errors.New("that is not a tunnel name")
	}
	return nil
}

func (p *Panel) handleDeleteTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var t tunnelTarget
	if !decodeJSON(w, r, &t) {
		return
	}
	if err := p.knownTarget(t); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": p.deleteTunnel(t)})
}

func (p *Panel) handleServiceTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		tunnelTarget
		Action string `json:"action"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := p.knownTarget(req.tunnelTarget); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	switch req.Action {
	case "start", "stop", "restart":
	default:
		writeErr(w, http.StatusBadRequest, "The action must be start, stop or restart.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": p.serviceTunnel(req.tunnelTarget, req.Action)})
}

func (p *Panel) handleTunnelCode(w http.ResponseWriter, r *http.Request, _ authed) {
	var t tunnelTarget
	if !decodeJSON(w, r, &t) {
		return
	}
	if t.Edge == "" {
		writeErr(w, http.StatusBadRequest, "Codes are made on the relay (Iran) server, which is not in the panel for this tunnel.")
		return
	}
	if err := p.knownTarget(t); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	code, err := p.tunnelCode(t.Edge, t.Name)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (p *Panel) handlePorts(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Server string `json:"server"`
		Ports  string `json:"ports"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, ok := p.viewOf(req.Server); !ok {
		writeErr(w, http.StatusBadRequest, "That server is not in the panel.")
		return
	}
	ports := intsOf(req.Ports)
	if len(ports) == 0 || len(ports) > 32 {
		writeErr(w, http.StatusBadRequest, "Give from 1 to 32 ports.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), agentTimeout)
	defer cancel()
	st, err := p.portsThere(ctx, req.Server, ports)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	out := make([]portState, 0, len(ports))
	for _, n := range ports {
		out = append(out, st[n])
	}
	writeJSON(w, http.StatusOK, map[string]any{"ports": out})
}

func (p *Panel) handleUpdates(w http.ResponseWriter, _ *http.Request, _ authed) {
	writeJSON(w, http.StatusOK, p.updates.status())
}

func (p *Panel) handleCheckUpdates(w http.ResponseWriter, r *http.Request, _ authed) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	p.updates.check(ctx)
	writeJSON(w, http.StatusOK, p.updates.status())
}

func (p *Panel) handleStartUpdate(w http.ResponseWriter, _ *http.Request, _ authed) {
	writeJSON(w, http.StatusAccepted, map[string]string{"job": p.updates.start()})
}

func (p *Panel) handleSSHUpdate(w http.ResponseWriter, r *http.Request, _ authed) {
	srv, ok := p.serverByID(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
		return
	}
	var req addRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Password == "" && strings.TrimSpace(req.PrivateKey) == "" {
		writeErr(w, http.StatusBadRequest, "Give the server's password, or its private key.")
		return
	}
	id := p.startJob(func(j *job) (string, error) { return srv.ID, p.sshUpdate(j, srv, req) })
	writeJSON(w, http.StatusAccepted, map[string]string{"job": id})
}

func (p *Panel) handleEditTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var req editTunnelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id, err := p.startEditTunnel(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": id})
}

func (p *Panel) handleTunnelLogs(w http.ResponseWriter, r *http.Request, _ authed) {
	var t tunnelTarget
	if !decodeJSON(w, r, &t) {
		return
	}
	if err := p.knownTarget(t); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": p.tunnelLogs(r.Context(), t)})
}

func (p *Panel) handleCheckTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var t tunnelTarget
	if !decodeJSON(w, r, &t) {
		return
	}
	if err := p.knownTarget(t); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": p.checkTunnel(r.Context(), t)})
}

func (p *Panel) handleSpeedtestTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	var t tunnelTarget
	if !decodeJSON(w, r, &t) {
		return
	}
	if err := p.knownTarget(t); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	srvName, out, err := p.speedtestTunnel(r.Context(), t)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok":     false,
			"server": srvName,
			"output": out,
			"error":  capitalise(plainAgentError(err)) + ".",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"server": srvName,
		"output": out,
	})
}

func (p *Panel) handleProbeTunnel(w http.ResponseWriter, r *http.Request, _ authed) {
	agent.ExtendDeadlines(w, 3*time.Minute)
	var req struct {
		Action    string                        `json:"action"`
		Relay     string                        `json:"relay"`
		Foreign   string                        `json:"foreign"`
		CDNDomain string                        `json:"cdn_domain"`
		DialerID  string                        `json:"dialer_id"`
		Secret    string                        `json:"secret"`
		Spec      engine.ProbeCandidateSpec     `json:"spec"`
		Session   probeSession                  `json:"session"`
		Results   []engine.ProbeCandidateResult `json:"results"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.Action {
	case "start":
		sess, err := p.startProbeSession(r.Context(), strings.TrimSpace(req.Relay), strings.TrimSpace(req.Foreign), strings.TrimSpace(req.CDNDomain))
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, capitalise(plainAgentError(err))+".")
			return
		}
		writeJSON(w, http.StatusOK, sess)
	case "step":
		res, err := p.runProbeStep(r.Context(), strings.TrimSpace(req.DialerID), strings.TrimSpace(req.Secret), req.Spec)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, capitalise(plainAgentError(err))+".")
			return
		}
		writeJSON(w, http.StatusOK, res)
	case "finish":
		rep := p.finishProbeSession(req.Session, req.Results)
		writeJSON(w, http.StatusOK, rep)
	default:
		rep, err := p.probeBetweenServers(r.Context(), strings.TrimSpace(req.Relay), strings.TrimSpace(req.Foreign), strings.TrimSpace(req.CDNDomain))
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, capitalise(plainAgentError(err))+".")
			return
		}
		writeJSON(w, http.StatusOK, rep)
	}
}

func (p *Panel) handleSetTunnelAutoHeal(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Name      string `json:"name"`
		Enabled   bool   `json:"enabled"`
		CDNDomain string `json:"cdn_domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if err := checkTunnelName(name); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	if err := p.healer.setConfig(name, req.Enabled, req.CDNDomain); err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleTriggerTunnelAutoHeal(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Name      string `json:"name"`
		Edge      string `json:"edge"`
		Origin    string `json:"origin"`
		CDNDomain string `json:"cdn_domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	jobID, err := p.healer.startManualHeal(strings.TrimSpace(req.Name), strings.TrimSpace(req.Edge), strings.TrimSpace(req.Origin), strings.TrimSpace(req.CDNDomain))
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job": jobID})
}

func (p *Panel) handleGetServerTune(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	if _, ok := p.viewOf(id); !ok {
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
		return
	}
	info, err := p.getServerTune(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (p *Panel) handleSetServerTune(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	if _, ok := p.viewOf(id); !ok {
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	info, err := p.setServerTune(r.Context(), id, req.Enable)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	p.refreshOne(id)
	writeJSON(w, http.StatusOK, info)
}

func (p *Panel) handleGetServerFirewall(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	if _, ok := p.viewOf(id); !ok {
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
		return
	}
	info, err := p.getServerFirewall(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (p *Panel) handleSetServerFirewall(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	if _, ok := p.viewOf(id); !ok {
		writeErr(w, http.StatusNotFound, "That server is not in the panel.")
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.Action {
	case "sweep", "on-all", "off-all":
	default:
		writeErr(w, http.StatusBadRequest, "The firewall action must be sweep, on-all or off-all.")
		return
	}
	info, err := p.setServerFirewall(r.Context(), id, req.Action)
	if err != nil {
		writeErr(w, http.StatusBadGateway, capitalise(plainAgentError(err))+".")
		return
	}
	p.refreshOne(id)
	writeJSON(w, http.StatusOK, info)
}

// capitalise starts a message with a capital letter, for showing on its own.
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

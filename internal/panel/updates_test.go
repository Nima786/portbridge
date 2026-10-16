package panel

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

// fakeAgent is a server's agent that can be updated: after an update it reports
// the new version, as a real one does once its installer has run.
type fakeAgent struct {
	mu        sync.Mutex
	version   string
	githubOK  bool   // it can download releases itself
	gotSent   bool   // the panel sent it the release
	refuse    int    // answer /api/update with this status
	noUpdates bool   // too old: no /api/update at all
	lastAsked string // the version it was asked for
	cutEvery  int    // drop every n-th part, as a network that cuts transfers does
	partsSeen int
	parts     map[int][]byte
	gotPulled bool // it downloaded the release from the panel
}

// pull downloads a release the panel offers, as a real agent does.
func pull(url, token, want string) bool {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == http.StatusOK && sha256Hex(b) == want
}

func (f *fakeAgent) handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/api/overview":
			_ = json.NewEncoder(w).Encode(agent.Overview{OK: true, Version: f.version, Arch: "amd64"})
		case "/api/update/part":
			var p agent.UpdatePart
			_ = json.NewDecoder(r.Body).Decode(&p)
			f.partsSeen++
			if f.cutEvery > 0 && f.partsSeen%f.cutEvery == 0 {
				// Cut the connection, as a filtered link does.
				hj, _ := w.(http.Hijacker)
				c, _, _ := hj.Hijack()
				_ = c.Close()
				return
			}
			if f.parts == nil {
				f.parts = map[int][]byte{}
			}
			f.parts[p.Index] = p.Data
			_ = json.NewEncoder(w).Encode(agent.UpdateResult{OK: true})
		case "/api/update":
			if f.noUpdates {
				http.NotFound(w, r)
				return
			}
			if f.refuse != 0 {
				w.WriteHeader(f.refuse)
				_ = json.NewEncoder(w).Encode(agent.UpdateResult{Error: "updates from the panel are turned off on this server"})
				return
			}
			var req agent.UpdateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.lastAsked = req.Version
			if req.PullURL != "" {
				if !pull(req.PullURL, token, req.SHA256) {
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(agent.UpdateResult{PullFailed: true, Error: "could not download it from the panel"})
					return
				}
				f.gotPulled = true
				f.version = req.Version
				_ = json.NewEncoder(w).Encode(agent.UpdateResult{OK: true, Version: req.Version})
				return
			}
			if req.Upload == "" && len(req.Archive) == 0 && !f.githubOK {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(agent.UpdateResult{NeedArchive: true, Error: "could not reach GitHub"})
				return
			}
			if req.Upload != "" {
				var whole []byte
				for i := 0; i < req.Parts; i++ {
					whole = append(whole, f.parts[i]...)
				}
				if sha256Hex(whole) != req.SHA256 {
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(agent.UpdateResult{Error: "the release did not arrive whole"})
					return
				}
				f.gotSent = true
			}
			f.version = req.Version
			_ = json.NewEncoder(w).Encode(agent.UpdateResult{OK: true, Version: req.Version})
		default:
			http.NotFound(w, r)
		}
	})
}

// fakeState is what a fake agent went through, read safely while its handler
// may still run.
type fakeState struct {
	version, lastAsked string
	gotSent, gotPulled bool
	partsSeen          int
}

func (f *fakeAgent) state() fakeState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeState{version: f.version, lastAsked: f.lastAsked, gotSent: f.gotSent, gotPulled: f.gotPulled, partsSeen: f.partsSeen}
}

func withFakeAgent(t *testing.T, p *Panel, id, group string, f *fakeAgent) Server {
	t.Helper()
	token := "pba_" + id
	srv := httptest.NewTLSServer(f.handler(token))
	t.Cleanup(srv.Close)
	s := addTestServer(t, p, Server{ID: id, Name: id, Group: group, Address: "203.0.113.30",
		AgentURL: srv.URL, Fingerprint: fingerprintOf(srv.Certificate().Raw)}, token)
	p.fleet.refresh(s)
	return s
}

func fastWaits(t *testing.T) {
	t.Helper()
	oldResume, oldRetry := resumeSettle, partRetryWait
	resumeSettle, partRetryWait = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { resumeSettle, partRetryWait = oldResume, oldRetry })
}

// A server that cannot reach GitHub downloads the release from the panel, which
// some networks carry far better than the panel sending it.
func TestAServerDownloadsTheReleaseFromThePanel(t *testing.T) {
	fastWaits(t)
	p := newTestPanel(t)
	ts := startPanel(t, p)
	p.cfg.PublicURL = ts.URL
	iran := &fakeAgent{version: "v0.15.0"}
	withFakeAgent(t, p, "iran1", GroupRelay, iran)
	oldFetch := fetchRelease
	fetchRelease = func(v, arch string) ([]byte, error) { return []byte("release " + v), nil }
	t.Cleanup(func() { fetchRelease = oldFetch })

	v := waitJob(t, p, p.startJob(func(j *job) (string, error) { return "", p.updates.updateServers(j, "v0.16.0") }))
	if st := iran.state(); v.Error != "" || !st.gotPulled || st.gotSent || st.version != "v0.16.0" {
		t.Fatalf("it should have downloaded it from the panel: %q %+v\n%s", v.Error, st, strings.Join(v.Lines, "\n"))
	}
	p.updates.mu.Lock()
	left := len(p.updates.offers)
	p.updates.mu.Unlock()
	if left != 0 {
		t.Fatalf("the offer was left open after the update")
	}
}

// Only the server a release is offered to can download it, and only while it is
// offered.
func TestAnOfferedReleaseIsOnlyForItsServer(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	addTestServer(t, p, Server{ID: "a", Name: "a", Group: GroupForeign}, "pba_aaaaaaaa")
	addTestServer(t, p, Server{ID: "b", Name: "b", Group: GroupForeign}, "pba_bbbbbbbb")
	id := p.updates.offer("a", []byte("the release"))
	url := ts.URL + "/hub/release/" + id
	want := sha256Hex([]byte("the release"))
	if !pull(url, "pba_aaaaaaaa", want) {
		t.Fatalf("the server it is offered to could not download it")
	}
	for name, tok := range map[string]string{"another server": "pba_bbbbbbbb", "no one": "pba_wrong", "nothing": ""} {
		if pull(url, tok, want) {
			t.Fatalf("%s could download it", name)
		}
	}
	p.updates.withdraw(id)
	if pull(url, "pba_aaaaaaaa", want) {
		t.Fatalf("it could be downloaded after it was withdrawn")
	}
}

// A network that cuts transfers part way: every third part is cut, tried again,
// and the release still arrives whole.
func TestAReleaseIsSentInPartsThroughACuttingNetwork(t *testing.T) {
	fastWaits(t)
	p := newTestPanel(t)
	p.cfg.PublicURL = "https://127.0.0.1:1"
	iran := &fakeAgent{version: "v0.15.0", cutEvery: 3}
	withFakeAgent(t, p, "iran1", GroupRelay, iran)
	oldFetch := fetchRelease
	big := make([]byte, 5*agent.PartSize+123)
	for i := range big {
		big[i] = byte(i * 7)
	}
	fetchRelease = func(v, arch string) ([]byte, error) { return big, nil }
	t.Cleanup(func() { fetchRelease = oldFetch })

	v := waitJob(t, p, p.startJob(func(j *job) (string, error) { return "", p.updates.updateServers(j, "v0.16.0") }))
	st := iran.state()
	if v.Error != "" || !st.gotSent || st.version != "v0.16.0" {
		t.Fatalf("the release did not get through: %q %+v\n%s", v.Error, st, strings.Join(v.Lines, "\n"))
	}
	if st.partsSeen <= 6 {
		t.Fatalf("no part was cut, so the test proves nothing (%d parts seen)", st.partsSeen)
	}
}

// The panel cannot reach GitHub; a foreign server downloads the release and
// passes it on in parts, which the panel checks against the checksum.
func TestAReleaseIsFetchedInPartsThroughAServer(t *testing.T) {
	fastWaits(t)
	p := newTestPanel(t)
	big := make([]byte, 3*agent.PartSize+5)
	for i := range big {
		big[i] = byte(i)
	}
	const token = "pba_parts"
	var corrupt atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req agent.ReleaseRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		parts := (len(big) + req.PartSize - 1) / req.PartSize
		data := append([]byte(nil), big[req.Part*req.PartSize:min((req.Part+1)*req.PartSize, len(big))]...)
		if corrupt.Load() && req.Part == 1 {
			data[0] ^= 0xff
		}
		_ = json.NewEncoder(w).Encode(agent.ReleaseReply{OK: true, Version: req.Version, Archive: data,
			Size: len(big), Parts: parts, SHA256: sha256Hex(big)})
	}))
	t.Cleanup(srv.Close)
	s := addTestServer(t, p, Server{ID: "f", Name: "f", Group: GroupForeign, AgentURL: srv.URL,
		Fingerprint: fingerprintOf(srv.Certificate().Raw)}, token)
	got, err := p.updates.fetchInParts(s, "v0.16.0", "amd64")
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("not fetched whole: %v", err)
	}
	corrupt.Store(true)
	if _, err := p.updates.fetchInParts(s, "v0.16.0", "amd64"); err == nil {
		t.Fatalf("a damaged release was accepted")
	}
}

func TestServersAreBroughtUpToThePanelsVersion(t *testing.T) {
	p := newTestPanel(t)
	// The panel cannot be downloaded from, so the release is pushed instead.
	p.cfg.PublicURL = "https://127.0.0.1:1"
	direct := &fakeAgent{version: "v0.15.0", githubOK: true}
	iran := &fakeAgent{version: "v0.15.0"} // cannot reach GitHub
	old := &fakeAgent{version: "v0.14.1", noUpdates: true}
	current := &fakeAgent{version: "v0.16.0"}
	withFakeAgent(t, p, "foreign1", GroupForeign, direct)
	withFakeAgent(t, p, "iran1", GroupRelay, iran)
	withFakeAgent(t, p, "old1", GroupForeign, old)
	withFakeAgent(t, p, "current1", GroupForeign, current)

	// The panel's own copy is what a server that cannot reach GitHub is sent.
	oldFetch := fetchRelease
	fetchRelease = func(v, arch string) ([]byte, error) { return []byte("release " + v), nil }
	t.Cleanup(func() { fetchRelease = oldFetch })

	id := p.startJob(func(j *job) (string, error) { return "", p.updates.updateServers(j, "v0.16.0") })
	v := waitJob(t, p, id)
	log := strings.Join(v.Lines, "\n")

	if st := direct.state(); st.version != "v0.16.0" || st.gotSent {
		t.Fatalf("a server that can reach GitHub should download it itself: %+v", st)
	}
	if st := iran.state(); st.version != "v0.16.0" || !st.gotSent {
		t.Fatalf("a server that cannot reach GitHub should be sent the release: %+v", st)
	}
	if st := old.state(); st.version != "v0.14.1" || !strings.Contains(log, "SSH login") {
		t.Fatalf("a server too old for one-click updates should be pointed at the SSH update:\n%s", log)
	}
	if current.state().lastAsked != "" {
		t.Fatalf("a server already up to date was updated")
	}
	if v.Error == "" || !strings.Contains(v.Error, "2 of 3") {
		t.Fatalf("the partial result was not reported: %q", v.Error)
	}

	// Which servers are behind, for the page, against a panel on v0.16.0.
	oldVersion := engine.Version
	engine.Version = "v0.16.0"
	t.Cleanup(func() { engine.Version = oldVersion })
	st := p.updates.status()
	needSSH := map[string]bool{}
	for _, s := range st.Servers {
		needSSH[s.ID] = s.NeedsSSH
	}
	if !needSSH["old1"] || needSSH["iran1"] {
		t.Fatalf("which servers need their SSH login is wrong: %+v", st.Servers)
	}
}

func TestAServerThatRefusesUpdatesSaysSo(t *testing.T) {
	p := newTestPanel(t)
	withFakeAgent(t, p, "locked", GroupForeign, &fakeAgent{version: "v0.15.0", refuse: http.StatusForbidden})
	id := p.startJob(func(j *job) (string, error) { return "", p.updates.updateServers(j, "v0.16.0") })
	v := waitJob(t, p, id)
	if !strings.Contains(strings.Join(v.Lines, "\n"), "does not allow updates") {
		t.Fatalf("not explained:\n%s", strings.Join(v.Lines, "\n"))
	}
	// Its card now offers the update with its SSH login, against a panel on v0.16.0.
	oldVersion := engine.Version
	engine.Version = "v0.16.0"
	t.Cleanup(func() { engine.Version = oldVersion })
	for _, s := range p.updates.status().Servers {
		if s.ID == "locked" && !s.NeedsSSH {
			t.Fatalf("a server that refused is not offered the SSH update: %+v", s)
		}
	}
}

func TestThePanelUpdatesItselfFirstThenCarriesOn(t *testing.T) {
	fastWaits(t)
	p := newTestPanel(t)
	far := &fakeAgent{version: "v0.15.0", githubOK: true}
	withFakeAgent(t, p, "far", GroupForeign, far)

	oldLatest, oldFetch, oldVersion := latestRelease, fetchRelease, engine.Version
	t.Cleanup(func() { latestRelease, fetchRelease, engine.Version = oldLatest, oldFetch, oldVersion })
	engine.Version = "v0.15.0"
	latestRelease = func() (string, error) { return "v0.16.0", nil }
	fetchRelease = func(v, arch string) ([]byte, error) { return []byte("release " + v), nil }
	var installed agent.UpdateRequest
	p.updates.selfInstall = func(req agent.UpdateRequest) (agent.UpdateResult, error) {
		installed = req
		return agent.UpdateResult{OK: true, Version: req.Version}, nil
	}

	p.updates.check(t.Context())
	if st := p.updates.status(); st.Latest != "v0.16.0" || !st.PanelOlder {
		t.Fatalf("the newer release was not noticed: %+v", st)
	}
	v := waitJob(t, p, p.updates.start())
	if v.Error != "" || installed.Version != "v0.16.0" || string(installed.Archive) != "release v0.16.0" {
		t.Fatalf("the panel's own server was not updated first: %q %+v", v.Error, installed)
	}
	if far.state().lastAsked != "" {
		t.Fatalf("other servers were updated before the panel came back on the new version")
	}
	if _, err := os.Stat(filepath.Join(p.dir, pendingFile)); err != nil {
		t.Fatalf("nothing was left for the restarted panel to carry on from")
	}

	// The panel comes back on the new version and carries on by itself.
	engine.Version = "v0.16.0"
	p.updates.resume()
	if _, err := os.Stat(filepath.Join(p.dir, pendingFile)); err == nil {
		t.Fatalf("the note to carry on was not cleared")
	}
	v = waitJob(t, p, p.updates.status().Job)
	if st := far.state(); v.Error != "" || st.version != "v0.16.0" {
		t.Fatalf("the other servers were not updated after the restart: %q %+v\n%s", v.Error, st, strings.Join(v.Lines, "\n"))
	}
}

func TestAnUpdateThatDidNotFinishIsReported(t *testing.T) {
	p := newTestPanel(t)
	data, _ := json.Marshal(pending{Target: "v9.9.9", ThenServers: true, From: engine.Version})
	_ = os.WriteFile(filepath.Join(p.dir, pendingFile), data, 0o600)
	p.updates.resume()
	if st := p.updates.status(); !strings.Contains(st.Note, "did not finish") || st.Job != "" {
		t.Fatalf("a failed self-update was not reported: %+v", st)
	}
}

func TestThePanelFindsTheNewestReleaseThroughAServer(t *testing.T) {
	p := newTestPanel(t)
	oldLatest := latestRelease
	latestRelease = func() (string, error) { return "", errors.New("GitHub is blocked here") }
	t.Cleanup(func() { latestRelease = oldLatest })

	const token = "pba_rel"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/release" && r.Header.Get("Authorization") == "Bearer "+token {
			_ = json.NewEncoder(w).Encode(agent.ReleaseReply{OK: true, Version: "v0.17.0"})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	addTestServer(t, p, Server{ID: "f", Name: "f", Group: GroupForeign, AgentURL: srv.URL,
		Fingerprint: fingerprintOf(srv.Certificate().Raw)}, token)
	p.updates.check(t.Context())
	if st := p.updates.status(); st.Latest != "v0.17.0" || st.CheckError != "" {
		t.Fatalf("the newest release was not found through the foreign server: %+v", st)
	}
}

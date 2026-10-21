package panel

// Keeping every server up to date from the panel.
//
// "Update everything" first updates the panel's own server to the newest
// release, if it is behind, and then, once the panel is back on the new version,
// every other server to the panel's version, one at a time, so only one server's
// tunnels restart at any moment. A server downloads the release from GitHub
// itself; one that cannot (common in Iran) is sent it by the panel. When the
// panel cannot reach GitHub either, a foreign server downloads it for the panel.
//
// Servers that run a PortBridge from before one-click updates existed have to be
// updated once with their SSH login, which the panel asks for and does not keep.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

const (
	// firstOneClickVersion is the first PortBridge whose agent can be updated
	// from the panel.
	firstOneClickVersion = "v0.15.0"
	updateCheckEvery     = 15 * time.Minute
	serverUpdateWait     = 4 * time.Minute
	pendingFile          = "update-pending.json"
)

// resumeSettle is how long the panel waits, after coming back on a new version,
// before updating the other servers. Shortened in tests.
var resumeSettle = 20 * time.Second

// latestRelease asks GitHub for the newest release. Replaced in tests.
var latestRelease = agent.LatestRelease

// fetchRelease downloads and checks a release. Replaced in tests.
var fetchRelease = agent.FetchRelease

type updater struct {
	p *Panel

	mu        sync.Mutex
	latest    string
	checked   time.Time
	checkErr  string
	jobID     string
	offers    map[string]offered
	note      string // what happened to an update that restarted the panel
	cacheKey  string
	cacheData []byte
	// needSSH is servers that refused a one-click update, so their card offers
	// the update with their SSH login, which also allows one-click updates.
	needSSH map[string]bool

	// selfInstall hands a release to the panel's own server's installer.
	// Replaced in tests, where nothing must actually be installed.
	selfInstall func(req agent.UpdateRequest) (agent.UpdateResult, error)
}

func newUpdater(p *Panel) *updater {
	u := &updater{p: p, needSSH: map[string]bool{}}
	u.selfInstall = func(req agent.UpdateRequest) (agent.UpdateResult, error) {
		var res agent.UpdateResult
		body, err := json.Marshal(req)
		if err != nil {
			return res, err
		}
		_, rb, err := p.callServer(context.Background(), "this", http.MethodPost, "/api/update", body, overviewLimit)
		if err != nil {
			return res, err
		}
		if err := json.Unmarshal(rb, &res); err != nil {
			return res, fmt.Errorf("the installer's answer could not be read: %s", rb)
		}
		return res, nil
	}
	return u
}

// serversFirst is every managed server, foreign ones first: they can usually
// reach GitHub when an Iran server cannot.
func (u *updater) serversFirst() []Server {
	list := u.p.store.get().Servers
	sort.SliceStable(list, func(i, j int) bool { return list[i].Group == GroupForeign && list[j].Group != GroupForeign })
	return list
}

// check finds out which release is the newest, asking a server to look when the
// panel cannot reach GitHub itself.
func (u *updater) check(ctx context.Context) {
	v, err := latestRelease()
	if err != nil {
		for _, s := range u.serversFirst() {
			var rep agent.ReleaseReply
			cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			_, cerr := u.p.callJSON(cctx, s.ID, "/api/release", agent.ReleaseRequest{Version: "latest"}, &rep)
			cancel()
			if cerr == nil && rep.OK && agent.IsReleaseVersion(rep.Version) {
				v, err = rep.Version, nil
				break
			}
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.checked = time.Now()
	if err != nil {
		u.checkErr = "neither this server nor any other could reach GitHub to see which version is the newest"
		return
	}
	u.latest, u.checkErr = v, ""
}

// run checks for a new release now and every few hours, until ctx ends.
func (u *updater) run(ctx context.Context) {
	for {
		u.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(updateCheckEvery):
		}
	}
}

type serverUpdate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	State    string `json:"state"` // current, older, newer or unknown
	NeedsSSH bool   `json:"needs_ssh,omitempty"`
}

type updateStatus struct {
	Panel      string         `json:"panel"`
	Latest     string         `json:"latest,omitempty"`
	PanelOlder bool           `json:"panel_older"`
	Checked    string         `json:"checked,omitempty"`
	CheckError string         `json:"check_error,omitempty"`
	Servers    []serverUpdate `json:"servers"`
	Older      int            `json:"older"`
	Job        string         `json:"job,omitempty"`
	Running    bool           `json:"running"`
	Note       string         `json:"note,omitempty"`
}

func (u *updater) status() updateStatus {
	u.mu.Lock()
	st := updateStatus{Panel: engine.Version, Latest: u.latest, CheckError: u.checkErr, Job: u.jobID, Note: u.note}
	if !u.checked.IsZero() {
		st.Checked = u.checked.UTC().Format(time.RFC3339)
	}
	u.mu.Unlock()
	st.PanelOlder = st.Latest != "" && compareVersions(engine.Version, st.Latest) < 0
	if st.Job != "" {
		st.Running = u.p.jobRunning(st.Job)
	}
	u.mu.Lock()
	refused := map[string]bool{}
	for k, v := range u.needSSH {
		refused[k] = v
	}
	u.mu.Unlock()
	for _, v := range u.p.fleet.views() {
		if v.This {
			continue
		}
		su := serverUpdate{ID: v.ID, Name: v.Name, State: "unknown"}
		if v.Overview != nil && v.Overview.Version != "" {
			su.Version = v.Overview.Version
			switch c := compareVersions(su.Version, engine.Version); {
			case c < 0:
				su.State = "older"
				st.Older++
				su.NeedsSSH = compareVersions(su.Version, firstOneClickVersion) < 0 || refused[v.ID]
			case c > 0:
				su.State = "newer"
				if agent.IsReleaseVersion(su.Version) && (st.Latest == "" || compareVersions(st.Latest, su.Version) < 0) {
					st.Latest = su.Version
					st.PanelOlder = true
				}
			default:
				su.State = "current"
			}
		}
		st.Servers = append(st.Servers, su)
	}
	return st
}

func (p *Panel) jobRunning(id string) bool {
	p.jobsMu.Lock()
	j := p.jobs[id]
	p.jobsMu.Unlock()
	return j != nil && !j.view().Done
}

// start begins "Update everything", or gives the update already running.
func (u *updater) start() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.jobID != "" && u.p.jobRunning(u.jobID) {
		return u.jobID
	}
	u.note = ""
	u.jobID = u.p.startJob(func(j *job) (string, error) { return "", u.updateAll(j) })
	return u.jobID
}

func (u *updater) updateAll(j *job) error {
	u.mu.Lock()
	latest := u.latest
	u.mu.Unlock()
	if latest == "" {
		j.say("Looking for the newest version...")
		u.check(context.Background())
		u.mu.Lock()
		latest = u.latest
		u.mu.Unlock()
	}
	target := engine.Version
	panelNeedsUpdate := false
	if latest != "" && compareVersions(engine.Version, latest) < 0 {
		target = latest
		panelNeedsUpdate = true
	} else if latest == "" {
		j.say("Could not find out the newest version, so the other servers are brought up to the panel's own, %s.", engine.Version)
	}
	srvErr := u.updateServers(j, target)
	if !panelNeedsUpdate {
		return srvErr
	}
	if err := u.updatePanel(j, target, srvErr); err != nil {
		return err
	}
	return srvErr
}

// pending is what an update that restarts the panel leaves for the panel that
// comes back, so it can carry on.
type pending struct {
	Target      string    `json:"target"`
	ThenServers bool      `json:"then_servers"`
	Started     time.Time `json:"started"`
	From        string    `json:"from"`
	JobID       string    `json:"job_id,omitempty"`
	Lines       []string  `json:"lines,omitempty"`
	ServerErr   string    `json:"server_err,omitempty"`
}

// releaseFor gets a release for the panel or another server: from GitHub, or
// failing that, through one of the servers.
func (u *updater) releaseFor(j *job, version, arch string) ([]byte, error) {
	u.mu.Lock()
	if u.cacheKey == version+"/"+arch && len(u.cacheData) > 0 {
		cached := u.cacheData
		u.mu.Unlock()
		return cached, nil
	}
	u.mu.Unlock()

	archive, err := fetchRelease(version, arch)
	if err == nil {
		u.mu.Lock()
		u.cacheKey = version + "/" + arch
		u.cacheData = archive
		u.mu.Unlock()
		return archive, nil
	}
	j.say("This server cannot download it from GitHub (%v); asking another server to...", err)
	var last error
	for _, s := range u.serversFirst() {
		a, ferr := u.fetchInParts(s, version, arch)
		if ferr == nil {
			j.say("%s downloaded it, checked it against GitHub's published checksum, and passed it on.", s.Name)
			u.mu.Lock()
			u.cacheKey = version + "/" + arch
			u.cacheData = a
			u.mu.Unlock()
			return a, nil
		}
		last = ferr
	}
	if last == nil {
		last = errors.New("there is no other server to ask")
	}
	return nil, fmt.Errorf("no server could download PortBridge %s from GitHub (%v)", version, last)
}

// updatePanel updates the panel's own server after the other servers have been
// updated; the panel restarts on the new version while keeping the user signed in.
func (u *updater) updatePanel(j *job, target string, srvErr error) error {
	j.say("Updating this server, the panel's own, from %s to %s...", engine.Version, target)
	archive, err := u.releaseFor(j, target, runtime.GOARCH)
	if err != nil {
		return err
	}
	j.say("Restarting the panel service on %s now...", target)
	var srvErrStr string
	if srvErr != nil {
		srvErrStr = srvErr.Error()
	}
	pend := pending{
		Target:      target,
		ThenServers: false,
		Started:     time.Now().UTC(),
		From:        engine.Version,
		JobID:       j.id,
		Lines:       j.view().Lines,
		ServerErr:   srvErrStr,
	}
	data, _ := json.Marshal(pend)
	if err := writeFileAtomic(filepath.Join(u.p.dir, pendingFile), data, 0o600); err != nil {
		return err
	}
	res, err := u.selfInstall(agent.UpdateRequest{Version: target, Archive: archive})
	if err == nil && !res.OK {
		err = errors.New(res.Error)
	}
	if err != nil {
		_ = os.Remove(filepath.Join(u.p.dir, pendingFile))
		return fmt.Errorf("this server could not be updated: %v", err)
	}
	return nil
}

// resume carries on after an update that restarted the panel.
func (u *updater) resume() {
	path := filepath.Join(u.p.dir, pendingFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = os.Remove(path)
	var pend pending
	if json.Unmarshal(data, &pend) != nil {
		return
	}
	if engine.Version != pend.Target {
		u.mu.Lock()
		u.note = fmt.Sprintf("The update to %s did not finish; this server is still on %s. "+
			"Its log: journalctl -u 'portbridge-update-*'", pend.Target, engine.Version)
		u.mu.Unlock()
		logf("the update to %s did not finish; still on %s", pend.Target, engine.Version)
		return
	}
	logf("updated from %s to %s", pend.From, pend.Target)
	if !pend.ThenServers {
		id := pend.JobID
		if id == "" {
			id = newID(9)
		}
		lines := append([]string(nil), pend.Lines...)
		lines = append(lines, fmt.Sprintf("The panel's own server is now on %s.", pend.Target))
		j := &job{
			id:      id,
			lines:   lines,
			done:    true,
			err:     pend.ServerErr,
			started: time.Now(),
		}
		u.p.jobsMu.Lock()
		u.p.jobs[id] = j
		u.p.jobsMu.Unlock()
		u.mu.Lock()
		u.jobID = id
		u.mu.Unlock()
		return
	}
	u.mu.Lock()
	u.jobID = u.p.startJob(func(j *job) (string, error) {
		for _, l := range pend.Lines {
			j.say("%s", l)
		}
		j.say("The panel's own server is now on %s.", pend.Target)
		// Give servers that call the panel a moment to find it again.
		time.Sleep(resumeSettle)
		u.p.fleet.refreshAll()
		return "", u.updateServers(j, pend.Target)
	})
	u.mu.Unlock()
}

// updateServers brings every other server up to target, one at a time.
func (u *updater) updateServers(j *job, target string) error {
	views := map[string]serverView{}
	for _, v := range u.p.fleet.views() {
		views[v.ID] = v
	}
	var todo []Server
	for _, s := range u.p.store.get().Servers {
		v := views[s.ID]
		if v.Overview != nil && compareVersions(v.Overview.Version, target) >= 0 {
			continue
		}
		todo = append(todo, s)
	}
	sort.SliceStable(todo, func(i, k int) bool {
		return todo[i].Group == GroupForeign && todo[k].Group != GroupForeign
	})
	if len(todo) == 0 {
		j.say("Every server already has %s.", target)
		return nil
	}
	done, failed := 0, 0
	for _, s := range todo {
		v := views[s.ID]
		if err := u.updateServer(j, s, v, target); err != nil {
			j.say("%s: %v", s.Name, err)
			failed++
			continue
		}
		done++
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d servers were updated; the messages above say what to do about the others", done, done+failed)
	}
	j.say("All done: every server has %s.", target)
	return nil
}

func (u *updater) updateServer(j *job, s Server, v serverView, target string) error {
	from := "an unknown version"
	arch := runtime.GOARCH
	if v.Overview != nil {
		from = v.Overview.Version
		if v.Overview.Arch != "" {
			arch = v.Overview.Arch
		}
	} else if !v.Online {
		return errors.New("it cannot be reached right now, so it was left for another time")
	}
	j.say("Updating %s from %s to %s (its tunnels restart for a few seconds)...", s.Name, from, target)

	ask := func(req agent.UpdateRequest) (agent.UpdateResult, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		var res agent.UpdateResult
		status, err := u.p.callJSON(ctx, s.ID, "/api/update", req, &res)
		return res, status, err
	}
	res, status, err := ask(agent.UpdateRequest{Version: target})
	markSSH := func() {
		u.mu.Lock()
		u.needSSH[s.ID] = true
		u.mu.Unlock()
	}
	switch {
	case errors.Is(err, errTooOld):
		markSSH()
		return fmt.Errorf("its PortBridge (%s) is too old to be updated from the panel; update it once with its SSH login, "+
			"from the button on its card", from)
	case err != nil:
		return errors.New(plainAgentError(err))
	case status == http.StatusForbidden:
		markSSH()
		return errors.New("it does not allow updates from the panel; update it with its SSH login, from the button on its card, " +
			"which also allows them from then on")
	}
	if !res.OK && res.NeedArchive {
		j.say("%s could not download it from GitHub itself (%s), so the panel is passing the release on...", s.Name, res.Error)
		archive, aerr := u.archiveFor(j, target, arch)
		if aerr != nil {
			return aerr
		}
		sum := sha256Hex(archive)
		// First the server downloads it from the panel: some networks choke a
		// large transfer the panel starts, yet carry it fast when the server
		// starts it.
		pulled := false
		if url := u.p.publicURL(); url != "" {
			id := u.offer(s.ID, archive)
			res, _, err = ask(agent.UpdateRequest{Version: target, SHA256: sum,
				PullURL: url + "/hub/release/" + id, PullFingerprint: u.p.ownFingerprint()})
			u.withdraw(id)
			switch {
			case err == nil && res.OK:
				j.say("%s downloaded it from the panel.", s.Name)
				pulled = true
			case err == nil && res.PullFailed:
				j.say("%s could not download it from the panel (%s); sending it instead...", s.Name, res.Error)
			case err != nil:
				j.say("Asking %s to download it from the panel failed (%s); sending it instead...", s.Name, plainAgentError(err))
			default:
				return fmt.Errorf("it could not be updated: %s", res.Error)
			}
		}
		if !pulled {
			upload, parts, serr := u.sendInParts(j, s, archive)
			if serr != nil {
				return serr
			}
			if res, _, err = ask(agent.UpdateRequest{Version: target, Upload: upload, Parts: parts, SHA256: sum}); err != nil {
				return errors.New(plainAgentError(err))
			}
		}
	}
	if !res.OK {
		return fmt.Errorf("it could not be updated: %s", res.Error)
	}
	return u.waitForVersion(j, s, target)
}

// offered is a release the panel offers one server to download, for a while.
type offered struct {
	server  string
	archive []byte
	until   time.Time
}

// offer makes a release available to one server, and gives its download name.
func (u *updater) offer(serverID string, archive []byte) string {
	id := newID(18)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.offers == nil {
		u.offers = map[string]offered{}
	}
	for k, o := range u.offers {
		if time.Now().After(o.until) {
			delete(u.offers, k)
		}
	}
	u.offers[id] = offered{server: serverID, archive: archive, until: time.Now().Add(20 * time.Minute)}
	return id
}

func (u *updater) withdraw(id string) {
	u.mu.Lock()
	delete(u.offers, id)
	u.mu.Unlock()
}

// handleRelease answers GET /hub/release/{id}: a release offered to the server
// asking, which proves who it is with its own token.
func (p *Panel) handleRelease(w http.ResponseWriter, r *http.Request) {
	who := p.agentByToken(r)
	u := p.updates
	u.mu.Lock()
	o, ok := u.offers[r.PathValue("id")]
	u.mu.Unlock()
	if who == "" || !ok || o.server != who || time.Now().After(o.until) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	agent.ExtendDeadlines(w, 15*time.Minute)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(o.archive)))
	_, _ = w.Write(o.archive)
}

// agentByToken says which managed server a request comes from, by its agent's
// token, whether or not the server calls the panel. Every token is compared, in
// constant time.
func (p *Panel) agentByToken(r *http.Request) string {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return ""
	}
	found := ""
	for _, s := range p.store.get().Servers {
		tok, err := p.store.open(s.TokenEnc)
		if err == nil && subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			found = s.ID
		}
	}
	return found
}

// Sending a release in parts. Networks between countries often cut a long
// transfer part way, so a release goes in small pieces, each tried again if it
// is cut, and the server checks the whole against its checksum at the end.
const partTries = 5

// partRetryWait is the pause before trying a cut part again. Shortened in tests.
var partRetryWait = 3 * time.Second

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// withRetries runs one small transfer, trying again when it is cut.
func withRetries(what string, try func(ctx context.Context) error) error {
	var err error
	for i := 0; i < partTries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err = try(ctx)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(partRetryWait * time.Duration(i+1))
	}
	return fmt.Errorf("%s could not be sent after %d tries: %s", what, partTries, plainAgentError(err))
}

// sendInParts sends a release to a server ahead of updating it.
func (u *updater) sendInParts(j *job, s Server, archive []byte) (string, int, error) {
	upload := newID(12)
	parts := (len(archive) + agent.PartSize - 1) / agent.PartSize
	j.say("Sending it in %d parts of %d KB...", parts, agent.PartSize/1024)
	for i := 0; i < parts; i++ {
		part := agent.UpdatePart{Upload: upload, Index: i, Data: archive[i*agent.PartSize : min((i+1)*agent.PartSize, len(archive))]}
		err := withRetries(fmt.Sprintf("part %d of %d", i+1, parts), func(ctx context.Context) error {
			var res agent.UpdateResult
			if _, err := u.p.callJSON(ctx, s.ID, "/api/update/part", part, &res); err != nil {
				return err
			}
			if !res.OK {
				return errors.New(res.Error)
			}
			return nil
		})
		if err != nil {
			return "", 0, err
		}
	}
	j.say("All %d parts arrived.", parts)
	return upload, parts, nil
}

// fetchInParts gets a release that a server downloaded for the panel, part by
// part, and checks the whole against the checksum the server reports, which is
// the one GitHub publishes.
func (u *updater) fetchInParts(s Server, version, arch string) ([]byte, error) {
	var first agent.ReleaseReply
	ask := func(part int, out *agent.ReleaseReply) error {
		return withRetries(fmt.Sprintf("part %d", part+1), func(ctx context.Context) error {
			req := agent.ReleaseRequest{Version: version, Arch: arch, Part: part, PartSize: agent.PartSize}
			if _, err := u.p.callJSON(ctx, s.ID, "/api/release", req, out); err != nil {
				return err
			}
			if !out.OK {
				return errors.New(out.Error)
			}
			return nil
		})
	}
	if err := ask(0, &first); err != nil {
		return nil, err
	}
	if first.Parts < 1 || first.Parts > agent.MaxReleaseSize/agent.PartSize+1 {
		return nil, errors.New("the server's answer about the release makes no sense")
	}
	buf := append([]byte(nil), first.Archive...)
	for i := 1; i < first.Parts; i++ {
		var rep agent.ReleaseReply
		if err := ask(i, &rep); err != nil {
			return nil, err
		}
		buf = append(buf, rep.Archive...)
	}
	if !strings.EqualFold(sha256Hex(buf), first.SHA256) || len(buf) != first.Size {
		return nil, errors.New("the release did not arrive whole")
	}
	return buf, nil
}

// archiveFor is a release for another server: the panel's own copy when it is
// that version and processor type, otherwise downloaded.
func (u *updater) archiveFor(j *job, version, arch string) ([]byte, error) {
	if version == engine.Version && arch == runtime.GOARCH {
		if a, err := u.p.archiveFor(arch); err == nil {
			return a, nil
		}
	}
	return u.releaseFor(j, version, arch)
}

// waitForVersion waits for a server to come back on the new version.
func (u *updater) waitForVersion(j *job, s Server, target string) error {
	deadline := time.Now().Add(serverUpdateWait)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		ov, err := u.p.fleet.overview(ctx, s)
		cancel()
		if err == nil && ov.Version == target {
			u.p.fleet.refresh(s)
			j.say("%s is on %s.", s.Name, target)
			return nil
		}
	}
	return fmt.Errorf("it did not come back on %s within %s; it may still be finishing. Check it in a few minutes, "+
		"or look at its log: journalctl -u 'portbridge-update-*'", target, serverUpdateWait)
}

// sshUpdate updates a server once with its SSH login, for one too old to be
// updated from the panel, and allows updates from the panel from then on.
func (p *Panel) sshUpdate(j *job, s Server, r addRequest) error {
	methods, err := sshAuth(r)
	if err != nil {
		return err
	}
	if r.User == "" {
		r.User = "root"
	}
	if r.SSHPort == 0 {
		r.SSHPort = 22
	}
	confirmed := strings.TrimSpace(r.HostKey)
	if s.HostKey == "" && confirmed == "" {
		return errors.New("confirm the server's SSH fingerprint first")
	}
	cfg := &ssh.ClientConfig{
		User: r.User,
		Auth: methods,
		// The key it had when it was added, so the login goes to that server and
		// no other. A server with no key on record (added by an old panel)
		// needs the one the person confirmed.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if s.HostKey != "" {
				if got != s.HostKey {
					return fmt.Errorf("its SSH host key is not the one it had when it was added (%s, now %s); "+
						"if it was reinstalled, remove it from the panel and add it again", s.HostKey, got)
				}
				return nil
			}
			if got != confirmed {
				return fmt.Errorf("its SSH fingerprint is %s, not the %s that was confirmed; nothing was sent", got, confirmed)
			}
			return nil
		},
		Timeout: 20 * time.Second,
	}
	addr := net.JoinHostPort(s.Address, strconv.Itoa(r.SSHPort))
	j.say("Connecting to %s over SSH...", addr)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return plainSSHError(err)
	}
	defer client.Close()
	rm := &remote{c: client}
	facts, err := rm.run("echo pb_uid=$(id -u); echo pb_arch=$(uname -m)", nil, 30*time.Second)
	if err != nil {
		return fmt.Errorf("could not look at the server: %v", err)
	}
	f := parseFacts(facts)
	if f["pb_uid"] != "0" {
		return errors.New("the account given is not root; PortBridge needs root to update")
	}
	arch := archName(f["pb_arch"])
	if arch == "" {
		return fmt.Errorf("its processor type (%s) is not one PortBridge is built for", f["pb_arch"])
	}
	j.say("Updating it to %s (its tunnels restart for a few seconds)...", engine.Version)
	if err := p.install(j, rm, arch); err != nil {
		return err
	}
	if _, err := remoteAgentSetup(rm, "-allow-updates on"); err != nil {
		return err
	}
	if s.HostKey == "" {
		// Remembered, so the next login to this server is checked against it.
		_ = p.store.update(func(st *State) error {
			for i := range st.Servers {
				if st.Servers[i].ID == s.ID && st.Servers[i].HostKey == "" {
					st.Servers[i].HostKey = confirmed
				}
			}
			return nil
		})
	}
	j.say("From now on it can be updated from the panel with one click. The SSH login was not kept.")
	p.updates.mu.Lock()
	delete(p.updates.needSSH, s.ID)
	p.updates.mu.Unlock()
	p.fleet.refresh(s)
	return nil
}

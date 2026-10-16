package agent

// Updating PortBridge from the web panel.
//
// The panel asks an agent to update to a version. The agent downloads that
// release from GitHub itself and checks it against the checksums published with
// it; if it cannot reach GitHub (common in Iran), the panel sends the release
// along, and it is checked against GitHub's checksums whenever those can be read.
// The installer is then started as its own short-lived service, so it carries on
// when it restarts the agent (and the tunnels) on the new version.
//
// This lets whoever holds the agent's token install software on the server, so
// it is allowed only where the owner said so: "allow_updates = on" in agent.conf,
// which the panel sets when it adds a server.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

const (
	releaseRepo = "Nima786/portbridge"
	// MaxReleaseSize is the most a release archive may be.
	MaxReleaseSize = 64 << 20
	updateWorkDir  = "/var/lib/portbridge"
)

var releaseTagRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// IsReleaseVersion says whether v names a published release, like v0.15.0.
func IsReleaseVersion(v string) bool { return releaseTagRe.MatchString(v) }

// releaseBase is where releases are downloaded from. Replaced in tests.
var releaseBase = "https://github.com/" + releaseRepo + "/releases"

var releaseClient = &http.Client{Timeout: 3 * time.Minute}

// LatestRelease asks GitHub which release is the newest. It reads where the
// "latest" page points rather than using GitHub's API, which limits how often
// it may be asked.
func LatestRelease() (string, error) {
	c := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Get(releaseBase + "/latest")
	if err != nil {
		return "", fmt.Errorf("could not reach GitHub: %w", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tag := loc[strings.LastIndex(loc, "/")+1:]
	if !IsReleaseVersion(tag) {
		return "", fmt.Errorf("GitHub did not say which release is the latest (HTTP %d)", resp.StatusCode)
	}
	return tag, nil
}

func releaseGet(url string) ([]byte, error) {
	resp, err := releaseClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, MaxReleaseSize))
}

// ReleaseArchiveName is the file a release keeps for one processor type.
func ReleaseArchiveName(version, arch string) string {
	return fmt.Sprintf("portbridge_%s_linux_%s.tar.gz", strings.TrimPrefix(version, "v"), arch)
}

// publishedChecksum reads the checksum GitHub publishes for one archive.
func publishedChecksum(version, arch string) (string, error) {
	sums, err := releaseGet(releaseBase + "/download/" + version + "/checksums.txt")
	if err != nil {
		return "", err
	}
	name := ReleaseArchiveName(version, arch)
	for _, l := range strings.Split(string(sums), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.TrimPrefix(f[1], "./") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("the release's checksums do not list %s", name)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// FetchRelease downloads one release for one processor type from GitHub, and
// gives it back only if it matches the checksum published with it.
func FetchRelease(version, arch string) ([]byte, error) {
	if !IsReleaseVersion(version) {
		return nil, fmt.Errorf("%q is not a release version", version)
	}
	archive, err := releaseGet(releaseBase + "/download/" + version + "/" + ReleaseArchiveName(version, arch))
	if err != nil {
		return nil, fmt.Errorf("could not download PortBridge %s from GitHub: %w", version, err)
	}
	want, err := publishedChecksum(version, arch)
	if err != nil {
		return nil, fmt.Errorf("could not read the checksums of PortBridge %s: %w", version, err)
	}
	if sha256Hex(archive) != want {
		return nil, errors.New("the download does not match its published checksum; not using it")
	}
	return archive, nil
}

// untarRelease unpacks a release archive into dir, refusing anything that would
// land outside it, and checks it holds a release: the program and its installer.
func untarRelease(archive []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("the release is not a gzip archive: %w", err)
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading the release: %w", err)
		}
		name := filepath.Clean(strings.TrimPrefix(filepath.ToSlash(h.Name), "./"))
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) ||
			strings.HasPrefix(filepath.ToSlash(name), "../") {
			return fmt.Errorf("the release has a file outside its folder: %s", h.Name)
		}
		target := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > 4*MaxReleaseSize {
				return errors.New("the release unpacks to far more than a release ever is")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, io.LimitReader(tr, h.Size))
			if err := f.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		}
	}
	for _, need := range []string{"portbridge", "install.sh", "scripts/portbridge-menu"} {
		if _, err := os.Stat(filepath.Join(dir, need)); err != nil {
			return fmt.Errorf("the release is missing %s", need)
		}
	}
	return nil
}

// transferTime is how long a request or answer that carries a whole release may
// take. A few megabytes over a link between countries can take minutes.
const transferTime = 15 * time.Minute

// ExtendDeadlines gives one request longer than the server's usual limits, for
// one that carries a release. A request run in-process (through the hub, or for
// the panel's own server) has no deadlines to extend, which is fine.
func ExtendDeadlines(w http.ResponseWriter, d time.Duration) { extendDeadlines(w, d) }

func extendDeadlines(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(d))
	_ = rc.SetWriteDeadline(time.Now().Add(d + time.Minute))
}

// UpdateRequest is what the panel sends to POST /api/update.
type UpdateRequest struct {
	Version string `json:"version"`
	// Archive is the release, for a server that cannot reach GitHub itself.
	Archive []byte `json:"archive,omitempty"`
	// Or the release was sent ahead in parts (POST /api/update/part), which
	// survives a network that cuts long transfers; SHA256 says it arrived whole.
	Upload string `json:"upload,omitempty"`
	Parts  int    `json:"parts,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// Or the server downloads it from the panel. Some networks, Iran's among
	// them, choke a large upload on a connection the panel opens, yet carry the
	// same data fast on one the server opens. The address and the panel's
	// certificate come in this request, which itself came over the panel's
	// checked connection, so they are as trustworthy as the request.
	PullURL         string `json:"pull_url,omitempty"`
	PullFingerprint string `json:"pull_fingerprint,omitempty"`
}

// UpdatePart is one piece of a release the panel sends ahead.
type UpdatePart struct {
	Upload string `json:"upload"`
	Index  int    `json:"index"`
	Data   []byte `json:"data"`
}

// PartSize is how big each piece of a release is when it is sent in parts:
// small enough that a cut connection costs little, large enough to be quick.
const PartSize = 256 << 10

const (
	maxPartSize = 1 << 20
	maxParts    = MaxReleaseSize / PartSize
	uploadTTL   = time.Hour
)

var uploadIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func uploadDir(workDir, id string) string { return filepath.Join(workDir, "upload-"+id) }

// clearOldUploads removes parts left by sends that never finished.
func clearOldUploads(workDir string) {
	entries, _ := os.ReadDir(workDir)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "upload-") {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > uploadTTL {
			_ = os.RemoveAll(filepath.Join(workDir, e.Name()))
		}
	}
}

// savePart keeps one piece of a release until the rest arrive.
func savePart(workDir string, p UpdatePart) error {
	if !uploadIDRe.MatchString(p.Upload) {
		return errors.New("that is not an upload name")
	}
	if p.Index < 0 || p.Index >= maxParts {
		return errors.New("that part is out of range")
	}
	if len(p.Data) == 0 || len(p.Data) > maxPartSize {
		return errors.New("that part is empty or too big")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	clearOldUploads(workDir)
	dir := uploadDir(workDir, p.Upload)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, fmt.Sprintf("%05d", p.Index)), p.Data, 0o600)
}

// assembleUpload puts the pieces back together and checks they are the whole.
func assembleUpload(workDir string, req UpdateRequest) ([]byte, error) {
	if !uploadIDRe.MatchString(req.Upload) || req.Parts < 1 || req.Parts > maxParts {
		return nil, errors.New("that upload is not one this server knows")
	}
	dir := uploadDir(workDir, req.Upload)
	defer os.RemoveAll(dir)
	var buf bytes.Buffer
	for i := 0; i < req.Parts; i++ {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%05d", i)))
		if err != nil {
			return nil, fmt.Errorf("part %d of the release never arrived; try again", i+1)
		}
		buf.Write(b)
	}
	if !strings.EqualFold(sha256Hex(buf.Bytes()), req.SHA256) {
		return nil, errors.New("the release did not arrive whole; try again")
	}
	return buf.Bytes(), nil
}

// UpdateResult is the agent's answer.
type UpdateResult struct {
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"`
	// NeedArchive says the server could not download the release itself, so
	// the panel should send it.
	NeedArchive bool `json:"need_archive,omitempty"`
	// PullFailed says the server could not download it from the panel either,
	// so the panel should push it.
	PullFailed bool   `json:"pull_failed,omitempty"`
	Error      string `json:"error,omitempty"`
}

// pullFromPanel downloads a release the panel offers. Replaced in tests.
var pullFromPanel = func(url, fingerprint, token, wantSHA string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := panelClient(fingerprint, url, transferTime).Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not download it from the panel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the panel answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxReleaseSize))
	if err != nil {
		return nil, fmt.Errorf("the download from the panel was cut: %w", err)
	}
	if !strings.EqualFold(sha256Hex(b), wantSHA) {
		return nil, errors.New("the release from the panel did not arrive whole")
	}
	return b, nil
}

// startInstaller runs a release's installer as its own short-lived service, so
// it is not stopped when it restarts the agent or the panel that asked for it.
// Replaced in tests.
var startInstaller = func(dir string) error {
	if !haveSystemd() {
		return errNoSystemd
	}
	unit := "portbridge-update-" + strconv.FormatInt(time.Now().Unix(), 10)
	// The pause lets the answer reach the panel before the agent is restarted.
	script := "sleep 2; bash " + shQuote(filepath.Join(dir, "install.sh")) + " --from-dir " + shQuote(dir) +
		" --no-menu; rc=$?; rm -rf " + shQuote(dir) + "; exit $rc"
	out, err := exec.Command("systemd-run", "--unit", unit, "--collect", "--quiet", "--no-block",
		"/bin/bash", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not start the installer: %s", strings.TrimSpace(string(out)))
	}
	log.Printf("[agent] updating PortBridge; the installer runs as %s", unit)
	return nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// updateWorkDirFor is where updates are unpacked for a tunnels folder: the
// system's own place for the real one, and inside the folder itself for any
// other, so an agent run on a scratch folder (in tests) never touches the system.
func updateWorkDirFor(confDir string) string {
	if filepath.ToSlash(filepath.Clean(confDir)) == defaultTunnelsDir {
		return updateWorkDir
	}
	return filepath.Join(confDir, ".update")
}

// releaseVersionOf asks an unpacked program which version it is.
var releaseVersionOf = func(bin string) (string, error) {
	out, err := exec.Command(bin, "version").Output()
	return strings.TrimSpace(string(out)), err
}

// runUpdate checks a release and starts installing it. The token is this agent's
// own, which it shows the panel to download a release the panel offers.
func runUpdate(req UpdateRequest, workDir string, token ...string) UpdateResult {
	res := UpdateResult{Version: req.Version}
	fail := func(format string, args ...any) UpdateResult {
		res.Error = fmt.Sprintf(format, args...)
		return res
	}
	if req.Version == "" {
		return fail("say which version to update to")
	}
	if req.Version == engine.Version {
		res.OK = true
		return res
	}
	archive := req.Archive
	if req.Upload != "" {
		a, err := assembleUpload(workDir, req)
		if err != nil {
			return fail("%v", err)
		}
		archive = a
	}
	if req.PullURL != "" && len(archive) == 0 {
		tok := ""
		if len(token) > 0 {
			tok = token[0]
		}
		a, err := pullFromPanel(req.PullURL, req.PullFingerprint, tok, req.SHA256)
		if err != nil {
			res.PullFailed = true
			return fail("%v", err)
		}
		archive = a
	}
	if len(archive) == 0 {
		a, err := FetchRelease(req.Version, runtime.GOARCH)
		if err != nil {
			res.NeedArchive = true
			return fail("%v", err)
		}
		archive = a
	} else if IsReleaseVersion(req.Version) {
		// Sent by the panel: checked against GitHub too, whenever GitHub can be
		// reached from here.
		if want, err := publishedChecksum(req.Version, runtime.GOARCH); err == nil && sha256Hex(archive) != want {
			return fail("the release sent does not match the checksum GitHub publishes for %s; not installing it", req.Version)
		}
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fail("making a folder for the update: %v", err)
	}
	dir, err := os.MkdirTemp(workDir, "update-")
	if err != nil {
		return fail("making a folder for the update: %v", err)
	}
	if err := untarRelease(archive, dir); err != nil {
		_ = os.RemoveAll(dir)
		return fail("%v", err)
	}
	got, err := releaseVersionOf(filepath.Join(dir, "portbridge"))
	if err != nil || got != req.Version {
		_ = os.RemoveAll(dir)
		return fail("the release does not run on this server, or is not %s (it says %q)", req.Version, got)
	}
	if err := startInstaller(dir); err != nil {
		_ = os.RemoveAll(dir)
		return fail("%v", err)
	}
	res.OK = true
	return res
}

// updatesAllowedByConfig reads agent.conf on each request, so turning updates
// off takes effect at once.
func updatesAllowedByConfig(confPath string) func() bool {
	return func() bool {
		ac, err := readAgentConfig(confPath)
		return err == nil && ac.AllowUpdates == "on"
	}
}

func writeJSONReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// updateHandler answers POST /api/update.
func updateHandler(token string, allowed func() bool, workDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if allowed == nil || !allowed() {
			writeJSONReply(w, http.StatusForbidden, UpdateResult{Error: "updates from the panel are turned off on this server"})
			return
		}
		// A release sent along takes a while to arrive over a slow link between
		// countries, far longer than any other request, so this one request is
		// given longer than the agent's usual limit.
		extendDeadlines(w, transferTime)
		var req UpdateRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, MaxReleaseSize*2)).Decode(&req); err != nil {
			writeJSONReply(w, http.StatusBadRequest, UpdateResult{Error: "the request could not be read"})
			return
		}
		res := runUpdate(req, workDir, token)
		status := http.StatusOK
		if !res.OK {
			status = http.StatusUnprocessableEntity
		}
		writeJSONReply(w, status, res)
	}
}

// updatePartHandler answers POST /api/update/part: one piece of a release sent
// ahead of the update.
func updatePartHandler(token string, allowed func() bool, workDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if allowed == nil || !allowed() {
			writeJSONReply(w, http.StatusForbidden, UpdateResult{Error: "updates from the panel are turned off on this server"})
			return
		}
		var p UpdatePart
		if err := json.NewDecoder(io.LimitReader(r.Body, 2*maxPartSize)).Decode(&p); err != nil {
			writeJSONReply(w, http.StatusBadRequest, UpdateResult{Error: "the part could not be read"})
			return
		}
		if err := savePart(workDir, p); err != nil {
			writeJSONReply(w, http.StatusUnprocessableEntity, UpdateResult{Error: err.Error()})
			return
		}
		writeJSONReply(w, http.StatusOK, UpdateResult{OK: true})
	}
}

// ReleaseRequest asks an agent to download a release for the panel, which may be
// unable to reach GitHub itself. With PartSize set, one part is sent back at a
// time, Part counting from 0, so a network that cuts long transfers costs only
// the part it cut.
type ReleaseRequest struct {
	Version  string `json:"version"` // "latest" for the newest
	Arch     string `json:"arch"`
	Part     int    `json:"part,omitempty"`
	PartSize int    `json:"part_size,omitempty"`
}

// ReleaseReply is the release, or one part of it, checked against its published
// checksum.
type ReleaseReply struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Archive []byte `json:"archive,omitempty"`
	Size    int    `json:"size,omitempty"`
	Parts   int    `json:"parts,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Error   string `json:"error,omitempty"`
}

// releaseCache keeps the last release downloaded for the panel, so asking for it
// part by part downloads it from GitHub once.
var releaseCache struct {
	sync.Mutex
	key     string
	archive []byte
	at      time.Time
}

func cachedRelease(version, arch string) ([]byte, error) {
	key := version + "/" + arch
	releaseCache.Lock()
	defer releaseCache.Unlock()
	if releaseCache.key == key && time.Since(releaseCache.at) < 15*time.Minute {
		return releaseCache.archive, nil
	}
	a, err := FetchRelease(version, arch)
	if err != nil {
		return nil, err
	}
	releaseCache.key, releaseCache.archive, releaseCache.at = key, a, time.Now()
	return a, nil
}

// releaseHandler answers POST /api/release: a release downloaded from GitHub on
// the panel's behalf, or with no archive asked for, just which is the latest.
func releaseHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req ReleaseRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSONReply(w, http.StatusBadRequest, ReleaseReply{Error: "the request could not be read"})
			return
		}
		version := req.Version
		if version == "" || version == "latest" {
			v, err := LatestRelease()
			if err != nil {
				writeJSONReply(w, http.StatusBadGateway, ReleaseReply{Error: err.Error()})
				return
			}
			version = v
		}
		rep := ReleaseReply{OK: true, Version: version}
		if req.Arch != "" {
			extendDeadlines(w, transferTime)
			if req.Arch != "amd64" && req.Arch != "arm64" {
				writeJSONReply(w, http.StatusBadRequest, ReleaseReply{Error: "the processor type must be amd64 or arm64"})
				return
			}
			a, err := cachedRelease(version, req.Arch)
			if err != nil {
				writeJSONReply(w, http.StatusBadGateway, ReleaseReply{Error: err.Error()})
				return
			}
			rep.Size, rep.SHA256 = len(a), sha256Hex(a)
			rep.Archive = a
			if req.PartSize > 0 {
				size := min(max(req.PartSize, 16<<10), maxPartSize)
				rep.Parts = (len(a) + size - 1) / size
				if req.Part < 0 || req.Part >= rep.Parts {
					writeJSONReply(w, http.StatusBadRequest, ReleaseReply{Error: "that part is out of range"})
					return
				}
				rep.Archive = a[req.Part*size : min((req.Part+1)*size, len(a))]
			}
		}
		writeJSONReply(w, http.StatusOK, rep)
	}
}

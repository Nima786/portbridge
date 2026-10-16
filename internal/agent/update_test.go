package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// releaseArchive builds a release archive with these files.
func releaseArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func goodRelease(t *testing.T) []byte {
	return releaseArchive(t, map[string]string{
		"./portbridge": "bin", "./install.sh": "#!/bin/bash", "./scripts/portbridge-menu": "menu",
	})
}

// fakeUpdate replaces what an update would do to the machine.
func fakeUpdate(t *testing.T, version string) *[]string {
	t.Helper()
	started := &[]string{}
	oldStart, oldVer := startInstaller, releaseVersionOf
	startInstaller = func(dir string) error { *started = append(*started, dir); return nil }
	releaseVersionOf = func(string) (string, error) { return version, nil }
	t.Cleanup(func() { startInstaller, releaseVersionOf = oldStart, oldVer })
	return started
}

// fakeGitHub serves releases as GitHub does, for one version.
func fakeGitHub(t *testing.T, version string, archive []byte) {
	t.Helper()
	name := ReleaseArchiveName(version, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			w.Header().Set("Location", "https://github.com/"+releaseRepo+"/releases/tag/"+version)
			w.WriteHeader(http.StatusFound)
		case "/download/" + version + "/" + name:
			_, _ = w.Write(archive)
		case "/download/" + version + "/checksums.txt":
			fmt.Fprintf(w, "%s  ./%s\n", sha256Hex(archive), name)
		default:
			http.NotFound(w, r)
		}
	}))
	old := releaseBase
	releaseBase = srv.URL
	t.Cleanup(func() { releaseBase = old; srv.Close() })
}

func TestReleasesAreUnpackedSafely(t *testing.T) {
	dir := t.TempDir()
	if err := untarRelease(goodRelease(t), dir); err != nil {
		t.Fatalf("a good release was refused: %v", err)
	}
	for _, f := range []string{"portbridge", "install.sh", "scripts/portbridge-menu"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s was not unpacked", f)
		}
	}
	for name, files := range map[string]map[string]string{
		"a file outside its folder": {"../escape": "x", "./portbridge": "b", "./install.sh": "i", "./scripts/portbridge-menu": "m"},
		"no installer":              {"./portbridge": "b", "./scripts/portbridge-menu": "m"},
		"no program":                {"./install.sh": "i", "./scripts/portbridge-menu": "m"},
	} {
		parent := t.TempDir()
		dir := filepath.Join(parent, "inside")
		_ = os.MkdirAll(dir, 0o700)
		if err := untarRelease(releaseArchive(t, files), dir); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
			t.Fatalf("%s: a file was written outside the folder", name)
		}
	}
	if err := untarRelease([]byte("not an archive"), t.TempDir()); err == nil {
		t.Fatalf("garbage was accepted")
	}
}

func TestAnUpdateDownloadsAndChecksTheRelease(t *testing.T) {
	archive := goodRelease(t)
	fakeGitHub(t, "v9.9.9", archive)
	started := fakeUpdate(t, "v9.9.9")

	if v, err := LatestRelease(); err != nil || v != "v9.9.9" {
		t.Fatalf("the latest release: %q %v", v, err)
	}
	res := runUpdate(UpdateRequest{Version: "v9.9.9"}, t.TempDir())
	if !res.OK || len(*started) != 1 {
		t.Fatalf("the update did not start: %+v", res)
	}

	// Sent by the panel, but not what GitHub publishes for that version.
	tampered := releaseArchive(t, map[string]string{"./portbridge": "evil", "./install.sh": "x", "./scripts/portbridge-menu": "m"})
	res = runUpdate(UpdateRequest{Version: "v9.9.9", Archive: tampered}, t.TempDir())
	if res.OK || !strings.Contains(res.Error, "checksum") {
		t.Fatalf("a release that does not match GitHub's checksum was installed: %+v", res)
	}
	if len(*started) != 1 {
		t.Fatalf("the installer ran for a refused release")
	}
}

func TestAnUpdateThatCannotReachGitHubAsksForTheRelease(t *testing.T) {
	old := releaseBase
	releaseBase = "http://127.0.0.1:1"
	t.Cleanup(func() { releaseBase = old })
	started := fakeUpdate(t, "v9.9.8")

	res := runUpdate(UpdateRequest{Version: "v9.9.8"}, t.TempDir())
	if res.OK || !res.NeedArchive {
		t.Fatalf("it should ask the panel to send the release: %+v", res)
	}
	// Sent along, and GitHub cannot be asked about it: used.
	res = runUpdate(UpdateRequest{Version: "v9.9.8", Archive: goodRelease(t)}, t.TempDir())
	if !res.OK || len(*started) != 1 {
		t.Fatalf("a release sent by the panel was not used: %+v", res)
	}
	// A release that is not the version it claims to be.
	releaseVersionOf = func(string) (string, error) { return "v1.0.0", nil }
	res = runUpdate(UpdateRequest{Version: "v9.9.8", Archive: goodRelease(t)}, t.TempDir())
	if res.OK || len(*started) != 1 {
		t.Fatalf("a release that is another version was installed: %+v", res)
	}
}

func TestUpdatesOnlyWhereAllowed(t *testing.T) {
	fakeUpdate(t, "v9.9.7")
	confPath := filepath.Join(t.TempDir(), "agent.conf")
	_ = writeAgentConfig(confPath, agentConfig{Listen: "0.0.0.0:2083", Token: "pba_x"})
	h := newAgentHandler("pba_x", t.TempDir(), updatesAllowedByConfig(confPath))
	ask := func() (int, UpdateResult) {
		body, _ := json.Marshal(UpdateRequest{Version: "v9.9.7", Archive: goodRelease(t)})
		req := httptest.NewRequest(http.MethodPost, "/api/update", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer pba_x")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var res UpdateResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}
	if code, res := ask(); code != http.StatusForbidden || res.OK {
		t.Fatalf("an update was allowed on a server that did not allow them: %d %+v", code, res)
	}
	if updateWorkDirFor(defaultTunnelsDir) != updateWorkDir || updateWorkDirFor(t.TempDir()) == updateWorkDir {
		t.Fatalf("only the real tunnels folder may unpack updates in the system's own place")
	}
	_ = writeAgentConfig(confPath, agentConfig{Listen: "0.0.0.0:2083", Token: "pba_x", AllowUpdates: "on"})
	if code, res := ask(); code != http.StatusOK || !res.OK {
		t.Fatalf("an allowed update was refused: %d %+v", code, res)
	}
	// And it takes effect without restarting the agent.
	_ = writeAgentConfig(confPath, agentConfig{Listen: "0.0.0.0:2083", Token: "pba_x", AllowUpdates: "off"})
	if code, _ := ask(); code != http.StatusForbidden {
		t.Fatalf("turning updates off did not take effect at once")
	}
	// No permission given at all means never.
	h = newAgentHandler("pba_x", t.TempDir(), nil)
	body, _ := json.Marshal(UpdateRequest{Version: "v9.9.7"})
	req := httptest.NewRequest(http.MethodPost, "/api/update", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer pba_x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a handler with no permission allowed an update")
	}
}

func TestReleaseForThePanelIsChecked(t *testing.T) {
	archive := goodRelease(t)
	fakeGitHub(t, "v9.9.6", archive)
	h := newAgentHandler("pba_x", t.TempDir(), nil)
	ask := func(r ReleaseRequest) (int, ReleaseReply) {
		body, _ := json.Marshal(r)
		req := httptest.NewRequest(http.MethodPost, "/api/release", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer pba_x")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var rep ReleaseReply
		_ = json.Unmarshal(rec.Body.Bytes(), &rep)
		return rec.Code, rep
	}
	if code, rep := ask(ReleaseRequest{Version: "latest"}); code != 200 || rep.Version != "v9.9.6" || len(rep.Archive) != 0 {
		t.Fatalf("asking for the latest: %d %+v", code, rep)
	}
	if code, rep := ask(ReleaseRequest{Version: "v9.9.6", Arch: runtime.GOARCH}); code != 200 || !bytes.Equal(rep.Archive, archive) {
		t.Fatalf("downloading for the panel: %d %+v", code, rep.Error)
	}
	if code, _ := ask(ReleaseRequest{Version: "v9.9.6", Arch: "mips"}); code != http.StatusBadRequest {
		t.Fatalf("an unknown processor type was accepted")
	}
}

func TestAReleaseSentInPartsIsCheckedWhole(t *testing.T) {
	started := fakeUpdate(t, "v9.9.5")
	work := t.TempDir()
	archive := goodRelease(t)
	n := (len(archive) + 99) / 100
	for i := 0; i < n; i++ {
		if err := savePart(work, UpdatePart{Upload: "upload-abc123", Index: i, Data: archive[i*100 : min((i+1)*100, len(archive))]}); err != nil {
			t.Fatal(err)
		}
	}
	res := runUpdate(UpdateRequest{Version: "v9.9.5", Upload: "upload-abc123", Parts: n, SHA256: sha256Hex(archive)}, work)
	if !res.OK || len(*started) != 1 {
		t.Fatalf("a release sent whole in parts was not installed: %+v", res)
	}
	// One part missing, or the whole not matching: refused.
	for i := 0; i < n-1; i++ {
		_ = savePart(work, UpdatePart{Upload: "upload-def456", Index: i, Data: archive[i*100 : (i+1)*100]})
	}
	if res := runUpdate(UpdateRequest{Version: "v9.9.5", Upload: "upload-def456", Parts: n, SHA256: sha256Hex(archive)}, work); res.OK {
		t.Fatalf("a release with a part missing was installed")
	}
	_ = savePart(work, UpdatePart{Upload: "upload-ghi789", Index: 0, Data: archive})
	if res := runUpdate(UpdateRequest{Version: "v9.9.5", Upload: "upload-ghi789", Parts: 1, SHA256: sha256Hex([]byte("other"))}, work); res.OK {
		t.Fatalf("a release that does not match its checksum was installed")
	}
	if len(*started) != 1 {
		t.Fatalf("the installer ran for a refused release")
	}
	// Names that could reach outside the folder are refused.
	for _, bad := range []string{"../x", "a/b", "", "short"} {
		if err := savePart(work, UpdatePart{Upload: bad, Index: 0, Data: []byte("x")}); err == nil {
			t.Fatalf("upload name %q was accepted", bad)
		}
	}
}

func TestAReleaseIsDownloadedFromThePanel(t *testing.T) {
	started := fakeUpdate(t, "v9.9.4")
	archive := goodRelease(t)
	var askedWith string
	old := pullFromPanel
	pullFromPanel = func(url, fp, token, want string) ([]byte, error) {
		askedWith = token
		if want != sha256Hex(archive) {
			return nil, errors.New("not whole")
		}
		return archive, nil
	}
	t.Cleanup(func() { pullFromPanel = old })
	res := runUpdate(UpdateRequest{Version: "v9.9.4", PullURL: "https://panel/hub/release/x", SHA256: sha256Hex(archive)}, t.TempDir(), "pba_me")
	if !res.OK || len(*started) != 1 || askedWith != "pba_me" {
		t.Fatalf("not installed from the panel's copy: %+v (token %q)", res, askedWith)
	}
	pullFromPanel = func(string, string, string, string) ([]byte, error) { return nil, errors.New("cut") }
	res = runUpdate(UpdateRequest{Version: "v9.9.4", PullURL: "https://panel/hub/release/x", SHA256: "x"}, t.TempDir(), "pba_me")
	if res.OK || !res.PullFailed {
		t.Fatalf("a failed download should ask the panel to send it instead: %+v", res)
	}
}

func TestAgentSetupKeepsTheUpdateSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	want := agentConfig{Listen: "0.0.0.0:4356", Token: "pba_abc", AllowUpdates: "on"}
	if err := writeAgentConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readAgentConfig(path)
	if err != nil || got != want {
		t.Fatalf("read back %+v (%v), want %+v", got, err, want)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreachable")
	}
}

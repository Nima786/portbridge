package panel

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStateIsSavedAndReadBack(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := st.seal("pba_secret_token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "pba_secret_token") {
		t.Fatalf("the sealed token is readable")
	}
	if err := st.update(func(s *State) error {
		s.Admin = Admin{User: "admin", Hash: "h"}
		s.ThisGroup = GroupRelay
		s.Servers = append(s.Servers, Server{ID: "a", Name: "far", Group: GroupForeign, TokenEnc: sealed})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	again, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := again.get()
	if got.Admin.User != "admin" || got.ThisGroup != GroupRelay || len(got.Servers) != 1 || got.Servers[0].Name != "far" {
		t.Fatalf("read back %+v", got)
	}
	plain, err := again.open(got.Servers[0].TokenEnc)
	if err != nil || plain != "pba_secret_token" {
		t.Fatalf("the token did not survive: %q %v", plain, err)
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), "pba_secret_token") {
		t.Fatalf("state.json holds the token in the clear")
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{"state.json", "secret.key"} {
			if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s is not private to root: %v %v", f, fi.Mode(), err)
			}
		}
	}
}

func TestAFailedChangeChangesNothing(t *testing.T) {
	st, _ := openStore(t.TempDir())
	_ = st.update(func(s *State) error { s.ThisName = "before"; return nil })
	err := st.update(func(s *State) error {
		s.ThisName = "after"
		s.Servers = append(s.Servers, Server{ID: "x"})
		return errors.New("refused")
	})
	if err == nil || st.get().ThisName != "before" || len(st.get().Servers) != 0 {
		t.Fatalf("a refused change was kept: %+v", st.get())
	}
}

func TestAnotherKeyCannotOpenTheTokens(t *testing.T) {
	a, _ := openStore(t.TempDir())
	b, _ := openStore(t.TempDir())
	sealed, _ := a.seal("pba_x")
	if _, err := b.open(sealed); err == nil {
		t.Fatalf("a different key opened the token")
	}
	if _, err := a.open("not base64!"); err == nil {
		t.Fatalf("garbage opened")
	}
	if _, err := a.open(sealed[:8]); err == nil {
		t.Fatalf("a cut-off value opened")
	}
}

func TestPanelConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := Config{Listen: ":2096", Domain: "panel.example.com", Email: "me@example.com", PublicURL: "https://203.0.113.5:2096"}
	if err := writeConfig(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := readConfig(dir)
	if err != nil || got != want {
		t.Fatalf("read back %+v (%v), want %+v", got, err, want)
	}
	_ = os.WriteFile(filepath.Join(dir, "panel.conf"), []byte("# nothing\n"), 0o600)
	if _, err := readConfig(dir); err == nil {
		t.Fatalf("settings without a port were accepted")
	}
}

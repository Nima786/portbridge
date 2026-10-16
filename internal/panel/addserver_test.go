package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVersionsCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"v0.13.1", "v0.13.1", 0},
		{"v0.13.1", "v0.14.0", -1},
		{"v0.14.0", "v0.13.1", 1},
		{"v0.9.9", "v0.10.0", -1},
		{"v1.0.0", "v0.99.99", 1},
		{"v0.14.0-test", "v0.14.0", 0},
		{"dev", "v0.14.0", -1},
		{"v0.14.0", "dev", 1},
		{"dev", "dev", 0},
		{"", "v0.1.0", -1},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("compare %q %q: want %d, got %d", tc.a, tc.b, tc.want, got)
		}
	}
}

func TestProcessorNames(t *testing.T) {
	for in, want := range map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "", "i686": ""} {
		if got := archName(in); got != want {
			t.Fatalf("%s: want %q, got %q", in, want, got)
		}
	}
}

func TestShellQuoteKeepsAValueWhole(t *testing.T) {
	if got := shellQuote("https://x:1/it's"); got != `'https://x:1/it'\''s'` {
		t.Fatalf("got %s", got)
	}
}

func TestLoginMethodsFromTheForm(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	plain := string(pem.EncodeToMemory(plainBlock))
	lockedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	locked := string(pem.EncodeToMemory(lockedBlock))

	if m, err := sshAuth(addRequest{Password: "pw"}); err != nil || len(m) != 2 {
		t.Fatalf("a password: %d methods, %v", len(m), err)
	}
	if m, err := sshAuth(addRequest{PrivateKey: "  " + plain + "  "}); err != nil || len(m) != 1 {
		t.Fatalf("a pasted key with spaces around it: %d methods, %v", len(m), err)
	}
	if _, err := sshAuth(addRequest{PrivateKey: locked}); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("a locked key without its passphrase should ask for it, not %v", err)
	}
	if m, err := sshAuth(addRequest{PrivateKey: locked, Passphrase: "open sesame"}); err != nil || len(m) != 1 {
		t.Fatalf("a locked key with its passphrase: %v", err)
	}
	if _, err := sshAuth(addRequest{PrivateKey: "not a key"}); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("garbage should be refused plainly, not %v", err)
	}
}

func TestAServerIsNotAddedTwice(t *testing.T) {
	p := newTestPanel(t)
	_ = p.store.update(func(s *State) error {
		s.Servers = append(s.Servers, Server{ID: "x", Name: "Aeza", Address: "203.0.113.7"})
		return nil
	})
	r := addRequest{Group: GroupForeign, Address: "203.0.113.7", Password: "pw"}
	if err := p.checkAddRequest(&r); err == nil || !strings.Contains(err.Error(), "already in the panel") {
		t.Fatalf("a second copy was not refused: %v", err)
	}
	r = addRequest{Group: GroupForeign, Address: " 203.0.113.8 ", Password: "pw"}
	if err := p.checkAddRequest(&r); err != nil {
		t.Fatalf("a new server was refused: %v", err)
	}
	if r.User != "root" || r.SSHPort != 22 || r.Address != "203.0.113.8" {
		t.Fatalf("defaults not filled in: %+v", r)
	}
}

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPairingMaxConnIsBounded(t *testing.T) {
	for _, bad := range []string{"0", "-5", "abc", "100001", "99999999999"} {
		p := goodPairing("mc")
		p.MaxConn = bad
		if err := validatePairing(p); err == nil {
			t.Errorf("max_conn %q was accepted", bad)
		}
	}
	for _, ok := range []string{"", "1", "2000", "100000"} {
		p := goodPairing("mc")
		p.MaxConn = ok
		if err := validatePairing(p); err != nil {
			t.Errorf("max_conn %q was refused: %v", ok, err)
		}
	}
}

func TestUploadsHeldAtOnceAreCapped(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxUploadsHeld; i++ {
		if err := savePart(dir, UpdatePart{Upload: fmt.Sprintf("upload-id-%02d", i), Index: 0, Data: []byte("x")}); err != nil {
			t.Fatalf("upload %d was refused: %v", i, err)
		}
	}
	if err := savePart(dir, UpdatePart{Upload: "one-too-many", Index: 0, Data: []byte("x")}); err == nil {
		t.Fatal("an upload beyond the cap was accepted")
	}
	// More parts of a release already being held are still welcome.
	if err := savePart(dir, UpdatePart{Upload: "upload-id-00", Index: 1, Data: []byte("y")}); err != nil {
		t.Fatalf("a further part of a held release was refused: %v", err)
	}
}

func TestFailedJoinKeepsACertificateThatWasAlreadyThere(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "keep.crt"), filepath.Join(dir, "keep.key")
	if err := os.WriteFile(crt, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := goodPairing("keep")
	p.Secret = "short" // refused when the secret is loaded, after files were written
	if err := applyPairingWarn(p, dir, nil); err == nil {
		t.Fatal("the join was expected to fail")
	}
	for _, f := range []string{crt, key} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was deleted by a failed join", filepath.Base(f))
		}
	}
}

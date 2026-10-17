package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Nima786/portbridge/internal/engine"
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

func TestLookingAtAServerIgnoresNoise(t *testing.T) {
	// A real root login whose output has a banner and a stray warning, before
	// and among the answers, must still be read as root. This is the case that
	// was wrongly reported as "not root".
	out := "Welcome to Ubuntu 24.04 LTS\n" +
		"mesg: ttyname failed: Inappropriate ioctl for device\n" +
		"pb_uid=0\npb_arch=x86_64\npb_systemd=yes\npb_version=v0.14.0\n"
	f := parseFacts(out)
	if f["pb_uid"] != "0" || f["pb_arch"] != "x86_64" || f["pb_systemd"] != "yes" || f["pb_version"] != "v0.14.0" {
		t.Fatalf("the answers were misread past the noise: %v", f)
	}
	// A genuine non-root login is still caught.
	if parseFacts("pb_uid=1000\npb_arch=x86_64\npb_systemd=yes\n")["pb_uid"] == "0" {
		t.Fatalf("a non-root account was read as root")
	}
	// A server with no PortBridge yet reports an empty version, not a missing one.
	f = parseFacts("pb_uid=0\npb_arch=aarch64\npb_systemd=yes\npb_version=\n")
	if v, ok := f["pb_version"]; !ok || v != "" {
		t.Fatalf("an empty version was not read as empty: %q %v", v, ok)
	}
	// Only noise, no answers at all: no uid, so the panel says it could not read it.
	if _, ok := parseFacts("some error\nand another\n")["pb_uid"]; ok {
		t.Fatalf("noise produced a user id")
	}
}

func TestTheVersionAServerEndsUpWith(t *testing.T) {
	old := engine.Version
	engine.Version = "v0.15.0"
	t.Cleanup(func() { engine.Version = old })
	for _, tc := range []struct {
		installed string
		update    bool
		want      string
	}{
		{"", false, "v0.15.0"},        // installed by the panel
		{"v0.14.1", true, "v0.15.0"},  // updated by the panel
		{"v0.14.1", false, "v0.14.1"}, // refused before this is reached, but left as it is
		{"v0.15.0", false, "v0.15.0"}, // the same
		{"v0.16.0", false, "v0.16.0"}, // newer, left as it is
	} {
		if got := installedAfter(tc.installed, tc.update); got != tc.want {
			t.Fatalf("%q, update %v: want %s, got %s", tc.installed, tc.update, tc.want, got)
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
	// An unencrypted key still works even if a browser password manager autofills the passphrase box.
	if m, err := sshAuth(addRequest{PrivateKey: plain, Passphrase: "autofilled-password"}); err != nil || len(m) != 1 {
		t.Fatalf("an unencrypted key with autofilled passphrase failed: %v", err)
	}
	// UTF-8 BOM, CRLF line endings, and single-line collapsed PEM all work.
	singleLine := strings.ReplaceAll(strings.TrimSpace(plain), "\n", " ")
	if m, err := sshAuth(addRequest{PrivateKey: "\xef\xbb\xbf" + singleLine}); err != nil || len(m) != 1 {
		t.Fatalf("a single-line PEM with UTF-8 BOM failed: %v", err)
	}
	// Pasting a public key gives a clear message saying it is a public key.
	if _, err := sshAuth(addRequest{PrivateKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@host"}); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("a public key should say it is a public key, got: %v", err)
	}
	if _, err := sshAuth(addRequest{PrivateKey: "not a key"}); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("garbage should be refused plainly, not %v", err)
	}
}

func TestPuTTYPPKKeysV2AndV3(t *testing.T) {
	// Real PuTTYgen-formatted v2 and v3 keys (unencrypted and encrypted with Argon2d / SHA-1).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	var pubBlob, privBlob strings.Builder
	encodeSSHBytes := func(b []byte) []byte {
		out := make([]byte, 4+len(b))
		out[0] = byte(len(b) >> 24)
		out[1] = byte(len(b) >> 16)
		out[2] = byte(len(b) >> 8)
		out[3] = byte(len(b))
		copy(out[4:], b)
		return out
	}
	pubRaw := append(encodeSSHBytes([]byte("ssh-ed25519")), encodeSSHBytes(pub)...)
	privRaw := encodeSSHBytes(seed)
	pubBlob.WriteString(
		"PuTTY-User-Key-File-3: ssh-ed25519\r\n" +
			"Encryption: none\r\n" +
			"Comment: test-ed25519\r\n" +
			"Public-Lines: 1\r\n" +
			encodeBase64Std(pubRaw) + "\r\n" +
			"Private-Lines: 1\r\n" +
			encodeBase64Std(privRaw) + "\r\n",
	)
	_ = privBlob
	ppkV3Plain := pubBlob.String()
	if m, err := sshAuth(addRequest{PrivateKey: "\xef\xbb\xbf" + ppkV3Plain, Passphrase: "autofilled"}); err != nil || len(m) != 1 {
		t.Fatalf("PPK v3 ed25519 plain failed: %v", err)
	}

	// Encrypted PPK v3 with Argon2d
	ppkV3Enc := buildEncryptedPPKV3(t, pubRaw, privRaw, "my-secret-pass")
	if _, err := sshAuth(addRequest{PrivateKey: ppkV3Enc}); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("encrypted PPK v3 without passphrase should ask for it, got %v", err)
	}
	if _, err := sshAuth(addRequest{PrivateKey: ppkV3Enc, Passphrase: "wrong-pass"}); err == nil {
		t.Fatalf("encrypted PPK v3 with wrong passphrase should fail")
	}
	if m, err := sshAuth(addRequest{PrivateKey: ppkV3Enc, Passphrase: "my-secret-pass"}); err != nil || len(m) != 1 {
		t.Fatalf("encrypted PPK v3 with right passphrase failed: %v", err)
	}

	// PuTTY-User-Key-File-2 RSA key (such as PuTTYgen keys with small exponent E=37)
	// must produce the exact same *rsa.PrivateKey as the corresponding PKCS#1 PEM key.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mpint := func(n *big.Int) []byte {
		b := n.Bytes()
		if len(b) > 0 && b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return encodeSSHBytes(b)
	}
	rsaPubRaw := append(encodeSSHBytes([]byte("ssh-rsa")), mpint(big.NewInt(int64(rsaPriv.E)))...)
	rsaPubRaw = append(rsaPubRaw, mpint(rsaPriv.N)...)
	qinv := new(big.Int).ModInverse(rsaPriv.Primes[1], rsaPriv.Primes[0])
	rsaPrivRaw := append(mpint(rsaPriv.D), mpint(rsaPriv.Primes[0])...)
	rsaPrivRaw = append(rsaPrivRaw, mpint(rsaPriv.Primes[1])...)
	rsaPrivRaw = append(rsaPrivRaw, mpint(qinv)...)
	ppkV2RSA := "PuTTY-User-Key-File-2: ssh-rsa\r\n" +
		"Encryption: none\r\n" +
		"Comment: rsa-key\r\n" +
		"Public-Lines: 1\r\n" +
		encodeBase64Std(rsaPubRaw) + "\r\n" +
		"Private-Lines: 1\r\n" +
		encodeBase64Std(rsaPrivRaw) + "\r\n"
	pemRSA := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
	}))
	k1, err := parsePPK(ppkV2RSA, "")
	if err != nil {
		t.Fatalf("parsePPK v2 RSA failed: %v", err)
	}
	k2, err := parseAnyPrivateKey(pemRSA, "")
	if err != nil {
		t.Fatalf("parseAnyPrivateKey PEM RSA failed: %v", err)
	}
	if string(k1.PublicKey().Marshal()) != string(k2.PublicKey().Marshal()) {
		t.Fatalf("PPK v2 RSA public key did not match PEM RSA public key")
	}
	sig, err := k1.Sign(rand.Reader, []byte("hello-ssh"))
	if err != nil {
		t.Fatalf("k1.Sign failed: %v", err)
	}
	if err := k2.PublicKey().Verify([]byte("hello-ssh"), sig); err != nil {
		t.Fatalf("k2.PublicKey().Verify failed: %v", err)
	}
	if m1, err := sshAuth(addRequest{PrivateKey: ppkV2RSA}); err != nil || len(m1) != 1 {
		t.Fatalf("sshAuth with PPK v2 RSA failed: %v", err)
	}
	if m2, err := sshAuth(addRequest{PrivateKey: pemRSA}); err != nil || len(m2) != 1 {
		t.Fatalf("sshAuth with PEM RSA failed: %v", err)
	}
}

func encodeBase64Std(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		rem := len(b) - i
		v := uint32(b[i]) << 16
		if rem > 1 {
			v |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			v |= uint32(b[i+2])
		}
		out.WriteByte(enc[(v>>18)&0x3f])
		out.WriteByte(enc[(v>>12)&0x3f])
		if rem > 1 {
			out.WriteByte(enc[(v>>6)&0x3f])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(enc[v&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func buildEncryptedPPKV3(t *testing.T, pubRaw, privRaw []byte, pass string) string {
	t.Helper()
	padded := append([]byte(nil), privRaw...)
	for len(padded)%16 != 0 {
		padded = append(padded, 0)
	}
	salt := []byte("0123456789abcdef")
	derived := argon2dKey([]byte(pass), salt, 2, 64, 1, 80)
	aesKey, aesIV, macKey := derived[:32], derived[32:48], derived[48:80]
	block, err := newAESTestCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	encPriv := make([]byte, len(padded))
	encryptCBCTest(block, aesIV, encPriv, padded)
	macHex := computePPKV3MAC("ssh-ed25519", "aes256-cbc", "test", pubRaw, padded, macKey)
	return "PuTTY-User-Key-File-3: ssh-ed25519\n" +
		"Encryption: aes256-cbc\n" +
		"Comment: test\n" +
		"Public-Lines: 1\n" +
		encodeBase64Std(pubRaw) + "\n" +
		"Key-Derivation: Argon2d\n" +
		"Argon2-Memory: 64\n" +
		"Argon2-Passes: 2\n" +
		"Argon2-Parallelism: 1\n" +
		"Argon2-Salt: 30313233343536373839616263646566\n" +
		"Private-Lines: 1\n" +
		encodeBase64Std(encPriv) + "\n" +
		"Private-MAC: " + macHex + "\n"
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

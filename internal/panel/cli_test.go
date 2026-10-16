package panel

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupValuesAreChecked(t *testing.T) {
	for d, ok := range map[string]bool{
		"panel.example.com": true, "a.b.co": true, "x-y.example.ir": true,
		"": false, "localhost": false, "203.0.113.5": false, "-bad.example.com": false,
		"bad-.example.com": false, "under_score.example.com": false, "two..dots.com": false,
	} {
		if validDomain(d) != ok {
			t.Fatalf("domain %q: want %v", d, ok)
		}
	}
	for e, ok := range map[string]bool{
		"me@example.com": true, "me@localhost": false, "me example@example.com": false, "@example.com": false, "me": false,
	} {
		if validEmail(e) != ok {
			t.Fatalf("email %q: want %v", e, ok)
		}
	}
	for u, ok := range map[string]bool{
		"https://203.0.113.5:2096": true, "https://panel.example.com": true, "https://[2001:db8::1]:2096/": true,
		"http://203.0.113.5:2096": false, "https://203.0.113.5:2096/panel": false, "203.0.113.5:2096": false,
		"https://user@203.0.113.5": false,
	} {
		if (checkPublicURL(u) == nil) != ok {
			t.Fatalf("public address %q: want %v", u, ok)
		}
	}
}

func TestPasswordIsReadWithoutItsLineEnding(t *testing.T) {
	for in, want := range map[string]string{
		"secret pass\n": "secret pass", "secret pass\r\n": "secret pass", "secret pass": "secret pass",
		" spaces kept \n": " spaces kept ", "first\nsecond\n": "first",
	} {
		got, err := readPassword(strings.NewReader(in))
		if err != nil || got != want {
			t.Fatalf("%q: got %q %v", in, got, err)
		}
	}
}

func TestAddressesToOpenThePanelAt(t *testing.T) {
	got := addressesFor(Config{Listen: ":2096", Domain: "panel.example.com", PublicURL: "https://203.0.113.5:2096"})
	if len(got) != 2 || got[0] != "https://panel.example.com:2096" || got[1] != "https://203.0.113.5:2096" {
		t.Fatalf("got %v", got)
	}
	got = addressesFor(Config{Listen: ":443", Domain: "panel.example.com", PublicURL: "https://panel.example.com"})
	if len(got) != 1 || got[0] != "https://panel.example.com" {
		t.Fatalf("on port 443 the address needs no port, and the domain only once: %v", got)
	}
}

func TestTheRealCertificateIsOnlyForItsDomain(t *testing.T) {
	p := newTestPanel(t)
	hello := &tls.ClientHelloInfo{ServerName: "panel.example.com"}
	c, err := p.getCertificate(hello)
	if err != nil || c != &p.selfCert {
		t.Fatalf("without a domain, the panel's own certificate should be used: %v", err)
	}
	p.certs = newCerts(p.dir, Config{Listen: ":2096", Domain: "panel.example.com"})
	// Not got yet: the panel's own one, never an error, so the panel stays usable.
	if c, err := p.getCertificate(hello); err != nil || c != &p.selfCert {
		t.Fatalf("before the real certificate is got: %v", err)
	}
	if c, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: "www.bing.com"}); err != nil || c != &p.selfCert {
		t.Fatalf("another name: %v", err)
	}
	if !p.certs.wants(&tls.ClientHelloInfo{ServerName: "Panel.Example.com."}) {
		t.Fatalf("the domain is matched regardless of case and a final dot")
	}
	st := p.certs.status()
	if st.Real || st.Domain != "panel.example.com" || st.Note == "" {
		t.Fatalf("status before a certificate: %+v", st)
	}

	// Each failure waits longer, up to a limit.
	first := p.certs.failed(errors.New("DNS problem: NXDOMAIN"))
	second := p.certs.failed(errors.New("DNS problem: NXDOMAIN"))
	if first != certRetryMin || second != 2*certRetryMin {
		t.Fatalf("waits %s then %s", first, second)
	}
	for i := 0; i < 20; i++ {
		p.certs.failed(errors.New("x"))
	}
	if p.certs.backoff != certRetryMax {
		t.Fatalf("the wait grew past its limit: %s", p.certs.backoff)
	}
	if !strings.Contains(plainCertError(errors.New("acme: DNS problem: NXDOMAIN looking up A")), "does not point") {
		t.Fatalf("a DNS failure is not explained")
	}
}

func TestStatusReadsTheSavedCertificate(t *testing.T) {
	dir := t.TempDir()
	if cachedCert(dir, "panel.example.com") != nil {
		t.Fatalf("found a certificate that is not there")
	}
	// Saved as the certificate manager saves it: the key, then the chain.
	p := &Panel{dir: dir}
	if err := p.loadSelfCert(); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(filepath.Join(dir, "cert", "panel.crt"))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "cert", "panel.key"))
	_ = os.MkdirAll(filepath.Join(dir, "acme"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "acme", "panel.example.com"), append(keyPEM, certPEM...), 0o600)
	c := cachedCert(dir, "panel.example.com")
	if c == nil || c.Subject.CommonName != "portbridge-panel" {
		t.Fatalf("the saved certificate was not read: %v", c)
	}
}

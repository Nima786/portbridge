package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeSSHServer is an SSH server that counts how many times anyone tried to
// log in to it, and gives back the fingerprint of its host key.
func fakeSSHServer(t *testing.T) (port int, fingerprint string, attempts *atomic.Int32) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	attempts = new(atomic.Int32)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for range chans {
						}
					}()
					_ = sc.Close()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey()), attempts
}

func TestFetchHostKeyShowsTheKeyWithoutLoggingIn(t *testing.T) {
	port, fp, attempts := fakeSSHServer(t)
	got, err := fetchHostKey("127.0.0.1", port)
	if err != nil || got != fp {
		t.Fatalf("fetchHostKey = %q, %v; want %q", got, err, fp)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("a login was attempted %d times while only looking at the key", n)
	}
}

func TestAddServerRefusesAnUnconfirmedKeyBeforeSendingThePassword(t *testing.T) {
	port, fp, attempts := fakeSSHServer(t)
	p := newTestPanel(t)
	r := addRequest{Address: "127.0.0.1", SSHPort: port, User: "root", Password: "secret", HostKey: "SHA256:notTheRealOne"}
	j := &job{}
	if _, err := p.addServer(j, r); err == nil || !strings.Contains(err.Error(), "confirmed") {
		t.Fatalf("a wrong host key was accepted or reported badly: %v", err)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("the password was sent %d times to a server whose key was not the confirmed one", n)
	}
	_ = fp
}

func TestAnAddRequestNeedsAConfirmedKey(t *testing.T) {
	p := newTestPanel(t)
	r := addRequest{Group: GroupForeign, Address: "203.0.113.9", Password: "pw"}
	if err := p.checkAddRequest(&r); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("a request without a confirmed key was accepted: %v", err)
	}
}

func TestSSHUpdateNeedsAKeyForAServerWithNoneOnRecord(t *testing.T) {
	port, fp, attempts := fakeSSHServer(t)
	p := newTestPanel(t)
	s := Server{ID: "old", Name: "Old", Address: "127.0.0.1"}
	j := &job{}
	err := p.sshUpdate(j, s, addRequest{SSHPort: port, Password: "secret"})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("an update with no confirmed key went ahead: %v", err)
	}
	err = p.sshUpdate(j, s, addRequest{SSHPort: port, Password: "secret", HostKey: "SHA256:wrong"})
	if err == nil || !strings.Contains(err.Error(), "confirmed") {
		t.Fatalf("a wrong key was accepted: %v", err)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("the password was sent %d times to an unconfirmed server", n)
	}
	// With a key on record, a different key is refused as before.
	s.HostKey = "SHA256:recorded"
	err = p.sshUpdate(j, s, addRequest{SSHPort: port, Password: "secret", HostKey: fp})
	if err == nil || !strings.Contains(err.Error(), "not the one it had") {
		t.Fatalf("a changed key was accepted: %v", err)
	}
}

func TestTheAgentTokenIsHiddenInQuotedOutput(t *testing.T) {
	out := redactToken(`warning {"ok":true,"token":"abc123SECRET","port":4356}`)
	if strings.Contains(out, "abc123SECRET") || !strings.Contains(out, `"port":4356`) {
		t.Fatalf("token not hidden, or too much removed: %s", out)
	}
}

func TestTheSameServerIsNotAddedTwiceAtOnce(t *testing.T) {
	p := newTestPanel(t)
	p.jobsMu.Lock()
	p.jobs["running"] = &job{started: time.Now(), addr: "203.0.113.50"}
	p.jobsMu.Unlock()
	_, err := p.startAdd(addRequest{Group: GroupForeign, Address: "203.0.113.50", Password: "pw", HostKey: "SHA256:x"})
	if err == nil || !strings.Contains(err.Error(), "already being added") {
		t.Fatalf("a second add of the same address went ahead: %v", err)
	}
}

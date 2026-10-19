package panel

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashChecksOnlyTheRightPassword(t *testing.T) {
	h, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") || strings.Contains(h, "correct horse") {
		t.Fatalf("not an Argon2id hash: %s", h)
	}
	if !checkPassword("correct horse battery", h) {
		t.Fatalf("the right password was refused")
	}
	for _, wrong := range []string{"", "correct horse batter", "Correct horse battery", "correct horse battery "} {
		if checkPassword(wrong, h) {
			t.Fatalf("%q was accepted", wrong)
		}
	}
	h2, _ := hashPassword("correct horse battery")
	if h2 == h {
		t.Fatalf("two hashes of one password are the same, so there is no salt")
	}
	for _, broken := range []string{"", "plain", "$argon2id$v=19$m=0,t=0,p=0$AAAA$AAAA", "$bcrypt$x$y$z$w"} {
		if checkPassword("anything", broken) {
			t.Fatalf("a broken hash %q let a password in", broken)
		}
	}
}

func TestNewCredentialsAreChecked(t *testing.T) {
	for _, tc := range []struct {
		user, pw string
		ok       bool
	}{
		{"admin", "long enough pw", true},
		{"", "long enough pw", false},
		{"ad min", "long enough pw", false},
		{"admin", "short", false},
		{"administrator", "Administrator", false},
		{strings.Repeat("u", 65), "long enough pw", false},
		{"admin", strings.Repeat("p", 257), false},
	} {
		if err := checkNewCredentials(tc.user, tc.pw); (err == nil) != tc.ok {
			t.Fatalf("%q / %q: ok=%v, got %v", tc.user, tc.pw, tc.ok, err)
		}
	}
}

func TestGuessingLocksAnAddressOut(t *testing.T) {
	s := newSessions()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	for i := 0; i < lockAfter-1; i++ {
		s.failed("198.51.100.7")
	}
	if locked, _ := s.locked("198.51.100.7"); locked {
		t.Fatalf("locked before %d failures", lockAfter)
	}
	s.failed("198.51.100.7")
	locked, wait := s.locked("198.51.100.7")
	if !locked || wait != lockFor {
		t.Fatalf("not locked for %s after %d failures (locked=%v, %s)", lockFor, lockAfter, locked, wait)
	}
	if l, _ := s.locked("198.51.100.8"); l {
		t.Fatalf("another address was locked too")
	}
	now = now.Add(lockFor + time.Second)
	if l, _ := s.locked("198.51.100.7"); l {
		t.Fatalf("still locked after the lock ran out")
	}

	// Failures spread out over more than the window never add up to a lock.
	for i := 0; i < 3*lockAfter; i++ {
		s.failed("203.0.113.9")
		now = now.Add(failureWindow/time.Duration(lockAfter-1) + time.Second)
	}
	if l, _ := s.locked("203.0.113.9"); l {
		t.Fatalf("slow, spread-out failures caused a lock")
	}

	// A good login forgets the failures.
	for i := 0; i < lockAfter-1; i++ {
		s.failed("192.0.2.1")
	}
	s.succeeded("192.0.2.1")
	s.failed("192.0.2.1")
	if l, _ := s.locked("192.0.2.1"); l {
		t.Fatalf("failures before a good login still counted")
	}
}

func TestSessionsRunOut(t *testing.T) {
	s := newSessions()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	id, sess := s.create("admin")
	if sess.csrf == "" || id == "" || id == sess.csrf {
		t.Fatalf("a session needs its own id and its own anti-forgery token")
	}
	if s.lookup(id) == nil || s.lookup("") != nil || s.lookup("nope") != nil {
		t.Fatalf("lookup is wrong")
	}

	// Used regularly, it lasts until its lifetime ends, and no longer.
	for now.Add(sessionIdle/2).Sub(sess.created) < sessionLifetime {
		now = now.Add(sessionIdle / 2)
		if s.lookup(id) == nil {
			t.Fatalf("a session in use ran out after %s", now.Sub(sess.created))
		}
	}
	now = now.Add(sessionIdle/2 + time.Second)
	if s.lookup(id) != nil {
		t.Fatalf("a session outlived its %s lifetime", sessionLifetime)
	}

	// Left alone, it runs out after the idle time.
	id2, _ := s.create("admin")
	now = now.Add(sessionIdle + time.Second)
	if s.lookup(id2) != nil {
		t.Fatalf("an idle session did not run out")
	}

	a, _ := s.create("admin")
	b, _ := s.create("admin")
	s.end(a)
	if s.lookup(a) != nil || s.lookup(b) == nil {
		t.Fatalf("ending one session ended the wrong ones")
	}
	s.endAll()
	if s.lookup(b) != nil {
		t.Fatalf("endAll left a session")
	}
}

func TestSessionsSurvivePanelRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.update(func(s *State) error {
		s.Admin = Admin{User: "admin", Hash: "h"}
		return nil
	})
	s1 := newSessionsWithStore(st)
	id, sess := s1.create("admin")

	// Simulate panel restart by reloading store and sessions from disk.
	st2, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2 := newSessionsWithStore(st2)
	got := s2.lookup(id)
	if got == nil || got.user != "admin" || got.csrf != sess.csrf {
		t.Fatalf("session did not survive panel restart: %+v", got)
	}

	// Ending all sessions removes the persisted session file.
	s2.endAll()
	s3 := newSessionsWithStore(st2)
	if s3.lookup(id) != nil {
		t.Fatalf("session survived after endAll")
	}
}

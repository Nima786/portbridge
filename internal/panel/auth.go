package panel

// Logging in.
//
// The password is kept only as an Argon2id hash. A login gives a session, held in
// memory (so restarting the panel logs everyone out), in a cookie the page's
// scripts cannot read and that is only ever sent back to this panel over HTTPS.
// Every request that changes something must also carry the session's own
// anti-forgery token, which another site cannot know, so a page elsewhere cannot
// act through a logged-in browser.
//
// Repeated wrong passwords from one address lock that address out for a while,
// and every failure costs a moment, so guessing is slow.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionIdle     = 2 * time.Hour
	sessionLifetime = 12 * time.Hour
	lockAfter       = 5
	lockFor         = 15 * time.Minute
	failureWindow   = 15 * time.Minute
	failureDelay    = 400 * time.Millisecond
	minPasswordLen  = 10
	maxPasswordLen  = 256
	maxUsernameLen  = 64
)

// Argon2id settings: about 64 MB and a fraction of a second per check on a small
// server, which is slow for a guesser and unnoticeable for a person.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func checkPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// checkUsername says what is wrong with a username, if anything.
func checkUsername(user string) error {
	if user == "" || len(user) > maxUsernameLen {
		return fmt.Errorf("the username must be 1 to %d characters", maxUsernameLen)
	}
	for _, r := range user {
		if r <= ' ' || r == 0x7f {
			return errors.New("the username cannot contain spaces or control characters")
		}
	}
	return nil
}

// checkNewCredentials says what is wrong with a username and password, if anything.
func checkNewCredentials(user, pw string) error {
	if err := checkUsername(user); err != nil {
		return err
	}
	if len(pw) < minPasswordLen {
		return fmt.Errorf("the password must be at least %d characters", minPasswordLen)
	}
	if len(pw) > maxPasswordLen {
		return fmt.Errorf("the password can be at most %d characters", maxPasswordLen)
	}
	if strings.EqualFold(pw, user) {
		return errors.New("the password cannot be the same as the username")
	}
	return nil
}

type session struct {
	user    string
	csrf    string
	created time.Time
	seen    time.Time
}

type failures struct {
	times       []time.Time
	lockedUntil time.Time
}

// sessions holds who is logged in, and who has been guessing.
type sessions struct {
	mu       sync.Mutex
	byID     map[string]*session
	failures map[string]*failures
	now      func() time.Time
}

func newSessions() *sessions {
	return &sessions{byID: map[string]*session{}, failures: map[string]*failures{}, now: time.Now}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create(user string) (id string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess = &session{user: user, csrf: randomToken(), created: now, seen: now}
	id = randomToken()
	s.byID[id] = sess
	return id, sess
}

// lookup finds a live session and marks it used.
func (s *sessions) lookup(id string) *session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byID[id]
	if sess == nil {
		return nil
	}
	now := s.now()
	if now.Sub(sess.seen) > sessionIdle || now.Sub(sess.created) > sessionLifetime {
		delete(s.byID, id)
		return nil
	}
	sess.seen = now
	return sess
}

func (s *sessions) end(id string) {
	s.mu.Lock()
	delete(s.byID, id)
	s.mu.Unlock()
}

// endAll logs everyone out, as after the password is changed.
func (s *sessions) endAll() {
	s.mu.Lock()
	s.byID = map[string]*session{}
	s.mu.Unlock()
}

// locked says whether an address may try to log in now, and if not, for how long.
func (s *sessions) locked(addr string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[addr]
	if f == nil {
		return false, 0
	}
	if wait := f.lockedUntil.Sub(s.now()); wait > 0 {
		return true, wait
	}
	return false, 0
}

func (s *sessions) failed(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	f := s.failures[addr]
	if f == nil {
		f = &failures{}
		s.failures[addr] = f
	}
	recent := f.times[:0]
	for _, t := range f.times {
		if now.Sub(t) < failureWindow {
			recent = append(recent, t)
		}
	}
	f.times = append(recent, now)
	if len(f.times) >= lockAfter {
		f.lockedUntil = now.Add(lockFor)
		f.times = nil
	}
	// Forget addresses that have been quiet a while, so the list cannot grow
	// without end.
	if len(s.failures) > 10000 {
		for a, g := range s.failures {
			if len(g.times) == 0 && now.After(g.lockedUntil) {
				delete(s.failures, a)
			}
		}
	}
}

func (s *sessions) succeeded(addr string) {
	s.mu.Lock()
	delete(s.failures, addr)
	s.mu.Unlock()
}

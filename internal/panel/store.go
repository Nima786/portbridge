package panel

// What the panel keeps on disk.
//
//	panel.conf   how it is reached: port, domain, address, this server's group
//	state.json   the admin account and the servers it manages
//	secret.key   the key the agents' tokens are encrypted with in state.json
//	cert/        its certificates
//
// All of it lives in one root-only directory. No server's root password or SSH
// key is ever written here: they are used while a server is being added and
// then dropped. What is kept is each agent's own token, encrypted.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultDir is where an installed panel keeps everything.
const DefaultDir = "/etc/portbridge/panel"

// Groups a server can be in.
const (
	GroupRelay   = "relay"
	GroupForeign = "foreign"
)

func validGroup(g string) bool { return g == GroupRelay || g == GroupForeign }

// Config is panel.conf.
type Config struct {
	Listen    string // address to listen on, e.g. 0.0.0.0:2053
	Domain    string // optional; a real certificate is got for it
	Email     string // for the certificate authority's notices
	PublicURL string // how agents that call the panel reach it; empty means worked out
	// ACMEDirectory is for testing only: "staging" uses Let's Encrypt's test
	// service, whose certificates no browser trusts. Not offered in the menu.
	ACMEDirectory string
}

func readConfig(dir string) (Config, error) {
	var c Config
	data, err := os.ReadFile(filepath.Join(dir, "panel.conf"))
	if err != nil {
		return c, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "listen":
			c.Listen = v
		case "domain":
			c.Domain = v
		case "email":
			c.Email = v
		case "public_url":
			c.PublicURL = v
		case "acme_directory":
			c.ACMEDirectory = v
		}
	}
	if c.Listen == "" {
		return c, errors.New("panel.conf has no listen address")
	}
	return c, nil
}

func writeConfig(dir string, c Config) error {
	var b strings.Builder
	b.WriteString("# PortBridge web panel. Change with: portbridge-menu -> Web panel\n")
	fmt.Fprintf(&b, "listen = %s\n", c.Listen)
	if c.Domain != "" {
		fmt.Fprintf(&b, "domain = %s\n", c.Domain)
	}
	if c.Email != "" {
		fmt.Fprintf(&b, "email = %s\n", c.Email)
	}
	if c.PublicURL != "" {
		fmt.Fprintf(&b, "public_url = %s\n", c.PublicURL)
	}
	if c.ACMEDirectory != "" {
		fmt.Fprintf(&b, "acme_directory = %s\n", c.ACMEDirectory)
	}
	return writeFileAtomic(filepath.Join(dir, "panel.conf"), []byte(b.String()), 0o600)
}

// Server is one server the panel manages, other than the one it runs on.
type Server struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Group       string    `json:"group"`
	Address     string    `json:"address"`      // what the user typed to reach it
	AgentURL    string    `json:"agent_url"`    // https://address:port of its agent
	Fingerprint string    `json:"fingerprint"`  // the agent's certificate, pinned
	TokenEnc    string    `json:"token"`        // the agent's token, encrypted
	CallsPanel  bool      `json:"calls_panel"`  // reached by the agent calling in
	HostKey     string    `json:"ssh_host_key"` // SSH host key seen when it was added
	Added       time.Time `json:"added"`
}

// Admin is the one account that can log in.
type Admin struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}

// CFAccount is one Cloudflare API token the panel keeps, encrypted.
type CFAccount struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	TokenEnc string    `json:"token"` // encrypted with secret.key
	Hint     string    `json:"hint"`  // last 4 characters, safe to display
	Added    time.Time `json:"added"`
}

// State is state.json.
type State struct {
	Admin      Admin       `json:"admin"`
	ThisGroup  string      `json:"this_group"` // the group the panel's own server is in, if any
	ThisName   string      `json:"this_name"`
	Servers    []Server    `json:"servers"`
	CFAccounts []CFAccount `json:"cf_accounts,omitempty"`
}

// store guards the state and saves every change at once.
type store struct {
	dir string
	key []byte

	mu sync.Mutex
	st State
}

func openStore(dir string) (*store, error) {
	key, err := loadOrMakeKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		return nil, err
	}
	s := &store{dir: dir, key: key}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s.st); err != nil {
			return nil, fmt.Errorf("reading state.json: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	return s, nil
}

// get returns a copy of the state.
func (s *store) get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Servers = append([]Server(nil), s.st.Servers...)
	st.CFAccounts = append([]CFAccount(nil), s.st.CFAccounts...)
	return st
}

// update changes the state and saves it; nothing changes if saving fails.
func (s *store) update(change func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st
	next.Servers = append([]Server(nil), s.st.Servers...)
	next.CFAccounts = append([]CFAccount(nil), s.st.CFAccounts...)
	if err := change(&next); err != nil {
		return err
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, "state.json"), append(data, '\n'), 0o600); err != nil {
		return err
	}
	s.st = next
	return nil
}

// seal and open encrypt what is kept secret in state.json.
func (s *store) seal(plain string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (s *store) open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("sealed value is too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("could not decrypt a stored value; secret.key does not match state.json")
	}
	return string(plain), nil
}

func loadOrMakeKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s is not a 32-byte key", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// writeFileAtomic writes to a temporary file and renames it, so a reader never
// sees half a file and a crash never leaves one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

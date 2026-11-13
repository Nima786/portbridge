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
	BasePath  string // optional secret URL prefix, e.g. "/k9x4m2"; empty means "/"
	PublicURL string // how agents that call the panel reach it; empty means worked out
	// ACMEDirectory is for testing only: "staging" uses Let's Encrypt's test
	// service, whose certificates no browser trusts. Not offered in the menu.
	ACMEDirectory string
}

// normalizeBasePath validates and normalizes a secret login path.
// Empty, "/", "off", or "none" disables the secret path (returns "").
// "random" or "auto" generates a fresh random 10-character slug.
// Otherwise returns "/<slug>".
func normalizeBasePath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "/" || strings.EqualFold(s, "off") || strings.EqualFold(s, "none") {
		return "", nil
	}
	if strings.EqualFold(s, "random") || strings.EqualFold(s, "auto") {
		return "/" + randomBaseSlug(), nil
	}
	slug := strings.Trim(s, "/")
	if slug == "" {
		return "", nil
	}
	if len(slug) > 64 {
		return "", errors.New("the secret path can be at most 64 characters")
	}
	parts := strings.Split(slug, "/")
	if len(parts) > 3 {
		return "", errors.New("the secret path can have at most 3 path segments")
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("the secret path contains an empty or invalid segment")
		}
		if strings.Trim(part, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
			return "", errors.New("the secret path may only contain letters, digits, '-' and '_'")
		}
		if i == 0 {
			switch strings.ToLower(part) {
			case "api", "hub", "app.js", "app.css", "icon.svg", "index.html", ".well-known", "off", "none", "random", "auto":
				return "", fmt.Errorf("%q is reserved and cannot be used as the secret path", part)
			}
		}
	}
	return "/" + slug, nil
}

func randomBaseSlug() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
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
		case "base_path":
			bp, err := normalizeBasePath(v)
			if err != nil {
				return c, fmt.Errorf("panel.conf base_path: %w", err)
			}
			c.BasePath = bp
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
	if c.BasePath != "" {
		fmt.Fprintf(&b, "base_path = %s\n", c.BasePath)
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
	Address     string    `json:"address"`                // what the user typed to reach it
	IPv6        []string  `json:"ipv6,omitempty"`         // known public IPv6 addresses for fallback
	AgentURL    string    `json:"agent_url"`              // https://address:port of its agent
	Fingerprint string    `json:"fingerprint"`            // the agent's certificate, pinned
	TokenEnc    string    `json:"token"`                  // the agent's token, encrypted
	CallsPanel  bool      `json:"calls_panel"`            // reached by the agent calling in
	StandbyHub  bool      `json:"standby_hub,omitempty"`  // allowed to call in on /hub/poll as a failover route
	JumpAllowed bool      `json:"jump_allowed,omitempty"` // reached via peer jump proxy when direct & hub fail
	HostKey     string    `json:"ssh_host_key"`           // SSH host key seen when it was added
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

// AutoHealEvent records one automatic or manual mode failover event.
type AutoHealEvent struct {
	At        string `json:"at"`
	FromDesc  string `json:"from_desc"`
	ToDesc    string `json:"to_desc"`
	Candidate string `json:"candidate"`
	Score     int    `json:"score"`
	Reason    string `json:"reason"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// AutoHealConfig holds per-tunnel Auto-Heal & Smart Failover settings and history.
type AutoHealConfig struct {
	Enabled                 bool            `json:"enabled"`
	CDNDomain               string          `json:"cdn_domain,omitempty"`
	StandbyForeignID        string          `json:"standby_foreign_id,omitempty"`
	StandbyForeignName      string          `json:"standby_foreign_name,omitempty"`
	PrimaryForeignID        string          `json:"primary_foreign_id,omitempty"`
	PrimaryForeignName      string          `json:"primary_foreign_name,omitempty"`
	OnStandby               bool            `json:"on_standby,omitempty"`
	PendingCleanupForeignID string          `json:"pending_cleanup_foreign_id,omitempty"`
	State                   string          `json:"state,omitempty"`      // "monitoring", "probing", "switching", "cooldown", "error"
	FailCount               int             `json:"fail_count,omitempty"` // consecutive unhealthy checks
	LastCheck               string          `json:"last_check,omitempty"`
	LastHeal                string          `json:"last_heal,omitempty"`
	LastNote                string          `json:"last_note,omitempty"`
	History                 []AutoHealEvent `json:"history,omitempty"`
}

// TunnelTraffic holds persistent byte counters and monthly quota settings for one tunnel.
type TunnelTraffic struct {
	TotalUp       int64   `json:"total_up"`
	TotalDown     int64   `json:"total_down"`
	MonthKey      string  `json:"month_key,omitempty"` // "YYYY-MM" in UTC
	MonthUp       int64   `json:"month_up"`
	MonthDown     int64   `json:"month_down"`
	QuotaGB       float64 `json:"quota_gb,omitempty"`
	AutoPause     bool    `json:"auto_pause,omitempty"`
	PausedByQuota bool    `json:"paused_by_quota,omitempty"`
	Warned80Month string  `json:"warned_80_month,omitempty"`
	ExceededMonth string  `json:"exceeded_month,omitempty"`
	LastInstance  string  `json:"last_instance,omitempty"`
	LastRawUp     int64   `json:"last_raw_up,omitempty"`
	LastRawDown   int64   `json:"last_raw_down,omitempty"`
	UpdatedAt     string  `json:"updated_at,omitempty"`
}

// NotifyConfig holds encrypted Telegram Bot and Webhook alert settings.
type NotifyConfig struct {
	Enabled          bool   `json:"enabled"`
	TelegramTokenEnc string `json:"telegram_token,omitempty"`
	TelegramHint     string `json:"telegram_hint,omitempty"`
	TelegramChatID   string `json:"telegram_chat_id,omitempty"`
	WebhookURLEnc    string `json:"webhook_url,omitempty"`
	WebhookHint      string `json:"webhook_hint,omitempty"`
	OnServerOffline  bool   `json:"on_server_offline"`
	OnTunnelFailover bool   `json:"on_tunnel_failover"`
	OnTrafficQuota   bool   `json:"on_traffic_quota"`
}

// State is state.json.
type State struct {
	Admin      Admin                     `json:"admin"`
	ThisGroup  string                    `json:"this_group"` // the group the panel's own server is in, if any
	ThisName   string                    `json:"this_name"`
	Servers    []Server                  `json:"servers"`
	CFAccounts []CFAccount               `json:"cf_accounts,omitempty"`
	AutoHeal   map[string]AutoHealConfig `json:"auto_heal,omitempty"`
	Traffic    map[string]TunnelTraffic  `json:"traffic,omitempty"`
	Notify     NotifyConfig              `json:"notify,omitempty"`
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
	for i := range st.Servers {
		st.Servers[i].IPv6 = append([]string(nil), s.st.Servers[i].IPv6...)
	}
	st.CFAccounts = append([]CFAccount(nil), s.st.CFAccounts...)
	if len(s.st.AutoHeal) > 0 {
		st.AutoHeal = make(map[string]AutoHealConfig, len(s.st.AutoHeal))
		for k, v := range s.st.AutoHeal {
			v.History = append([]AutoHealEvent(nil), v.History...)
			st.AutoHeal[k] = v
		}
	}
	if len(s.st.Traffic) > 0 {
		st.Traffic = make(map[string]TunnelTraffic, len(s.st.Traffic))
		for k, v := range s.st.Traffic {
			st.Traffic[k] = v
		}
	}
	return st
}

// update changes the state and saves it; nothing changes if saving fails.
func (s *store) update(change func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.st
	next.Servers = append([]Server(nil), s.st.Servers...)
	next.CFAccounts = append([]CFAccount(nil), s.st.CFAccounts...)
	if len(s.st.AutoHeal) > 0 {
		next.AutoHeal = make(map[string]AutoHealConfig, len(s.st.AutoHeal))
		for k, v := range s.st.AutoHeal {
			v.History = append([]AutoHealEvent(nil), v.History...)
			next.AutoHeal[k] = v
		}
	}
	if len(s.st.Traffic) > 0 {
		next.Traffic = make(map[string]TunnelTraffic, len(s.st.Traffic))
		for k, v := range s.st.Traffic {
			next.Traffic[k] = v
		}
	}
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
	// Flushed to disk before the rename: after a power cut the file is then
	// either the old one or the new one, never an empty one the panel would
	// refuse to start with.
	if err := tmp.Sync(); err != nil {
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

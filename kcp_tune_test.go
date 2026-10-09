package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kcpConf writes a minimal KCP edge config with extra lines added, loads it and
// validates it, which is what the program does before it runs.
func kcpConf(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret-s3cret-s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "name = kt\nmode = direct\nrole = edge\n" +
		"tunnel_addr = [2001:db8::2]:18600\nuser_listen = 127.0.0.1:18700\n" +
		"peer_ip = 2001:db8::2\ntransport = kcp\nfirewall = off\n" +
		"secret_file = " + secret + "\n" + extra
	path := filepath.Join(dir, "kt.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

func TestKCPTuningDefaultsAndOverrides(t *testing.T) {
	cfg, err := kcpConf(t, "")
	if err != nil {
		t.Fatalf("default config should load: %v", err)
	}
	if cfg.KCPWindow != kcpDefaultWindow || cfg.KCPMTU != kcpDefaultMTU ||
		cfg.KCPInterval != kcpDefaultInterval || cfg.KCPResend != kcpDefaultResend || cfg.KCPCongestion {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	cfg, err = kcpConf(t, "kcp_window = 512\nkcp_mtu = 1200\nkcp_interval = 20\nkcp_resend = 0\nkcp_congestion_control = on\n")
	if err != nil {
		t.Fatalf("tuned config should load: %v", err)
	}
	if cfg.KCPWindow != 512 || cfg.KCPMTU != 1200 || cfg.KCPInterval != 20 || cfg.KCPResend != 0 || !cfg.KCPCongestion {
		t.Fatalf("settings not read: %+v", cfg)
	}
	if !cfg.resendSet {
		t.Fatal("resend written down as 0 must mean off, not unset")
	}
}

func TestKCPTuningRejectsNonsense(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"kcp_window = 4\n", "kcp_window"},
		{"kcp_window = 999999\n", "kcp_window"},
		{"kcp_mtu = 100\n", "kcp_mtu"},
		{"kcp_mtu = 9000\n", "kcp_mtu"},
		{"kcp_interval = 1\n", "kcp_interval"},
		{"kcp_resend = 50\n", "kcp_resend"},
		{"kcp_congestion_control = maybe\n", "kcp_congestion_control"},
	} {
		_, err := kcpConf(t, tc.line)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: want an error naming %s, got %v", strings.TrimSpace(tc.line), tc.want, err)
		}
	}
}

// A Config built by hand, as the tests and the speed test do, leaves every
// setting at zero. That has to mean "the defaults", with resend still on.
func TestKCPTuningZeroMeansDefault(t *testing.T) {
	var c Config
	if err := c.validateKCP(); err != nil {
		t.Fatalf("zero settings must be valid: %v", err)
	}
	if got := orDefault(c.KCPWindow, kcpDefaultWindow); got != kcpDefaultWindow {
		t.Fatalf("window %d", got)
	}
}

package panel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupAndRestoreAcrossDifferentPanels(t *testing.T) {
	dir1 := t.TempDir()
	tunnels1 := filepath.Join(dir1, "tunnels")
	if err := os.MkdirAll(tunnels1, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write a sample local edge tunnel on panel 1.
	sampleConf := strings.Join([]string{
		"name = D-A",
		"mode = direct",
		"role = edge",
		"tunnel_addr = 79.137.202.176:2083",
		"user_listen = 1080",
		"server_inbound_port = 1080",
		"peer_ip = 79.137.202.176",
		"local_ip = 88.218.16.186",
		"firewall = off",
		"transport = plain",
		"mux = on",
		"mux_links = 4",
		"pool_size = 25",
		"max_conn = 2000",
		"max_pending = 512",
		"spare_ttl = 10m",
		"park_timeout = 15m",
		"drain = 5s",
		"secret_file = " + filepath.ToSlash(filepath.Join(tunnels1, "D-A.secret")),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(tunnels1, "D-A.conf"), []byte(sampleConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tunnels1, "D-A.secret"), []byte("dGVzdHNlY3JldDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg1 := Config{Listen: "127.0.0.1:2096", Domain: "panel.example.com"}
	st1, err := openStore(dir1)
	if err != nil {
		t.Fatal(err)
	}
	srvToken := "agent-secret-token-for-foreign-1"
	cfToken := "cf-api-token-xyz-9876"
	srvEnc, err := st1.seal(srvToken)
	if err != nil {
		t.Fatal(err)
	}
	cfEnc, err := st1.seal(cfToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.update(func(st *State) error {
		st.Admin = Admin{User: "nazeem", Hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"}
		st.ThisName = "Iran-Relay-1"
		st.ThisGroup = GroupRelay
		st.Servers = []Server{{
			ID:          "srv-foreign-1",
			Name:        "AllHost",
			Group:       GroupForeign,
			Address:     "198.51.100.10",
			IPv6:        []string{"2001:db8::1"},
			AgentURL:    "https://127.0.0.1:1",
			Fingerprint: "aa:bb:cc",
			TokenEnc:    srvEnc,
			CallsPanel:  true,
			StandbyHub:  true,
			Added:       time.Now().UTC(),
		}}
		st.CFAccounts = []CFAccount{{
			ID:       "cf-1",
			Name:     "Main CF",
			TokenEnc: cfEnc,
			Hint:     "9876",
			Added:    time.Now().UTC(),
		}}
		st.AutoHeal = map[string]AutoHealConfig{
			"D-A": {
				Enabled:   true,
				CDNDomain: "console.wpadvise.com",
			},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	p1 := newPanel(dir1, cfg1, st1)
	p1.setLocal(tunnels1)
	if err := p1.loadSelfCert(); err != nil {
		t.Fatal(err)
	}
	origFP := p1.ownFingerprint()

	// 1. Create an encrypted backup with a passphrase.
	ctx := context.Background()
	env, err := p1.CreateBackup(ctx, "my-strong-backup-pass")
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}
	if !env.Encrypted || env.Payload != nil || env.Ciphertext == "" {
		t.Fatalf("expected encrypted envelope, got %+v", env)
	}
	rawBackup, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Set up a brand-new panel (dir2) with its own different secret.key and different cert.
	dir2 := t.TempDir()
	tunnels2 := filepath.Join(dir2, "tunnels")
	cfg2 := Config{Listen: "127.0.0.1:2096"}
	st2, err := openStore(dir2)
	if err != nil {
		t.Fatal(err)
	}
	p2 := newPanel(dir2, cfg2, st2)
	p2.setLocal(tunnels2)
	if err := p2.loadSelfCert(); err != nil {
		t.Fatal(err)
	}

	// Inspect without passphrase should report NeedsPassphrase = true.
	repLocked, err := p2.InspectBackup(rawBackup, "")
	if err != nil {
		t.Fatalf("InspectBackup without passphrase failed: %v", err)
	}
	if !repLocked.NeedsPassphrase {
		t.Fatalf("expected NeedsPassphrase=true, got %+v", repLocked)
	}

	// Inspect with wrong passphrase should error.
	if _, err := p2.InspectBackup(rawBackup, "wrong-pass"); err == nil {
		t.Fatalf("expected error with wrong passphrase")
	}

	// Inspect with correct passphrase should return full preview.
	rep, err := p2.InspectBackup(rawBackup, "my-strong-backup-pass")
	if err != nil {
		t.Fatalf("InspectBackup with passphrase failed: %v", err)
	}
	if rep.ServerCount != 1 || rep.CFAccountCount != 1 || rep.AutoHealCount != 1 || rep.LocalTunnelCount != 1 {
		t.Fatalf("unexpected inspect counts: %+v", rep)
	}

	// 3. Restore onto p2 (including panel identity and local tunnels).
	res, err := p2.RestoreBackup(ctx, rawBackup, RestoreOptions{
		Passphrase:           "my-strong-backup-pass",
		Mode:                 "replace",
		RestoreCredentials:   true,
		RestorePanelIdentity: true,
		LocalTunnelsAction:   "restore",
	})
	if err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}
	if res.ServersRestored != 1 || res.CFAccountsRestored != 1 || res.AutoHealRestored != 1 || res.LocalTunnelsRestored != 1 {
		t.Fatalf("unexpected RestoreResult: %+v", res)
	}

	// Verify p2 now has p1's exact TLS certificate fingerprint.
	if gotFP := p2.ownFingerprint(); gotFP != origFP {
		t.Fatalf("expected restored panel fingerprint %s, got %s", origFP, gotFP)
	}

	// Verify server token and CF token were re-encrypted with st2's secret.key and decrypt cleanly!
	restoredState := p2.store.get()
	if len(restoredState.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(restoredState.Servers))
	}
	gotSrvTok, err := p2.store.open(restoredState.Servers[0].TokenEnc)
	if err != nil || gotSrvTok != srvToken {
		t.Fatalf("server token decryption on new panel failed: got %q, err %v", gotSrvTok, err)
	}
	gotCFTok, err := p2.store.open(restoredState.CFAccounts[0].TokenEnc)
	if err != nil || gotCFTok != cfToken {
		t.Fatalf("CF token decryption on new panel failed: got %q, err %v", gotCFTok, err)
	}
	if restoredState.AutoHeal["D-A"].CDNDomain != "console.wpadvise.com" {
		t.Fatalf("AutoHeal config not restored: %+v", restoredState.AutoHeal)
	}

	// Verify local tunnel files were restored into tunnels2.
	if _, err := os.Stat(filepath.Join(tunnels2, "D-A.conf")); err != nil {
		t.Fatalf("expected D-A.conf in tunnels2: %v", err)
	}
}

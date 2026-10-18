package panel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

const (
	backupFormat   = "portbridge-panel-backup"
	backupVersion  = 1
	backupMaxBytes = 16 << 20 // 16 MB max upload size for restore
)

// BackupEnvelope is the top-level JSON file downloaded when backing up the panel.
// If Encrypted is true, Payload is nil and Ciphertext holds the AES-256-GCM
// encrypted JSON of BackupPayload derived from the user's passphrase via Argon2id.
type BackupEnvelope struct {
	Format     string         `json:"format"`
	Version    int            `json:"version"`
	CreatedAt  string         `json:"created_at"`
	AppVersion string         `json:"app_version"`
	Encrypted  bool           `json:"encrypted"`
	Salt       string         `json:"salt,omitempty"`
	Ciphertext string         `json:"ciphertext,omitempty"`
	Payload    *BackupPayload `json:"payload,omitempty"`
}

// BackupSourcePanel records the identity and network addresses of the panel
// server where the backup was created, so restoring onto a different server
// can detect the IP change and guide the user safely.
type BackupSourcePanel struct {
	ThisName    string   `json:"this_name"`
	ThisGroup   string   `json:"this_group"`
	Hostname    string   `json:"hostname,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
	Listen      string   `json:"listen,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Email       string   `json:"email,omitempty"`
	PublicURL   string   `json:"public_url,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	CertPEM     string   `json:"cert_pem,omitempty"`
	KeyPEM      string   `json:"key_pem,omitempty"`
}

// BackupServer holds a managed server and its decrypted agent token so it can
// be re-encrypted with the target panel's secret.key upon restore.
type BackupServer struct {
	Server
	PlainToken string                 `json:"plain_token"`
	Tunnels    []agent.TunnelSnapshot `json:"tunnels,omitempty"`
}

// BackupCFAccount holds a Cloudflare account and its decrypted API token.
type BackupCFAccount struct {
	CFAccount
	PlainToken string `json:"plain_token"`
}

// BackupPairedTunnel records both ends of a tunnel and its pairing code.
type BackupPairedTunnel struct {
	Name             string            `json:"name"`
	EdgeServerID     string            `json:"edge_server_id,omitempty"`
	EdgeServerName   string            `json:"edge_server_name,omitempty"`
	EdgeAddress      string            `json:"edge_address,omitempty"`
	OriginServerID   string            `json:"origin_server_id,omitempty"`
	OriginServerName string            `json:"origin_server_name,omitempty"`
	OriginAddress    string            `json:"origin_address,omitempty"`
	PairingCode      string            `json:"pairing_code,omitempty"`
	EdgeInfo         *agent.TunnelInfo `json:"edge_info,omitempty"`
	OriginInfo       *agent.TunnelInfo `json:"origin_info,omitempty"`
}

// BackupPayload is the full state inside a panel backup.
type BackupPayload struct {
	Source        BackupSourcePanel         `json:"source"`
	Admin         Admin                     `json:"admin"`
	Servers       []BackupServer            `json:"servers"`
	CFAccounts    []BackupCFAccount         `json:"cf_accounts,omitempty"`
	AutoHeal      map[string]AutoHealConfig `json:"auto_heal,omitempty"`
	LocalTunnels  []agent.TunnelSnapshot    `json:"local_tunnels,omitempty"`
	PairedTunnels []BackupPairedTunnel      `json:"paired_tunnels,omitempty"`
}

// BackupInspectReport is returned by POST /api/backup/inspect so the UI can
// show a preview and ask the right migration questions before applying changes.
type BackupInspectReport struct {
	Encrypted         bool     `json:"encrypted"`
	NeedsPassphrase   bool     `json:"needs_passphrase,omitempty"`
	CreatedAt         string   `json:"created_at"`
	AppVersion        string   `json:"app_version"`
	SourceName        string   `json:"source_name"`
	SourceGroup       string   `json:"source_group"`
	SourceIPv4        []string `json:"source_ipv4,omitempty"`
	SourceIPv6        []string `json:"source_ipv6,omitempty"`
	SourceDomain      string   `json:"source_domain,omitempty"`
	CurrentIPv4       []string `json:"current_ipv4,omitempty"`
	CurrentIPv6       []string `json:"current_ipv6,omitempty"`
	SameServer        bool     `json:"same_server"`
	SourceWasNode     bool     `json:"source_was_node"` // true if old panel was also a Relay/Foreign server or had local tunnels
	ServerCount       int      `json:"server_count"`
	ServerNames       []string `json:"server_names,omitempty"`
	CallHomeServers   []string `json:"call_home_servers,omitempty"`
	CFAccountCount    int      `json:"cf_account_count"`
	AutoHealCount     int      `json:"auto_heal_count"`
	LocalTunnelCount  int      `json:"local_tunnel_count"`
	LocalTunnelNames  []string `json:"local_tunnel_names,omitempty"`
	PairedTunnelCount int      `json:"paired_tunnel_count"`
	PairedTunnelNames []string `json:"paired_tunnel_names,omitempty"`
	HasPanelIdentity  bool     `json:"has_panel_identity"`
	AdminUser         string   `json:"admin_user,omitempty"`
	MigrationNotes    []string `json:"migration_notes,omitempty"`
}

// RestoreOptions controls how a backup is applied.
type RestoreOptions struct {
	Passphrase            string `json:"passphrase,omitempty"`
	Mode                  string `json:"mode,omitempty"`                   // "merge" (default) or "replace"
	RestoreCredentials    bool   `json:"restore_credentials,omitempty"`    // overwrite admin username/password
	RestorePanelIdentity  bool   `json:"restore_panel_identity,omitempty"` // restore cert/panel.crt & panel.key
	LocalTunnelsAction    string `json:"local_tunnels_action,omitempty"`   // "restore", "migrate", or "skip"
	RedeployRemoteTunnels bool   `json:"redeploy_remote_tunnels,omitempty"`
}

// RestoreResult summarizes what was restored and any follow-up steps for the user.
type RestoreResult struct {
	OK                   bool     `json:"ok"`
	ServersRestored      int      `json:"servers_restored"`
	CFAccountsRestored   int      `json:"cf_accounts_restored"`
	AutoHealRestored     int      `json:"auto_heal_restored"`
	LocalTunnelsRestored int      `json:"local_tunnels_restored"`
	RemotePeersUpdated   int      `json:"remote_peers_updated"`
	RemoteTunnelsJoined  int      `json:"remote_tunnels_joined"`
	CallHomeSeeded       int      `json:"call_home_seeded"`
	Warnings             []string `json:"warnings,omitempty"`
	ActionsNeeded        []string `json:"actions_needed,omitempty"`
}

func encryptBackupPayload(p *BackupPayload, passphrase string) (saltB64, cipherB64 string, err error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	sealed := gcm.Seal(nonce, nonce, raw, nil)
	return base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptBackupPayload(saltB64, cipherB64, passphrase string) (*BackupPayload, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("backup salt is invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, errors.New("backup ciphertext is invalid")
	}
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("backup ciphertext is truncated")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("incorrect backup password (decryption failed)")
	}
	var payload BackupPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("reading decrypted backup payload: %w", err)
	}
	return &payload, nil
}

func parseBackupEnvelope(raw []byte, passphrase string) (*BackupEnvelope, *BackupPayload, error) {
	var env BackupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, errors.New("that file is not a valid PortBridge backup JSON file")
	}
	if env.Format != backupFormat {
		return nil, nil, errors.New("that file is not a PortBridge panel backup")
	}
	if env.Encrypted {
		if passphrase == "" {
			return &env, nil, nil
		}
		payload, err := decryptBackupPayload(env.Salt, env.Ciphertext, passphrase)
		if err != nil {
			return &env, nil, err
		}
		return &env, payload, nil
	}
	if env.Payload == nil {
		return nil, nil, errors.New("backup file has no payload")
	}
	return &env, env.Payload, nil
}

// CreateBackup snapshots the panel's servers, tokens, Cloudflare accounts,
// Auto-Heal rules, TLS identity, and all local + remote tunnels.
func (p *Panel) CreateBackup(ctx context.Context, passphrase string) (*BackupEnvelope, error) {
	st := p.store.get()
	localOv := agent.LocalOverview(p.tunnelsDir)
	localSnaps, _ := agent.ExportTunnels(p.tunnelsDir)

	certDir := filepath.Join(p.dir, "cert")
	certPEM, _ := os.ReadFile(filepath.Join(certDir, "panel.crt"))
	keyPEM, _ := os.ReadFile(filepath.Join(certDir, "panel.key"))

	src := BackupSourcePanel{
		ThisName:    st.ThisName,
		ThisGroup:   st.ThisGroup,
		Hostname:    localOv.Hostname,
		IPv4:        localOv.IPv4,
		IPv6:        localOv.IPv6,
		Listen:      p.cfg.Listen,
		Domain:      p.cfg.Domain,
		Email:       p.cfg.Email,
		PublicURL:   p.cfg.PublicURL,
		Fingerprint: p.ownFingerprint(),
		CertPEM:     string(certPEM),
		KeyPEM:      string(keyPEM),
	}

	// Fetch remote tunnel snapshots concurrently with a short timeout so offline
	// servers never block or slow down creating a backup.
	remoteSnaps := make([][]agent.TunnelSnapshot, len(st.Servers))
	var wg sync.WaitGroup
	for i, srv := range st.Servers {
		wg.Add(1)
		go func(idx int, s Server) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			status, body, err := p.fleet.call(rctx, s, http.MethodGet, "/api/tunnels/export", nil)
			if err != nil || status != http.StatusOK {
				return
			}
			var resp struct {
				OK      bool                   `json:"ok"`
				Tunnels []agent.TunnelSnapshot `json:"tunnels"`
			}
			if json.Unmarshal(body, &resp) == nil && resp.OK {
				remoteSnaps[idx] = resp.Tunnels
			}
		}(i, srv)
	}
	wg.Wait()

	codeByServerTunnel := map[string]string{}
	for _, sn := range localSnaps {
		if sn.PairingCode != "" {
			codeByServerTunnel["this:"+sn.Name] = sn.PairingCode
		}
	}

	servers := make([]BackupServer, 0, len(st.Servers))
	for i, srv := range st.Servers {
		tok, err := p.store.open(srv.TokenEnc)
		if err != nil {
			continue
		}
		snaps := remoteSnaps[i]
		for _, sn := range snaps {
			if sn.PairingCode != "" {
				codeByServerTunnel[srv.ID+":"+sn.Name] = sn.PairingCode
			}
		}
		servers = append(servers, BackupServer{
			Server:     srv,
			PlainToken: tok,
			Tunnels:    snaps,
		})
	}

	cfAccounts := make([]BackupCFAccount, 0, len(st.CFAccounts))
	for _, acc := range st.CFAccounts {
		tok, err := p.store.open(acc.TokenEnc)
		if err != nil {
			continue
		}
		cfAccounts = append(cfAccounts, BackupCFAccount{
			CFAccount:  acc,
			PlainToken: tok,
		})
	}

	views := p.fleet.views()
	paired := pairTunnels(views)
	var pairedOut []BackupPairedTunnel
	for _, tv := range paired {
		pt := BackupPairedTunnel{Name: tv.Name}
		if tv.Edge != nil {
			pt.EdgeServerID = tv.Edge.ServerID
			pt.EdgeServerName = tv.Edge.ServerName
			pt.EdgeAddress = tv.Edge.Address
			info := tv.Edge.Info
			pt.EdgeInfo = &info
			code := codeByServerTunnel[tv.Edge.ServerID+":"+tv.Name]
			if code == "" {
				if c, err := p.tunnelCode(tv.Edge.ServerID, tv.Name); err == nil {
					code = c
				}
			}
			pt.PairingCode = code
		}
		if tv.Origin != nil {
			pt.OriginServerID = tv.Origin.ServerID
			pt.OriginServerName = tv.Origin.ServerName
			pt.OriginAddress = tv.Origin.Address
			info := tv.Origin.Info
			pt.OriginInfo = &info
		}
		pairedOut = append(pairedOut, pt)
	}

	payload := &BackupPayload{
		Source:        src,
		Admin:         st.Admin,
		Servers:       servers,
		CFAccounts:    cfAccounts,
		AutoHeal:      st.AutoHeal,
		LocalTunnels:  localSnaps,
		PairedTunnels: pairedOut,
	}

	env := &BackupEnvelope{
		Format:     backupFormat,
		Version:    backupVersion,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		AppVersion: engine.Version,
	}
	if passphrase != "" {
		salt, ctext, err := encryptBackupPayload(payload, passphrase)
		if err != nil {
			return nil, err
		}
		env.Encrypted = true
		env.Salt = salt
		env.Ciphertext = ctext
	} else {
		env.Payload = payload
	}
	return env, nil
}

func samePanelHost(src BackupSourcePanel, curV4, curV6 []string, curHost string) bool {
	for _, a := range src.IPv4 {
		for _, b := range curV4 {
			if a != "" && strings.EqualFold(a, b) {
				return true
			}
		}
	}
	for _, a := range src.IPv6 {
		for _, b := range curV6 {
			if a != "" && strings.EqualFold(a, b) {
				return true
			}
		}
	}
	if len(src.IPv4) == 0 && len(src.IPv6) == 0 && len(curV4) == 0 && len(curV6) == 0 {
		return src.Hostname != "" && strings.EqualFold(src.Hostname, curHost)
	}
	return false
}

// InspectBackup analyzes a backup file and builds a preview + migration guide
// before anything is changed on the server.
func (p *Panel) InspectBackup(raw []byte, passphrase string) (*BackupInspectReport, error) {
	env, payload, err := parseBackupEnvelope(raw, passphrase)
	if err != nil {
		return nil, err
	}
	if env.Encrypted && payload == nil {
		return &BackupInspectReport{
			Encrypted:       true,
			NeedsPassphrase: true,
			CreatedAt:       env.CreatedAt,
			AppVersion:      env.AppVersion,
		}, nil
	}

	localOv := agent.LocalOverview(p.tunnelsDir)
	sameHost := samePanelHost(payload.Source, localOv.IPv4, localOv.IPv6, localOv.Hostname)
	sourceName := payload.Source.ThisName
	if sourceName == "" {
		sourceName = payload.Source.Hostname
	}
	if sourceName == "" && len(payload.Source.IPv4) > 0 {
		sourceName = payload.Source.IPv4[0]
	}

	rep := &BackupInspectReport{
		Encrypted:         env.Encrypted,
		CreatedAt:         env.CreatedAt,
		AppVersion:        env.AppVersion,
		SourceName:        sourceName,
		SourceGroup:       payload.Source.ThisGroup,
		SourceIPv4:        payload.Source.IPv4,
		SourceIPv6:        payload.Source.IPv6,
		SourceDomain:      payload.Source.Domain,
		CurrentIPv4:       localOv.IPv4,
		CurrentIPv6:       localOv.IPv6,
		SameServer:        sameHost,
		SourceWasNode:     payload.Source.ThisGroup != "" || len(payload.LocalTunnels) > 0,
		ServerCount:       len(payload.Servers),
		CFAccountCount:    len(payload.CFAccounts),
		AutoHealCount:     len(payload.AutoHeal),
		LocalTunnelCount:  len(payload.LocalTunnels),
		PairedTunnelCount: len(payload.PairedTunnels),
		HasPanelIdentity:  payload.Source.CertPEM != "" && payload.Source.KeyPEM != "",
		AdminUser:         payload.Admin.User,
	}

	for _, s := range payload.Servers {
		label := s.Name
		if s.Address != "" {
			label += " (" + s.Address + ")"
		}
		rep.ServerNames = append(rep.ServerNames, label)
		if s.CallsPanel {
			rep.CallHomeServers = append(rep.CallHomeServers, label)
		}
	}
	for _, lt := range payload.LocalTunnels {
		rep.LocalTunnelNames = append(rep.LocalTunnelNames, lt.Name)
	}
	for _, pt := range payload.PairedTunnels {
		rep.PairedTunnelNames = append(rep.PairedTunnelNames, pt.Name)
	}

	srcIPDesc := strings.Join(payload.Source.IPv4, ", ")
	if srcIPDesc == "" {
		srcIPDesc = sourceName
	}
	curIPDesc := strings.Join(localOv.IPv4, ", ")
	if curIPDesc == "" {
		curIPDesc = localOv.Hostname
	}

	if sameHost {
		rep.MigrationNotes = append(rep.MigrationNotes,
			fmt.Sprintf("Same server detected (%s). All managed servers, Cloudflare tokens, Auto-Heal rules, and local tunnels can be restored directly.", curIPDesc))
	} else {
		rep.MigrationNotes = append(rep.MigrationNotes,
			fmt.Sprintf("New panel server detected: this backup was created on %s (%s) and is being restored onto %s.",
				sourceName, srcIPDesc, curIPDesc))
		if len(payload.LocalTunnels) > 0 || payload.Source.ThisGroup != "" {
			rep.MigrationNotes = append(rep.MigrationNotes,
				fmt.Sprintf("The previous panel server (%s) was acting as a %s server with %d local tunnel(s) (%s): "+
					"If %s is STILL online and running those tunnels, choose \"Keep on old server (do not move local tunnels here)\" below and then click \"+ Add Server\" to add %s as a remote server. "+
					"If this new server (%s) is REPLACING %s, choose \"Migrate local tunnels to this server & update remote peer IPs\".",
					srcIPDesc, strings.ToUpper(payload.Source.ThisGroup), len(payload.LocalTunnels),
					strings.Join(rep.LocalTunnelNames, ", "), srcIPDesc, srcIPDesc, curIPDesc, srcIPDesc))
		}
		if len(rep.CallHomeServers) > 0 {
			rep.MigrationNotes = append(rep.MigrationNotes,
				fmt.Sprintf("Reverse Control Hub server(s) (%s): The panel's TLS certificate identity will be restored so agents recognize this panel, and reachable servers will be updated automatically. If a server cannot be reached directly from %s over IPv4 or IPv6, click \"Update via SSH\" on its card once after restore (or point your panel domain %s to %s).",
					strings.Join(rep.CallHomeServers, ", "), curIPDesc, payload.Source.Domain, curIPDesc))
		}
	}

	return rep, nil
}

// RestoreBackup applies a backup to the panel according to opts.
func (p *Panel) RestoreBackup(ctx context.Context, raw []byte, opts RestoreOptions) (*RestoreResult, error) {
	env, payload, err := parseBackupEnvelope(raw, opts.Passphrase)
	if err != nil {
		return nil, err
	}
	if env.Encrypted && payload == nil {
		return nil, errors.New("this backup is password-protected; enter the backup password to restore it")
	}

	localOv := agent.LocalOverview(p.tunnelsDir)
	sameHost := samePanelHost(payload.Source, localOv.IPv4, localOv.IPv6, localOv.Hostname)

	mode := opts.Mode
	if mode != "replace" {
		mode = "merge"
	}
	localAction := opts.LocalTunnelsAction
	if localAction == "" {
		if sameHost {
			localAction = "restore"
		} else {
			localAction = "skip"
		}
	}

	res := &RestoreResult{OK: true}

	// 1. Restore the panel's self-signed TLS identity so Reverse Hub agents
	// pinning the panel's certificate fingerprint continue to trust it.
	if opts.RestorePanelIdentity && payload.Source.CertPEM != "" && payload.Source.KeyPEM != "" {
		certDir := filepath.Join(p.dir, "cert")
		if err := os.MkdirAll(certDir, 0o700); err == nil {
			crtPath := filepath.Join(certDir, "panel.crt")
			keyPath := filepath.Join(certDir, "panel.key")
			if _, err := tlsLoadPair(payload.Source.CertPEM, payload.Source.KeyPEM); err == nil {
				_ = writeFileAtomic(crtPath, []byte(payload.Source.CertPEM), 0o644)
				_ = writeFileAtomic(keyPath, []byte(payload.Source.KeyPEM), 0o600)
				_ = p.loadSelfCert()
			} else {
				res.Warnings = append(res.Warnings, "Backup panel certificate was invalid and was skipped.")
			}
		}
	}

	// 2. Re-encrypt server tokens and Cloudflare tokens using this panel's secret.key
	// and update state.json atomically.
	var sealedServers []Server
	for _, bs := range payload.Servers {
		// Never add this server's own IP as a remote server in itself.
		if isOwnAddress(bs.Address, localOv.IPv4, localOv.IPv6) {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("Skipped adding %q (%s) as a remote server because %s is this panel's own server.", bs.Name, bs.Address, bs.Address))
			continue
		}
		tok := bs.PlainToken
		if tok == "" {
			continue
		}
		enc, err := p.store.seal(tok)
		if err != nil {
			return nil, fmt.Errorf("encrypting server token for %s: %w", bs.Name, err)
		}
		srv := bs.Server
		srv.TokenEnc = enc
		sealedServers = append(sealedServers, srv)
	}

	var sealedCF []CFAccount
	for _, bc := range payload.CFAccounts {
		if bc.PlainToken == "" {
			continue
		}
		enc, err := p.store.seal(bc.PlainToken)
		if err != nil {
			return nil, fmt.Errorf("encrypting Cloudflare token %s: %w", bc.Name, err)
		}
		acc := bc.CFAccount
		acc.TokenEnc = enc
		sealedCF = append(sealedCF, acc)
	}

	if err := p.store.update(func(st *State) error {
		if opts.RestoreCredentials && payload.Admin.User != "" && payload.Admin.Hash != "" {
			st.Admin = payload.Admin
		} else if st.Admin.Hash == "" && payload.Admin.User != "" && payload.Admin.Hash != "" {
			st.Admin = payload.Admin
		}

		if sameHost || localAction == "restore" || localAction == "migrate" {
			if payload.Source.ThisGroup != "" && (mode == "replace" || st.ThisGroup == "") {
				st.ThisGroup = payload.Source.ThisGroup
			}
			if payload.Source.ThisName != "" && (mode == "replace" || st.ThisName == "") {
				st.ThisName = payload.Source.ThisName
			}
		}

		if mode == "replace" {
			st.Servers = sealedServers
			st.CFAccounts = sealedCF
			st.AutoHeal = map[string]AutoHealConfig{}
		} else {
			for _, ns := range sealedServers {
				replaced := false
				for i := range st.Servers {
					if st.Servers[i].ID == ns.ID || (ns.Address != "" && strings.EqualFold(st.Servers[i].Address, ns.Address)) {
						ns.ID = st.Servers[i].ID
						st.Servers[i] = ns
						replaced = true
						break
					}
				}
				if !replaced {
					st.Servers = append(st.Servers, ns)
				}
			}
			for _, nc := range sealedCF {
				replaced := false
				for i := range st.CFAccounts {
					if st.CFAccounts[i].ID == nc.ID || (nc.Name != "" && strings.EqualFold(st.CFAccounts[i].Name, nc.Name)) {
						nc.ID = st.CFAccounts[i].ID
						st.CFAccounts[i] = nc
						replaced = true
						break
					}
				}
				if !replaced {
					st.CFAccounts = append(st.CFAccounts, nc)
				}
			}
		}

		if st.AutoHeal == nil && len(payload.AutoHeal) > 0 {
			st.AutoHeal = make(map[string]AutoHealConfig, len(payload.AutoHeal))
		}
		for k, v := range payload.AutoHeal {
			st.AutoHeal[k] = v
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("saving restored state: %w", err)
	}

	res.ServersRestored = len(sealedServers)
	res.CFAccountsRestored = len(sealedCF)
	res.AutoHealRestored = len(payload.AutoHeal)

	// 3. Refresh all servers and re-seed Reverse Control Hub (/api/callhome)
	// so every reachable agent learns this panel's current IPv4/IPv6 URLs and fingerprint.
	curServers := p.store.get().Servers
	var seedWG sync.WaitGroup
	var seededMu sync.Mutex
	var unreachableCallHome []string
	for _, srv := range curServers {
		seedWG.Add(1)
		go func(s Server) {
			defer seedWG.Done()
			p.fleet.seedCallHome(s)
			p.fleet.refresh(s)
			p.fleet.mu.Lock()
			h := p.fleet.by[s.ID]
			online := h != nil && h.err == nil
			p.fleet.mu.Unlock()
			seededMu.Lock()
			if online {
				res.CallHomeSeeded++
			} else if s.CallsPanel && !sameHost {
				unreachableCallHome = append(unreachableCallHome, fmt.Sprintf("%s (%s)", s.Name, s.Address))
			}
			seededMu.Unlock()
		}(srv)
	}
	seedWG.Wait()

	// 4. Restore or migrate local ("This Server") tunnels if requested.
	if (localAction == "restore" || localAction == "migrate") && len(payload.LocalTunnels) > 0 {
		for _, snap := range payload.LocalTunnels {
			newLocalIP := ""
			if localAction == "migrate" && !sameHost {
				newLocalIP = pickMigratedLocalIP(snap.Conf, localOv.IPv4, localOv.IPv6)
			}
			impRes, err := agent.ImportTunnel(snap, p.tunnelsDir, true, newLocalIP)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Local tunnel %q could not be started on this server: %s", snap.Name, err.Error()))
				continue
			}
			res.LocalTunnelsRestored++

			// If migrating to a new server IP, automatically update the remote peer
			// so the other half of the tunnel points to this new server's IP.
			if localAction == "migrate" && !sameHost && newLocalIP != "" {
				if updated, warn := p.updateRemotePeerForMigratedTunnel(ctx, payload, snap, impRes.Code, newLocalIP); updated {
					res.RemotePeersUpdated++
				} else if warn != "" {
					res.Warnings = append(res.Warnings, warn)
				}
			}
		}
		if localAction == "migrate" && !sameHost && res.LocalTunnelsRestored > 0 {
			curIP := strings.Join(localOv.IPv4, ", ")
			res.ActionsNeeded = append(res.ActionsNeeded,
				fmt.Sprintf("Local tunnel(s) were migrated to this new server (%s). Remember to update your users' client configurations or DNS records to point to %s (and stop those tunnels on the old server if it is still running).", curIP, curIP))
		}
	} else if localAction == "skip" && len(payload.LocalTunnels) > 0 && !sameHost {
		srcIP := strings.Join(payload.Source.IPv4, ", ")
		if srcIP == "" {
			srcIP = payload.Source.ThisName
		}
		res.ActionsNeeded = append(res.ActionsNeeded,
			fmt.Sprintf("The old panel server (%s) had %d local tunnel(s) (%s) that were kept untouched on %s. If %s is still active as a %s server, click \"+ Add Server\" and add %s via SSH so this new panel manages it and its tunnels.",
				srcIP, len(payload.LocalTunnels), joinTunnelNames(payload.LocalTunnels), srcIP, srcIP,
				orDefault(payload.Source.ThisGroup, "relay"), srcIP))
	}

	// 5. Optionally re-deploy any missing tunnels onto remote servers.
	if opts.RedeployRemoteTunnels {
		res.RemoteTunnelsJoined = p.redeployMissingRemoteTunnels(ctx, payload, &res.Warnings)
		p.fleet.refreshAll()
	}

	if len(unreachableCallHome) > 0 {
		res.ActionsNeeded = append(res.ActionsNeeded,
			fmt.Sprintf("Server(s) in 'Agent calls panel' mode (%s) could not be reached directly from this new server to push the new panel IP. Click \"Update via SSH\" on their server card once (or point your panel domain to this server's IP) so they connect in.",
				strings.Join(unreachableCallHome, ", ")))
	}

	return res, nil
}

func (p *Panel) updateRemotePeerForMigratedTunnel(ctx context.Context, payload *BackupPayload, snap agent.TunnelSnapshot, newCode, newLocalIP string) (bool, string) {
	var pt *BackupPairedTunnel
	for i := range payload.PairedTunnels {
		if payload.PairedTunnels[i].Name == snap.Name {
			pt = &payload.PairedTunnels[i]
			break
		}
	}
	if pt == nil {
		return false, ""
	}
	rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	// Case 1: "This Server" is the Relay (edge) half, and a remote managed server is the Foreign (origin) half.
	if snap.Role == "edge" && pt.OriginServerID != "" && pt.OriginServerID != "this" && newCode != "" {
		targetID := p.resolveRestoredServerID(pt.OriginServerID, pt.OriginAddress)
		if targetID == "" {
			return false, fmt.Sprintf("Tunnel %q: remote foreign server (%s) not found to update peer IP.", snap.Name, pt.OriginServerName)
		}
		var upd struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_, err := p.callJSON(rctx, targetID, "/api/tunnel/update", map[string]string{"code": newCode}, &upd)
		if err != nil || !upd.OK {
			// If the tunnel didn't exist on the foreign server yet, try join.
			_, err2 := p.callJSON(rctx, targetID, "/api/tunnel/join", map[string]string{"code": newCode}, &upd)
			if err2 != nil || !upd.OK {
				msg := upd.Error
				if err != nil {
					msg = plainAgentError(err)
				}
				return false, fmt.Sprintf("Tunnel %q: could not update foreign server %s with new panel IP (%s): %s", snap.Name, pt.OriginServerName, newLocalIP, msg)
			}
		}
		p.refreshOne(targetID)
		return true, ""
	}

	// Case 2: "This Server" is the Foreign (origin) half, and a remote managed server is the Relay (edge) half.
	if snap.Role == "origin" && pt.EdgeServerID != "" && pt.EdgeServerID != "this" {
		targetID := p.resolveRestoredServerID(pt.EdgeServerID, pt.EdgeAddress)
		if targetID == "" {
			return false, fmt.Sprintf("Tunnel %q: remote relay server (%s) not found to update peer IP.", snap.Name, pt.EdgeServerName)
		}
		var editRes agent.EdgeResult
		_, err := p.callJSON(rctx, targetID, "/api/tunnel/edit-edge", agent.EditSpec{
			Name:   snap.Name,
			PeerIP: newLocalIP,
		}, &editRes)
		if err != nil || !editRes.OK {
			msg := editRes.Error
			if err != nil {
				msg = plainAgentError(err)
			}
			return false, fmt.Sprintf("Tunnel %q: could not update relay server %s with new foreign IP (%s): %s", snap.Name, pt.EdgeServerName, newLocalIP, msg)
		}
		if editRes.Code != "" {
			var upd struct {
				OK bool `json:"ok"`
			}
			_, _ = p.callJSON(rctx, "this", "/api/tunnel/update", map[string]string{"code": editRes.Code}, &upd)
		}
		p.refreshOne(targetID)
		return true, ""
	}

	return false, ""
}

func (p *Panel) redeployMissingRemoteTunnels(ctx context.Context, payload *BackupPayload, warns *[]string) int {
	deployed := 0
	for _, bs := range payload.Servers {
		targetID := p.resolveRestoredServerID(bs.ID, bs.Address)
		if targetID == "" || targetID == "this" {
			continue
		}
		for _, snap := range bs.Tunnels {
			rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
			var imp agent.EdgeResult
			status, err := p.callJSON(rctx, targetID, "/api/tunnels/import", map[string]any{
				"tunnel":    snap,
				"overwrite": false,
			}, &imp)
			cancel()
			if err == nil && imp.OK {
				deployed++
				continue
			}
			if status == http.StatusNotFound && snap.Role == "origin" && snap.PairingCode != "" {
				rctx2, cancel2 := context.WithTimeout(ctx, 25*time.Second)
				var jres struct {
					OK bool `json:"ok"`
				}
				if _, jerr := p.callJSON(rctx2, targetID, "/api/tunnel/join", map[string]string{"code": snap.PairingCode}, &jres); jerr == nil && jres.OK {
					deployed++
				}
				cancel2()
			} else if err != nil {
				*warns = append(*warns, fmt.Sprintf("Could not verify tunnel %q on %s: %s", snap.Name, bs.Name, plainAgentError(err)))
			}
		}
	}

	// Also check PairedTunnels where we have a PairingCode for an Origin server
	// that might not have had /api/tunnels/export at backup time.
	views := p.fleet.views()
	hasTunnelOn := func(srvID, tunName string) bool {
		for _, v := range views {
			if v.ID == srvID && v.Overview != nil {
				for _, t := range v.Overview.Tunnels {
					if t.Name == tunName {
						return true
					}
				}
			}
		}
		return false
	}
	for _, pt := range payload.PairedTunnels {
		if pt.PairingCode == "" || pt.OriginServerID == "" || pt.OriginServerID == "this" {
			continue
		}
		targetID := p.resolveRestoredServerID(pt.OriginServerID, pt.OriginAddress)
		if targetID == "" || hasTunnelOn(targetID, pt.Name) {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		var jres struct {
			OK bool `json:"ok"`
		}
		if _, err := p.callJSON(rctx, targetID, "/api/tunnel/join", map[string]string{"code": pt.PairingCode}, &jres); err == nil && jres.OK {
			deployed++
		}
		cancel()
	}
	return deployed
}

func (p *Panel) resolveRestoredServerID(id, addr string) string {
	if id == "this" {
		return "this"
	}
	for _, s := range p.store.get().Servers {
		if s.ID == id {
			return s.ID
		}
	}
	if addr != "" {
		for _, s := range p.store.get().Servers {
			if strings.EqualFold(s.Address, addr) {
				return s.ID
			}
		}
	}
	return ""
}

func pickMigratedLocalIP(conf string, v4, v6 []string) string {
	for _, l := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(l)
		k, v, ok := strings.Cut(t, "=")
		if ok && strings.TrimSpace(k) == "local_ip" {
			oldIP := strings.TrimSpace(v)
			if strings.Contains(oldIP, ":") && len(v6) > 0 {
				return v6[0]
			}
			if len(v4) > 0 {
				return v4[0]
			}
		}
	}
	if len(v4) > 0 {
		return v4[0]
	}
	if len(v6) > 0 {
		return v6[0]
	}
	return ""
}

func isOwnAddress(addr string, v4, v6 []string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	for _, ip := range v4 {
		if strings.EqualFold(addr, ip) {
			return true
		}
	}
	for _, ip := range v6 {
		if strings.EqualFold(addr, ip) {
			return true
		}
	}
	return false
}

func tlsLoadPair(certPEM, keyPEM string) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

func joinTunnelNames(snaps []agent.TunnelSnapshot) string {
	names := make([]string, 0, len(snaps))
	for _, s := range snaps {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (p *Panel) handleBackupCreate(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	pass := strings.TrimSpace(req.Passphrase)
	if pass != "" && len(pass) < 6 {
		writeErr(w, http.StatusBadRequest, "Backup password must be at least 6 characters (or leave empty for an unencrypted backup).")
		return
	}
	env, err := p.CreateBackup(r.Context(), pass)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, capitalise(err.Error())+".")
		return
	}
	dateStr := time.Now().UTC().Format("2006-01-02-1504")
	filename := fmt.Sprintf("portbridge-backup-%s.json", dateStr)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"filename": filename,
		"backup":   env,
	})
}

func (p *Panel) handleBackupInspect(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		BackupJSON string `json:"backup_json"`
		Passphrase string `json:"passphrase"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.BackupJSON) == "" {
		writeErr(w, http.StatusBadRequest, "Choose a PortBridge backup file first.")
		return
	}
	rep, err := p.InspectBackup([]byte(req.BackupJSON), strings.TrimSpace(req.Passphrase))
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (p *Panel) handleBackupRestore(w http.ResponseWriter, r *http.Request, a authed) {
	agent.ExtendDeadlines(w, 2*time.Minute)
	var req struct {
		BackupJSON string         `json:"backup_json"`
		Options    RestoreOptions `json:"options"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.BackupJSON) == "" {
		writeErr(w, http.StatusBadRequest, "Choose a PortBridge backup file first.")
		return
	}
	res, err := p.RestoreBackup(r.Context(), []byte(req.BackupJSON), req.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	// If the admin username changed because RestoreCredentials was requested,
	// keep the current browser session logged in under the restored username.
	if req.Options.RestoreCredentials {
		curUser := p.store.get().Admin.User
		if curUser != "" && (a.s == nil || curUser != a.s.user) {
			id, s := p.sessions.create(curUser)
			setSessionCookie(w, id)
			writeJSON(w, http.StatusOK, map[string]any{
				"result": res,
				"user":   s.user,
				"csrf":   s.csrf,
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": res,
	})
}

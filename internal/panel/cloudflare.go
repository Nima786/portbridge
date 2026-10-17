package panel

// Talking to Cloudflare's DNS API on the user's behalf.
//
// Each API token is encrypted with secret.key in state.json (the same AES-GCM
// key used for agent tokens) and is never sent back to the browser once saved.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var cfAPIBase = "https://api.cloudflare.com/client/v4"

var cfHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
}

// cfAccountView is the public view of a saved Cloudflare token. The token
// itself is never included here.
type cfAccountView struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Hint  string    `json:"hint"`
	Added time.Time `json:"added"`
}

type cfZoneView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
}

type cfRecordView struct {
	ID        string `json:"id"`
	ZoneID    string `json:"zone_id,omitempty"`
	ZoneName  string `json:"zone_name,omitempty"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Proxied   bool   `json:"proxied"`
	Proxiable bool   `json:"proxiable"`
	TTL       int    `json:"ttl"`
	Comment   string `json:"comment,omitempty"`
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func validCFID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validCFToken(s string) bool {
	if len(s) < 10 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func maskCFToken(token string) string {
	if len(token) <= 4 {
		return "••••"
	}
	return "••••" + token[len(token)-4:]
}

func (p *Panel) cfTokenFor(accountID string) (CFAccount, string, error) {
	accts := p.store.get().CFAccounts
	if len(accts) == 0 {
		return CFAccount{}, "", errors.New("no Cloudflare API token is saved yet")
	}
	var chosen CFAccount
	if accountID == "" {
		chosen = accts[0]
	} else {
		found := false
		for _, a := range accts {
			if a.ID == accountID {
				chosen = a
				found = true
				break
			}
		}
		if !found {
			return CFAccount{}, "", errors.New("that Cloudflare account was not found")
		}
	}
	tok, err := p.store.open(chosen.TokenEnc)
	if err != nil {
		return CFAccount{}, "", err
	}
	return chosen, tok, nil
}

func cfDo(ctx context.Context, token, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfAPIBase, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := cfHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("reaching Cloudflare API: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("reading Cloudflare response: %w", err)
	}

	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		if resp.StatusCode >= 400 {
			return fmt.Errorf("Cloudflare returned HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("invalid response from Cloudflare: %w", err)
	}
	if !env.Success || resp.StatusCode >= 400 {
		if len(env.Errors) > 0 && env.Errors[0].Message != "" {
			return fmt.Errorf("Cloudflare: %s", env.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare request failed (HTTP %d)", resp.StatusCode)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("decoding Cloudflare result: %w", err)
		}
	}
	return nil
}

// verifyCFToken confirms the token can list zones on Cloudflare.
func verifyCFToken(ctx context.Context, token string) error {
	var zones []struct {
		ID string `json:"id"`
	}
	return cfDo(ctx, token, http.MethodGet, "/zones?per_page=1", nil, &zones)
}

func (p *Panel) handleGetCFAccounts(w http.ResponseWriter, _ *http.Request, _ authed) {
	accts := p.store.get().CFAccounts
	out := make([]cfAccountView, 0, len(accts))
	for _, a := range accts {
		out = append(out, cfAccountView{
			ID:    a.ID,
			Name:  a.Name,
			Hint:  a.Hint,
			Added: a.Added,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

func (p *Panel) handleAddCFAccount(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Token = strings.TrimSpace(req.Token)
	if req.Name == "" {
		req.Name = "Cloudflare"
	}
	if len(req.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "account label is too long (max 64 characters)")
		return
	}
	if !validCFToken(req.Token) {
		writeErr(w, http.StatusBadRequest, "please enter a valid Cloudflare API token")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := verifyCFToken(ctx, req.Token); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	sealed, err := p.store.seal(req.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	acct := CFAccount{
		ID:       newID(9),
		Name:     req.Name,
		TokenEnc: sealed,
		Hint:     maskCFToken(req.Token),
		Added:    time.Now().UTC(),
	}
	if err := p.store.update(func(st *State) error {
		st.CFAccounts = append(st.CFAccounts, acct)
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, cfAccountView{
		ID:    acct.ID,
		Name:  acct.Name,
		Hint:  acct.Hint,
		Added: acct.Added,
	})
}

func (p *Panel) handleDeleteCFAccount(w http.ResponseWriter, r *http.Request, _ authed) {
	id := r.PathValue("id")
	var found bool
	if err := p.store.update(func(st *State) error {
		out := st.CFAccounts[:0]
		for _, a := range st.CFAccounts {
			if a.ID == id {
				found = true
				continue
			}
			out = append(out, a)
		}
		st.CFAccounts = out
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "that Cloudflare account was not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleGetCFZones(w http.ResponseWriter, r *http.Request, _ authed) {
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	accts := p.store.get().CFAccounts
	if len(accts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"zones": []cfZoneView{}})
		return
	}

	var targets []CFAccount
	if accountID != "" {
		for _, a := range accts {
			if a.ID == accountID {
				targets = append(targets, a)
				break
			}
		}
		if len(targets) == 0 {
			writeErr(w, http.StatusNotFound, "that Cloudflare account was not found")
			return
		}
	} else {
		targets = accts
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var allZones []cfZoneView
	var firstErr error
	for _, a := range targets {
		tok, err := p.store.open(a.TokenEnc)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var rawZones []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := cfDo(ctx, tok, http.MethodGet, "/zones?per_page=50", nil, &rawZones); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, z := range rawZones {
			allZones = append(allZones, cfZoneView{
				ID:          z.ID,
				Name:        z.Name,
				Status:      z.Status,
				AccountID:   a.ID,
				AccountName: a.Name,
			})
		}
	}

	if len(allZones) == 0 && firstErr != nil {
		writeErr(w, http.StatusBadGateway, firstErr.Error())
		return
	}
	if allZones == nil {
		allZones = []cfZoneView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": allZones})
}

func (p *Panel) handleGetCFRecords(w http.ResponseWriter, r *http.Request, _ authed) {
	zoneID := r.PathValue("zoneID")
	if !validCFID(zoneID) {
		writeErr(w, http.StatusBadRequest, "invalid zone ID")
		return
	}
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	_, tok, err := p.cfTokenFor(accountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var records []cfRecordView
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records?per_page=100"
	if err := cfDo(ctx, tok, http.MethodGet, path, nil, &records); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if records == nil {
		records = []cfRecordView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

type cfRecordPayload struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func validateCFRecordInput(recType, name, content string, ttl int, proxied bool) (cfRecordPayload, error) {
	recType = strings.ToUpper(strings.TrimSpace(recType))
	switch recType {
	case "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA":
	default:
		return cfRecordPayload{}, errors.New("unsupported DNS record type")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 253 {
		return cfRecordPayload{}, errors.New("please enter a record name (use @ for the root domain)")
	}
	content = strings.TrimSpace(content)
	if content == "" || len(content) > 2048 {
		return cfRecordPayload{}, errors.New("please enter the record target / IP address")
	}
	if ttl <= 0 {
		ttl = 1 // 1 = Automatic in Cloudflare
	} else if ttl != 1 && (ttl < 60 || ttl > 86400) {
		return cfRecordPayload{}, errors.New("TTL must be 1 (Auto) or between 60 and 86400 seconds")
	}
	out := cfRecordPayload{
		Type:    recType,
		Name:    name,
		Content: content,
		TTL:     ttl,
	}
	if recType == "A" || recType == "AAAA" || recType == "CNAME" {
		p := proxied
		if p {
			out.TTL = 1
		}
		out.Proxied = &p
	}
	return out, nil
}

func (p *Panel) handleCreateCFRecord(w http.ResponseWriter, r *http.Request, _ authed) {
	zoneID := r.PathValue("zoneID")
	if !validCFID(zoneID) {
		writeErr(w, http.StatusBadRequest, "invalid zone ID")
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Content   string `json:"content"`
		TTL       int    `json:"ttl"`
		Proxied   bool   `json:"proxied"`
		Comment   string `json:"comment"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	payload, err := validateCFRecordInput(req.Type, req.Name, req.Content, req.TTL, req.Proxied)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	payload.Comment = strings.TrimSpace(req.Comment)

	_, tok, err := p.cfTokenFor(strings.TrimSpace(req.AccountID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var created cfRecordView
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	if err := cfDo(ctx, tok, http.MethodPost, path, payload, &created); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, created)
}

func (p *Panel) handleUpdateCFRecord(w http.ResponseWriter, r *http.Request, _ authed) {
	zoneID := r.PathValue("zoneID")
	recordID := r.PathValue("recordID")
	if !validCFID(zoneID) || !validCFID(recordID) {
		writeErr(w, http.StatusBadRequest, "invalid zone or record ID")
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Content   string `json:"content"`
		TTL       int    `json:"ttl"`
		Proxied   bool   `json:"proxied"`
		Comment   string `json:"comment"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	payload, err := validateCFRecordInput(req.Type, req.Name, req.Content, req.TTL, req.Proxied)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	payload.Comment = strings.TrimSpace(req.Comment)

	_, tok, err := p.cfTokenFor(strings.TrimSpace(req.AccountID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var updated cfRecordView
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	if err := cfDo(ctx, tok, http.MethodPut, path, payload, &updated); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (p *Panel) handlePatchCFRecord(w http.ResponseWriter, r *http.Request, _ authed) {
	zoneID := r.PathValue("zoneID")
	recordID := r.PathValue("recordID")
	if !validCFID(zoneID) || !validCFID(recordID) {
		writeErr(w, http.StatusBadRequest, "invalid zone or record ID")
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		Proxied   bool   `json:"proxied"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	_, tok, err := p.cfTokenFor(strings.TrimSpace(req.AccountID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var updated cfRecordView
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	body := map[string]any{"proxied": req.Proxied}
	if err := cfDo(ctx, tok, http.MethodPatch, path, body, &updated); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (p *Panel) handleDeleteCFRecord(w http.ResponseWriter, r *http.Request, _ authed) {
	zoneID := r.PathValue("zoneID")
	recordID := r.PathValue("recordID")
	if !validCFID(zoneID) || !validCFID(recordID) {
		writeErr(w, http.StatusBadRequest, "invalid zone or record ID")
		return
	}
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	_, tok, err := p.cfTokenFor(accountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	if err := cfDo(ctx, tok, http.MethodDelete, path, nil, nil); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

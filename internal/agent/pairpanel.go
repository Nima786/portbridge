package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

// HubRegisterRequest is sent by "portbridge agent pair-panel" to register a
// hard-to-reach server with the panel using a short-lived one-time ticket.
type HubRegisterRequest struct {
	Ticket      string   `json:"ticket"`
	Token       string   `json:"token"`
	Port        int      `json:"port"`
	Fingerprint string   `json:"fingerprint"`
	Hostname    string   `json:"hostname"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
	Version     string   `json:"version"`
}

// HubRegisterReply is the panel's answer to /hub/register.
type HubRegisterReply struct {
	OK       bool   `json:"ok"`
	ServerID string `json:"server_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Error    string `json:"error,omitempty"`
}

func cmdAgentPairPanel(args []string) error {
	fs := flag.NewFlagSet("agent pair-panel", flag.ExitOnError)
	confPath := fs.String("config", defaultAgentConf, "path to the agent's settings")
	port := fs.Int("port", 0, "port for the agent to listen on (default: keep its port, or pick a free one)")
	panelURL := fs.String("panel-url", "", "comma-separated panel HTTPS URLs")
	panelFP := fs.String("panel-fingerprint", "", "SHA-256 fingerprint of the panel's certificate")
	ticket := fs.String("ticket", "", "one-time pairing ticket from the panel")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*panelURL) == "" {
		return errors.New("-panel-url is required")
	}
	if strings.TrimSpace(*ticket) == "" {
		return errors.New("-ticket is required")
	}
	res, err := agentSetup(*confPath, *port, *panelURL, *panelFP, "on")
	if err != nil {
		return err
	}
	ov := LocalOverview(defaultTunnelsDir)
	reg := HubRegisterRequest{
		Ticket:      strings.TrimSpace(*ticket),
		Token:       res.Token,
		Port:        res.Port,
		Fingerprint: res.Fingerprint,
		Hostname:    ov.Hostname,
		IPv4:        ov.IPv4,
		IPv6:        ov.IPv6,
		Version:     engine.Version,
	}
	rep, usedURL, err := RegisterWithPanel(context.Background(), *panelURL, *panelFP, reg)
	if err != nil {
		return err
	}
	fmt.Printf("Paired %q with the panel via %s (agent port %d).\n", rep.Name, usedURL, res.Port)
	return nil
}

// RegisterWithPanel tries every panel URL (domain/CDN, IPv4, IPv6) using both
// standard TLS and Stealth Chrome uTLS + ClientHello fragmentation until one
// succeeds in registering the agent with the panel.
func RegisterWithPanel(ctx context.Context, panelURLs, fingerprint string, reg HubRegisterRequest) (HubRegisterReply, string, error) {
	var out HubRegisterReply
	urls := splitPanelURLs(panelURLs)
	if len(urls) == 0 {
		return out, "", errors.New("no valid https:// panel URL provided")
	}
	payload, err := json.Marshal(reg)
	if err != nil {
		return out, "", err
	}
	cands := buildPanelClients(fingerprint, urls, 15*time.Second)
	var errs []string
	for _, cand := range cands {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, rerr := http.NewRequestWithContext(rctx, http.MethodPost, cand.url+"/hub/register", bytes.NewReader(payload))
		if rerr != nil {
			cancel()
			errs = append(errs, rerr.Error())
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, derr := cand.client.Do(req)
		if derr != nil {
			cancel()
			errs = append(errs, fmt.Sprintf("%s: %v", cand.label, derr))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		_ = resp.Body.Close()
		cancel()
		_ = json.Unmarshal(body, &out)
		if resp.StatusCode == http.StatusOK && out.OK {
			return out, cand.label, nil
		}
		if out.Error != "" {
			return out, cand.label, errors.New(out.Error)
		}
		errs = append(errs, fmt.Sprintf("%s: HTTP %d", cand.label, resp.StatusCode))
	}
	return out, "", fmt.Errorf("could not reach the panel over any path (%s)", strings.Join(errs, "; "))
}

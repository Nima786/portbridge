package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Which public addresses does this server have?
//
// The menu offers to connect the two servers over IPv6 when both have a public
// IPv6 address, and it needs to know them. This server's own come from its
// network cards; the foreign server's are asked of its agent.

// publicAddresses sorts the addresses of the network cards into public IPv4 and
// public IPv6 ones. Private ranges, the carrier-grade NAT range, link-local and
// unique-local (fc00::/7) addresses are left out: none of them can be reached from
// the other server.
func publicAddresses(addrs []net.Addr) (v4, v6 []string) {
	for _, a := range addrs {
		var ip net.IP
		switch x := a.(type) {
		case *net.IPNet:
			ip = x.IP
		case *net.IPAddr:
			ip = x.IP
		}
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		if p4 := ip.To4(); p4 != nil {
			// 100.64.0.0/10 is the carrier-grade NAT range.
			if p4[0] == 100 && p4[1]&0xc0 == 64 {
				continue
			}
			v4 = append(v4, p4.String())
			continue
		}
		// Public IPv6 is 2000::/3.
		if ip[0]&0xe0 == 0x20 {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

func localPublicAddresses() (v4, v6 []string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}
	return publicAddresses(addrs)
}

// addressLines is the plain form the menu reads: "ipv4 <address>" and
// "ipv6 <address>", one to a line.
func addressLines(v4, v6 []string) string {
	var b strings.Builder
	for _, a := range v4 {
		fmt.Fprintf(&b, "ipv4 %s\n", a)
	}
	for _, a := range v6 {
		fmt.Fprintf(&b, "ipv6 %s\n", a)
	}
	return b.String()
}

// cmdAddresses handles "portbridge addresses".
func cmdAddresses() {
	v4, v6 := localPublicAddresses()
	fmt.Print(addressLines(v4, v6))
}

// addressesHandler answers GET /api/addresses on the agent.
func addressesHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		v4, v6 := localPublicAddresses()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ipv4": v4, "ipv6": v6})
	}
}

// agentClientAddresses asks a remote agent for its server's public addresses and
// prints them in the same form as the local command.
func agentClientAddresses(agentURL, token string, trust agentTrust) error {
	agentURL = strings.TrimRight(agentURL, "/")
	req, err := http.NewRequest(http.MethodGet, agentURL+"/api/addresses", bytes.NewReader(nil))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := makeAgentHTTPClient(trust, agentURL)
	client.Timeout = 12 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return explainAgentError(fmt.Errorf("connecting to agent at %s: %w", agentURL, err), trust)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("the agent on that server is too old to report its addresses; update PortBridge there first")
	}
	var res struct {
		OK   bool     `json:"ok"`
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &res) != nil || !res.OK {
		return fmt.Errorf("the agent could not report its addresses (HTTP %d)", resp.StatusCode)
	}
	fmt.Print(addressLines(res.IPv4, res.IPv6))
	return nil
}

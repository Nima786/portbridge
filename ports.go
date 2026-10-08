package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Which ports can a tunnel use?
//
// A tunnel's link needs a port that is free on the server that listens for it,
// and a CDN will only forward a handful of ports, which are easy to forget and
// are usually taken by a web server or a panel. This answers for one server; the
// menu asks both servers (the other through its agent) and puts the answers side
// by side, so the choice is made once, with the facts in front of it.

// defaultPortsToCheck are the ports a CDN forwards. Cloudflare forwards the first
// six; the rest are the extra ones other providers, such as ArvanCloud, forward.
const defaultPortsToCheck = "443,2053,2083,2087,2096,8443,80,8080,8880,2052,2082,2086,2095"

// portStatus is one port on one server.
type portStatus struct {
	Port  int    `json:"port"`
	State string `json:"state"`        // "free", "busy" or "reserved"
	By    string `json:"by,omitempty"` // what has it, when that is known
}

// parsePortList reads a list of ports separated by commas or spaces. Duplicates
// are dropped, the order is kept, and anything that is not a port is refused.
func parsePortList(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q is not a port number", f)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports given")
	}
	if len(out) > 64 {
		return nil, errors.New("too many ports at once (the most is 64)")
	}
	return out, nil
}

// portReport says, for each port asked about, whether this server can give it to
// a tunnel.
//
// "busy" means something is listening on it. "reserved" means nothing is, yet,
// but one of this server's tunnels is set to use it, so it would clash as soon
// as that tunnel starts: a stopped tunnel still owns its port.
func portReport(confDir string, ports []int, host agentHost) []portStatus {
	claims := map[int]claimedPort{}
	for _, c := range portsClaimedByOthers(confDir, "") {
		if _, ok := claims[c.port]; !ok {
			claims[c.port] = c
		}
	}
	out := make([]portStatus, 0, len(ports))
	for _, p := range ports {
		st := portStatus{Port: p, State: "free"}
		claim, claimed := claims[p]
		busy := host.PortFree(TransportPlain, p) != nil
		owner := ""
		if busy {
			owner = host.ListenOwner(p)
		}
		switch {
		case claimed:
			st.State = "busy"
			st.By = fmt.Sprintf("PortBridge tunnel %s (%s)", claim.tunnel, claim.what)
			if !busy {
				st.State = "reserved"
			}
		case busy:
			st.State = "busy"
			st.By = owner
		}
		out = append(out, st)
	}
	return out
}

// portLines is the plain form the menu reads: port, state and owner, separated
// by tabs, one port to a line.
func portLines(rs []portStatus) string {
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "%d\t%s\t%s\n", r.Port, r.State, r.By)
	}
	return b.String()
}

var ssUsersRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

// listenOwnerFromSS pulls the program name out of one line of "ss -ltnp".
func listenOwnerFromSS(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if m := ssUsersRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

// ListenOwner names the program listening on a port, if the machine will say.
func (systemHost) ListenOwner(port int) string {
	out, err := hostRun("ss", "-H", "-ltnp", "sport = :"+strconv.Itoa(port))
	if err != nil {
		return ""
	}
	return listenOwnerFromSS(out)
}

func (noHost) ListenOwner(int) string { return "" }

// portsHandler answers POST /api/ports on the agent.
func portsHandler(token, confDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
		if err != nil {
			http.Error(w, `{"error":"reading body"}`, http.StatusBadRequest)
			return
		}
		var req struct {
			Ports string `json:"ports"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"json body with ports required"}`, http.StatusBadRequest)
			return
		}
		ports, err := parsePortList(req.Ports)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    true,
			"ports": portReport(confDir, ports, hostFor(confDir)),
		})
	}
}

// agentClientPorts asks a remote agent about a list of ports and prints the
// answer in the same form as the local command.
func agentClientPorts(agentURL, token, list string, trust agentTrust) error {
	agentURL = strings.TrimRight(agentURL, "/")
	payload, _ := json.Marshal(map[string]string{"ports": list})
	req, err := http.NewRequest(http.MethodPost, agentURL+"/api/ports", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := makeAgentHTTPClient(trust, agentURL)
	client.Timeout = 30 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return explainAgentError(fmt.Errorf("connecting to agent at %s: %w", agentURL, err), trust)
	}
	defer resp.Body.Close()

	var res struct {
		OK    bool         `json:"ok"`
		Error string       `json:"error"`
		Ports []portStatus `json:"ports"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("the agent on that server is too old to report its ports; update PortBridge there first")
	}
	if resp.StatusCode != http.StatusOK || !res.OK {
		if res.Error != "" {
			return fmt.Errorf("the agent could not report its ports: %s", res.Error)
		}
		return fmt.Errorf("the agent could not report its ports (HTTP %d)", resp.StatusCode)
	}
	fmt.Print(portLines(res.Ports))
	return nil
}

// cmdPorts handles "portbridge ports [list]": which of the ports can this server
// give a tunnel?
func cmdPorts(args []string) error {
	list := defaultPortsToCheck
	if len(args) > 0 {
		list = strings.Join(args, ",")
	}
	ports, err := parsePortList(list)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "note: not running as root, so ports below 1024 cannot be tried and may be reported wrongly")
	}
	fmt.Print(portLines(portReport(defaultTunnelsDir, ports, hostFor(defaultTunnelsDir))))
	return nil
}

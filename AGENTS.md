# Repository Guidelines for PortBridge

## Layout

- `cmd/portbridge/` – the program's starting point only: picks a command and
  hands it to the right part. The release number is stamped here
  (`-X main.version=...`) and passed to the engine.
- `internal/engine/` – the tunnel itself: settings, both halves (edge and
  origin), link disguises, shared connections, routes and health checks, status,
  speed test, and the `run`, `check`, `teardown` and `speedtest` commands.
- `internal/agent/` – the management agent, pairing codes, port checks, and the
  `agent`, `join`, `ports` and `addresses` commands. It uses the engine; the
  engine never uses it.
- `internal/proxyproto/` – the PROXY protocol header (users' real addresses).
- `internal/panel/` – the web panel (`portbridge panel ...`): login, adding
  servers over SSH, talking to each server's agent directly or through the hub
  agents call in on, and the page itself in `web/` (built into the program, no
  libraries, no inline script). It uses the agent and the engine; neither uses it.
  It never writes a server's SSH password or key anywhere.
- `scripts/` – the menu, the firewall helper and the tuning helper.
- `packaging/` – the systemd units.
- `docs/` – the long explanations; the README links to them.

Build the program with `go build ./cmd/portbridge`. Tests that check the shell
scripts read them from `../../scripts/`.

## Mandatory Pre-Push CI Verification Rule
All commits pushed to GitHub MUST pass the GitHub Actions CI checks (`.github/workflows/ci.yml`).
Before pushing ANY commit to `origin/main` or any remote branch, you MUST verify:

1. **Go Code Formatting (`gofmt`)**:
   - Run `gofmt -l .` (locally or on build server).
   - The output MUST be empty. If any files are listed, format them (`gofmt -w <file>`) and commit the formatting before pushing.

2. **Shell Script Syntax & ShellCheck**:
   - Run syntax check:
     - `bash -n install.sh`
     - `bash -n scripts/portbridge-menu`
     - `bash -n scripts/portbridge-firewall`
     - `bash -n scripts/portbridge-tune`
   - Run ShellCheck matching CI:
     - `shellcheck -s bash -S warning install.sh scripts/portbridge-menu scripts/portbridge-firewall scripts/portbridge-tune`
   - Zero warnings or errors are permitted. If an intentional shell pattern triggers a false positive, suppress it explicitly with `# shellcheck disable=SCxxxx` above the line/function.

3. **Go Vet & Tests**:
   - Run `go vet ./...`
   - Run `go test -race ./...` (or run full suite on the build server `45.74.158.41`).
   - All tests must pass.

## Never Run the Tests as Root on a Real Server
The tests must be run as an ordinary user. The agent code starts services and
changes firewall rules, and although it only does that for the real settings
directory (`/etc/portbridge/tunnels`), running as root on a machine that has real
tunnels is never worth the risk. Use an unprivileged account, or a throwaway
container. Any new test that needs the machine (services, firewall, ports below
1024) must go through the replaceable host in `internal/agent/agentops.go` instead.

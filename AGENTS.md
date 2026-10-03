# Repository Guidelines for PortBridge

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

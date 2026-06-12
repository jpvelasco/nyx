# Claude Code Guidance

## Tools
Document available tools, application programming interfaces (APIs), and usage patterns here or in TOOLS.md, including the Codacy command-line interface (CLI), GitHub CLI, and **MCP (Model Context Protocol)** integrations.

### Codacy CLI (codacy-cli-v2)
**Must be run in WSL2 on this Windows machine** (native Windows is not supported per the CLI's own docs).

The binary is cached under `~/.cache/codacy/codacy-cli-v2/<version>/codacy-cli-v2`. Discover it with:
```bash
find ~/.cache/codacy/codacy-cli-v2 -name codacy-cli-v2 -type f | head -1
```

**Consult the CLI itself for help/docs** (do not guess flags):
- `codacy-cli --help`
- `codacy-cli init --help`
- `codacy-cli config --help`
- `codacy-cli config reset --help`
- `codacy-cli analyze --help`
- `codacy-cli config discover --help`
- etc.

The authoritative docs are also in the distribution:
`~/.cache/codacy/codacy-cli-v2/<version>/README.md`

**Key commands for this repo (jpvelasco/nyx):**

To (re)download the full project rules + tool configs from Codacy (what was done to initialize `.codacy/`):

```bash
# Preferred: use env var for token (avoids some quoting/flag issues in the harness)
export CODACY_API_TOKEN=...
cd /mnt/f/source/nyx   # or the WSL path to the nyx checkout
$CLI config reset --provider gh --organization jpvelasco --repository nyx
# or with explicit flag:
$CLI config reset --api-token $CODACY_API_TOKEN --provider gh --organization jpvelasco --repository nyx
```

`init` does similar bootstrapping (creates `.codacy/codacy.yaml` etc.):

```bash
$CLI init --api-token $TOKEN --provider gh --organization jpvelasco --repository nyx
```

After (re)sync:

```bash
$CLI install          # ensure runtimes + tools (cached after first run)
$CLI analyze          # all configured tools (opengrep, revive, eslint, pmd, trivy, ...)
$CLI analyze --tool revive
$CLI analyze --tool opengrep -o /tmp/opengrep.txt
```

**Config files (do not casually overwrite generated ones):**
- `.codacy/codacy.yaml` — runtimes + enabled tools list (managed by this CLI + `config reset`).
- `.codacy/tools-configs/` — the actual rule files (semgrep.yaml is huge, revive.toml, eslint.config.mjs, ruleset.xml for PMD, etc.).
- `.codacy.yml` (at repo root) — older/engines config (currently only govet + staticcheck + exclude for the npm shim). This is separate from the v2 CLI config.

We intentionally keep manual tweaks on top of what `config reset` produces:
- PMD ruleset has an `<exclude-pattern>.*/npm/.*</exclude-pattern>` (the JS shim uses top-level await + ESM-ish constructs that make the PMD JS parser emit noise).
- eslint.config.mjs ignores `npm/scripts/**` + provides node globals (the shim is a postinstall downloader, not part of the Go app; it has many intentional `nosemgrep` for fs/path/perm patterns that opengrep correctly flags in general code).

**Token handling (this repo):**
- Pass via `CODACY_API_TOKEN` env var **or** `--api-token`.
- Provider is always `gh` for this project.
- The token only needs to be present for `init` / `config reset` / analyze when you want to pull the *remote* Codacy project ruleset. Local analysis works without it once configs are present.

**WSL gotchas (from the CLI README):**
- Always run inside a real WSL distro terminal.
- The harness (pwsh calling `wsl bash -c "..."`) is fragile with multi-line strings, `$VAR` expansion, and nested quotes. Prefer one-liner commands or write temp scripts with `python3 -c '...'`.
- PATH for Go, etc. inside the codacy tool invocations is handled by the CLI (it constructs its own env with the downloaded runtimes).

**Typical local validation flow (after editing code or configs):**
1. In WSL: `export CODACY_API_TOKEN=...`
2. `cd .../nyx`
3. `.../codacy-cli-v2 config reset --provider gh --organization jpvelasco --repository nyx` (if you want latest rules)
4. `.../codacy-cli-v2 analyze`
5. Fix anything that appears (add `nosemgrep` only when the exception is truly intentional and documented, like the probe SSH key read or the nmap/system execs).

The project deliberately keeps the number of suppressions low and uses the root `.codacy.yml` `exclude_paths` + tool-level ignores where possible.

For uploading SARIF or other advanced flows, see the bundled README (upload, container-scan, etc.).

**History note:** Earlier manual runs of `config reset` + small follow-up PRs (#27, #28) were used to pull the current rule set and make the npm shim produce fewer false positives under the generated eslint/pmd configs while preserving the semgrep `nosemgrep` annotations. All checks (including Codacy's own "Static Code Analysis" and the various Analyze jobs) were green before the squash merges.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
make build        # go build -o nyx ./cmd/nyx/
make test         # go test ./...
make vet          # go vet ./...
make clean        # remove built binaries
make release      # cross-compile linux/darwin/windows (amd64+arm64)

# Run a single test package
go test ./internal/intent/...
go test ./internal/audit/...

# Run a specific test
go test -run TestParseSpec ./internal/intent/...
go test -run TestDiscoveryWarnPreserved ./internal/audit/...
```

CI runs `go vet ./...` → `go test ./...` → `go build` on every push to main and all PRs.

## Architecture

nyx is a CLI tool that validates live network behavior against a declared YAML intent model. Primary flow for the `audit` command:

```
YAML spec → intent.LoadSpec → audit.Engine.Run → []CheckResult → report.Render
```

**Key packages:**

- `internal/intent` — YAML spec types and validation. `LoadSpec`/`ParseSpec`/`ValidateSpec` are the entry points. Per-type required field validation is enforced at load time.

- `internal/models` — The `CheckResult` envelope used by every backend and assertion. All checks produce a `CheckResult` with `Status`, `Summary`, `Observed`, `Expected`, `Violations`, and `Evidence`. `AuditReport` aggregates them.

- `internal/audit` — Assertion engine. `Engine.Run` executes all assertions concurrently with per-assertion timeouts (30s default, 90s for `subnet_discovery`). Results preserve spec order.

- `internal/backends/nmap` — Wraps `nmap -sn` subprocess. `DiscoverWithOptions` accepts `ScanOptions`. Upstream `StatusWarn` (e.g. 0 hosts) is preserved — the engine does not overwrite it to pass.

- `internal/backends/system` — Platform-specific implementations (`system_linux.go`, `system_darwin.go`, `system_windows.go`) selected via Go build tags.

- `internal/backends/omada` — Read-only REST client for Omada **Software Defined Networking (SDN)** 6.x. `NewClient` calls `/api/info` unauthenticated. All authenticated calls use `/{omadaCID}/api/v2/...` with `Csrf-Token`. TLS verification intentionally skipped (self-signed cert). Not concurrency-safe.

- `internal/providers` — Provider interface (`Provider`) and registry (`Register`/`Get`/`List`/`Reset`). Providers self-register via `init()` blank imports in `cmd/nyx/main.go`. CLI vendor subcommands (`nyx omada ...`) are built dynamically in `Execute()` via `BuildProviderSubcommands`.

- `internal/providers/omada` — OmadaProvider wrapping `backends/omada`. Supports info, import, check.

- `internal/providers/opnsense` — OPNsenseProvider fully implemented (Info + ImportSpec + Check). Uses API key/secret auth.

- `internal/recommendations`
  - Analyzes `[]CheckResult` failures and produces prioritized `Recommendation` structs.
  - Called by `audit` in human mode only (not JSON).

- `internal/logger` — JSON-lines append logger with file rotation. Writes to `~/.nyx/nyx.log`. 5MB max size, 3 rotated files. Best-effort — never fails a command (unless the user explicitly requests it).

- `internal/mcp` — **Model Context Protocol (MCP)** stdio server. All tools return `CheckResult`-shaped JSON consistent with CLI `--json` output.

- `internal/report` — `RenderJSON`, `RenderHuman`, `RenderRecommendations` output renderers.

- `internal/version` — Single-source version constant. Read by `nyx version` and MCP `serverInfo.Version`.

- `internal/cli` — Cobra command definitions. Global flags (`--json`, `--output`, `--spec`, `--verbose`, `--timeout`) in `root.go`. `Execute()` calls `BuildProviderSubcommands(rootCmd)` before dispatch.

## Spec Format

Version 1 intent spec: `networks`, `vpn`, `probes`, `policies`, `assertions`.
Eight assertion types: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`, `port_check`, `dns_check`, `network_health`, `acl_check`.
`ValidateSpec` enforces required fields per type. Probes declare SSH nodes for remote checks.
See `examples/homelab.yaml` (a realistic seven-network **VLAN (Virtual Local Area Network)** example) and `testdata/valid_spec.yaml`.
The authoritative spec reference is now `docs/spec.html`.
Assertions can use `runner: <probe-name>` to execute checks remotely via SSH from a different VLAN.

## Provider System

Vendors register as providers via `init()` blank imports in `cmd/nyx/main.go`. The CLI builds `nyx omada` / `nyx opnsense` subcommands dynamically from the registry. Missing providers produce a clear error. `nyx provider list` shows all registered providers and capabilities.

## Omada Backend

Pass credentials via flags (`--host`, `--username`, `--password`) or env vars (`OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`). `nyx omada import` generates a spec YAML; `nyx omada check` imports and audits; `nyx omada info` needs no credentials.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid configuration |
| 3 | One or more warnings |

## What's Stubbed

- `internal/backends/batfish` — returns `ErrNotImplemented`, planned for v2
- HTTP MCP transport — only stdio is implemented

## Documentation

- Primary spec reference: `docs/spec.html` (modern, with diagram and light/dark support)
- Narrative walkthrough: `docs/walkthrough.md`
- The old `docs/spec.md` has been removed.

All personal/homelab-specific data has been removed from source, tests, docs, and examples for guest/viewer readiness. Personal specs belong in `specs/` (gitignored) or outside the repo.

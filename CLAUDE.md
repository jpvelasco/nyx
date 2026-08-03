# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

## Build & Test

```bash
make build        # go build -o nyx ./cmd/nyx/
make test         # go test ./... (fast, no coverage — dev iteration)
make coverage     # go test -coverprofile=coverage.out -covermode=atomic ./...
make vet          # go vet ./...
make gosec        # run gosec static analysis
make check        # full CI suite: gosec → vet → coverage → build
make lint         # golangci-lint run ./...
make clean        # remove built binaries and coverage.out
make release      # cross-compile linux/darwin/windows (amd64+arm64)

# Run a single test package
go test ./internal/intent/...
go test ./internal/audit/...

# Run a specific test
go test -run TestParseSpec ./internal/intent/...
go test -run TestDiscoveryWarnPreserved ./internal/audit/...
```

CI (`.github/workflows/ci.yml`) runs a matrix of jobs on push to `main` and PRs: `lint` (golangci-lint v2), `vuln` (govulncheck, informational — `continue-on-error`), `build` (3-OS matrix on push, 2-OS on PR), `test` (race + coverage + Codecov upload via OIDC, JUnit XML via gotestsum on Linux for Codecov Test Analytics), `goreleaser` (snapshot build + smoke test + npm shim tests), `lint-windows`, `gosec`, `trivy` (filesystem scan, fails on CRITICAL/HIGH), and `codacy-analysis` (push-to-main only, since PR-level Codacy checks come from the GitHub webhook integration). Separate workflows: `codacy-coverage.yml` (uploads the `test` job's coverage artifact to Codacy via `workflow_run`), `socket.yml` (dependency security on PRs), `octopus.yml` (PR review bot), `release.yml` (GoReleaser on `v*` tags).

`.golangci.yml` enables only `govet`, `ineffassign`, `staticcheck`, `unused`, `misspell` (+ `gofmt` formatter) — revive is intentionally disabled to avoid pre-existing style churn.

### Release flow

`.github/workflows/release.yml` runs GoReleaser. Tag `vX.Y.Z` or use `workflow_dispatch` with a version input. Builds all 6 binaries (linux/darwin/windows × amd64/arm64), generates SHA-256 checksums, extracts release notes from `CHANGELOG.md`, and creates the GitHub Release with attached artifacts. The npm package (`nyx-audit-cli`) is a thin platform-aware wrapper (`npm/`) that downloads the matching prebuilt binary from the GitHub Release on `postinstall`.

## Architecture

nyx is a CLI tool that validates live network behavior against a declared YAML intent model. Primary flow for the `audit` command:

```
YAML spec → intent.LoadSpec → audit.Engine.Run → []CheckResult → report.Render
```

`cmd/nyx/main.go` calls `cli.Execute()`. If it returns an error, `os.Exit(2)`. Exit code 1 is set inside the audit command when status is `StatusFail`.

**Key packages:**

- `internal/intent` — YAML spec types and validation. `LoadSpec`/`ParseSpec`/`ValidateSpec` are the entry points. `ValidateSpec` (`internal/intent/spec.go`) enforces required fields per assertion type at load time (e.g. `isolation` requires `from`/`to`/`expect`; `port_check` requires `target`/`ports`/`expect`). `runner:` references must be declared in the `probes` section or be `"local"`.

- `internal/models` — The `CheckResult` envelope used by every backend and assertion. All checks produce a `CheckResult` with `Status`, `Summary`, `Observed`, `Expected`, `Violations`, and `Evidence`. Callers must call `result.Finish()` before rendering. `AuditReport` aggregates them.

- `internal/audit` — Assertion engine (`engine.go`, ~1100 lines). `Engine.Run` executes all assertions concurrently with per-assertion timeouts (30s default, 90s for `subnet_discovery` — hardcoded constants, no per-spec override). Results **preserve spec order** despite concurrent execution. Runner context (`runnerCtx`) and the `SeenDB` are both populated once at the start of `Run()`, not per-assertion. Assertions with `runner: <probe>` are dispatched to `runViaProbe` instead of running against the local host directly.

- `internal/probe` — SSH execution of assertions from a remote vantage point (for multi-VLAN checks). `Run` dials the probe host, authenticates via private key and/or ssh-agent, shell-quotes args, and returns combined output. Supported assertion types over SSH: `isolation` and `network_health` (`ping -c 3 -W 3`), `port_check` (`nc -z -w 3`, first port only), `dns_check` (`nslookup`). Any other type returns an error if a runner is set. Uses `InsecureIgnoreHostKey()` when `skip_host_key_verify` is set — homelab trust model, not a security boundary.

- `internal/service` — Shared check operations (`CheckService`) used by both the CLI and the MCP server, so behavior can't drift between the two entry points. Also home to `doctor.go`'s standalone checks (`NmapCheck`, `SpecFileCheck`, `SpecValidCheck`).

- `internal/backends` — Low-level network check implementations, selected via the `Backend` interface (`backends.NewDefaultBackend()`):
  - `nmap/` — wraps `nmap -sn` subprocess for discovery; `nmap.PortScan` for port checks. Upstream `StatusWarn` (e.g. 0 hosts) is **preserved** — the engine does not overwrite it to pass.
  - `system/` — platform-specific implementations (`system_linux.go`, `system_darwin.go`, `system_windows.go`) selected via Go build tags; only `system.go` is shared. When adding system calls, provide all three platform files.
  - `dns/` — `dns_check` assertion implementation, via system resolver or a custom UDP resolver, with optional DNSSEC validation.
  - `health/` — latency, packet loss, and MTU probing for `network_health`.
  - `omada/` — read-only REST client for Omada **Software Defined Networking (SDN)** 6.x. `NewClient` calls `/api/info` unauthenticated. Authenticated calls use `/{omadaCID}/api/v2/...` with `Csrf-Token`. TLS verification intentionally skipped (self-signed cert). **Not concurrency-safe** — do not call from multiple goroutines.
  - `batfish/` — stub returning `ErrNotImplemented`; `Available()` returns `false`. Planned for v2.

- `internal/providers` — Provider interface and registry (`Register`/`Get`/`List`/`Reset`, guarded by a `sync.RWMutex`). Providers self-register via `init()` blank imports in `cmd/nyx/main.go`. CLI vendor subcommands (`nyx <vendor> info|import|check`) are built dynamically from the provider's `Capabilities()` in `Execute()` via `BuildProviderSubcommands` — no separate CLI wiring needed per vendor. **Adding a new provider requires two changes**: (1) create the package with an `init()` calling `providers.Register()`, (2) add the blank import in `main.go` — omitting the import means the provider is silently absent at runtime.
  - `providers/omada` — wraps `backends/omada`. Supports info, import, check.
  - `providers/opnsense` — fully implements `Info`, `ImportSpec`, `Check`. Uses API key/secret auth (not username/password). TLS verification disabled (self-signed cert). `ImportSpec` builds networks from interfaces, policies from deny/block/reject firewall rules, and estimates host counts from **DHCP** leases only.

- `internal/recommendations` — `engine.go` analyzes `[]CheckResult` failures and produces prioritized `Recommendation` structs, called by `audit` in human mode only (not JSON). Two-pass: classify failures into 10 categories, then generate one recommendation per category. `SpecPatch` output is diff-style (`+`/`-`) with real values from the spec. Capped at 8 recommendations per run. Pure config/credential errors (e.g. missing Omada credentials) are excluded.

- `internal/snapshot` — persists audit results to `~/.nyx/snapshots/` with rotation at 50 snapshots. Baseline is stored as `baseline.json` and is **not** rotated. `nyx drift status` falls back to the most recent saved snapshot when no fresh audit is available. Drift comparison uses a `check_type:target` key for cross-run matching.

- `internal/seendb` — persists virtual-network acknowledgements to `~/.nyx/seen.json`, used to suppress repeat `subnet_discovery` WARNs on virtual subnets (VMware, Hyper-V, WSL2) that always return 0 hosts. `seendb.Load()` never returns nil — on error it falls back to an in-memory-only DB. Concurrency-safe (`sync.Mutex`) so concurrent `subnet_discovery` assertions can ack different CIDRs simultaneously. `--warn-virtual` bypasses it to always emit WARN.

- `internal/logger` — JSON-lines append logger with file rotation, writes to `~/.nyx/nyx.log`. 5MB max size, 3 rotated files. Best-effort — never fails a command.

- `internal/mcp` — **MCP** stdio server (`server.go`). All tools return `CheckResult`-shaped JSON consistent with CLI `--json` output. Only the stdio transport is implemented; HTTP transport is stubbed.

- `internal/report` — `RenderJSON`, `RenderHuman`, `RenderRecommendations` output renderers.

- `internal/version` — Single-source version constant, injected via `-ldflags` at release build time. Read by `nyx version` and MCP `serverInfo.Version`.

- `internal/cli` — Cobra command definitions. Global flags (`--json`, `--output`, `--spec`, `--verbose`, `--timeout`) in `root.go`. `nyx init` (`init.go`) auto-detects RFC1918 interfaces + gateways via the routing table (not `.1` guessing), skips loopback/virtual/non-RFC1918 adapters, and generates a starter spec via polite nmap scans; it hard-requires nmap and fails fast if missing. `nyx doctor --spec <file>` and `nyx interfaces --spec <file>` both validate/match against a spec.

## Spec Format

Version 1 intent spec: `networks`, `vpn`, `probes`, `policies`, `assertions`.
Eight assertion types: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`, `port_check`, `dns_check`, `network_health`, `acl_check`.
`ValidateSpec` enforces required fields per type. Probes declare SSH nodes for remote checks.
See `examples/homelab.yaml` (a realistic seven-network **VLAN** example) and `testdata/valid_spec.yaml`.
The authoritative spec reference is `docs/spec.html`; narrative walkthrough is `docs/walkthrough.md`.
Assertions can use `runner: <probe-name>` to execute checks remotely via SSH from a different VLAN.

`acl_check` assertions read Omada credentials from env vars (`OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`, `OMADA_SITE`), not from the spec or flags.

## Generated Specs

Put specs generated by `nyx init` (or manually) in `specs/` — the directory is fully gitignored except `.gitignore`/`.gitkeep`. Do not commit scratch or machine-specific specs at the repo root. All personal/homelab-specific data has been removed from the repository itself (tests, docs, examples, Omada heuristics) for external viewer/collaborator readiness; personal specs must live outside source control.

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

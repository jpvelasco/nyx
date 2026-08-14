# Agent Instructions

## Build & Test

```bash
make build          # go build -o nyx ./cmd/nyx/
make test           # go test ./... (fast, no coverage — dev iteration)
make coverage       # go test -coverprofile=coverage.out (with coverage)
make vet            # go vet ./...
make gosec          # run gosec static analysis
make check          # full CI suite: gosec → vet → coverage → build
make lint           # golangci-lint run ./...
make clean          # remove built binaries and coverage.out
make release        # cross-compile linux/darwin/windows (amd64+arm64)

# Target a single package or test:
go test ./internal/intent/...
go test -run TestParseSpec ./internal/intent/...
```

Go toolchain: `go.mod` declares `go 1.25.13` — the `go` directive is authoritative over any README minimum-version claim.

Local (Windows) gotchas:
- Parallel `go test ./...` can hit localhost port-binding flakiness on this machine — prefer `go test -p 1 ./...` for reliable runs.
- `-race` cannot run locally (no C compiler/cgo). CI runs `-race` on all 3 OS legs; do not treat local non-race runs as full coverage.
- The `gh` CLI token in the Windows keyring expires periodically (HTTP 401 on API calls) — restore with `gh auth login`, then continue.

CI runs a matrix of jobs: `lint` (golangci-lint v2), `vuln` (govulncheck — a hard gate; stdlib vulnerabilities fail the check and require a `go.mod` toolchain bump), `build` (3-OS matrix), `test` (race + coverage + Codecov upload, 3-OS matrix — protect-main requires `Test (macos-latest)`), `goreleaser` (snapshot build + smoke test), `lint-windows`, `gosec`, and `trivy`. A separate `codacy-coverage.yml` workflow uploads coverage to Codacy via trusted handoff. CodeQL and Socket run on push/PR.

`.golangci.yml` enables only `govet`, `ineffassign`, `staticcheck`, `unused`, `misspell` (+ `gofmt` formatter) — revive is intentionally disabled to avoid pre-existing style churn.

### Release flow

Release workflow (`.github/workflows/release.yml`) runs GoReleaser. Tag `vX.Y.Z` or use `workflow_dispatch` with the version input. The workflow builds all 6 binaries, generates SHA-256 checksums, extracts release notes from `CHANGELOG.md`, and creates the GitHub Release with attached artifacts. The npm package `nyx-audit-cli` (`npm/`) is a thin platform-aware wrapper that downloads the matching prebuilt binary from the GitHub Release on `postinstall`.

Coverage data is uploaded to Codecov via OIDC (no token) after tests in CI.

**codecov/patch target is 90%** and CI runners have no nmap. Production code exercised only through nmap-gated tests (e.g. `internal/audit` virtual-adapter helpers) shows as uncovered on CI — add focused unit tests that run on every platform.

PRs do not edit `CHANGELOG.md`; it is populated only at release time.

## Codacy CLI (codacy-cli-v2)

**Must be run in WSL2 on this Windows machine** (native Windows unsupported). Binary cached under `~/.cache/codacy/codacy-cli-v2/<version>/codacy-cli-v2`; discover with `find ~/.cache/codacy/codacy-cli-v2 -name codacy-cli-v2 -type f | head -1`. The authoritative docs are that directory's `README.md` — consult `codacy-cli --help` / `codacy-cli <subcommand> --help` and do not guess flags.

Typical local validation flow:
1. In WSL: `export CODACY_API_TOKEN=...`
2. `cd` to the nyx checkout
3. `$CLI config reset --provider gh --organization jpvelasco --repository nyx` (pulls latest remote rules; `$CLI init ...` does similar bootstrap)
4. `$CLI install` then `$CLI analyze` (or `--tool opengrep|revive|...` to scope)

Config files (do not casually overwrite generated ones):
- `.codacy/codacy.yaml` — runtimes + enabled tools list (managed by the CLI + `config reset`).
- `.codacy/tools-configs/` — the actual rule files (semgrep.yaml, revive.toml, eslint.config.mjs, ruleset.xml for PMD).
- `.codacy.yml` (repo root) — older/engines config (govet + staticcheck + npm shim excludes); separate from the v2 CLI config.

Intentional manual tweaks on top of `config reset` output: PMD ruleset excludes `.*/npm/.*` (top-level await noise) and eslint.config.mjs ignores `npm/scripts/**` (shim is a postinstall downloader with intentional `nosemgrep` for fs/path/perm).

Token only needed for `init` / `config reset` / remote-ruleset pulls; local analysis works without it once configs are present. WSL gotchas: the pwsh → `wsl bash -c "..."` harness is fragile with multi-line strings, `$VAR` expansion, and nested quotes — prefer one-liners or temp scripts. Keep suppressions low; prefer `.codacy.yml` `exclude_paths` + tool-level ignores, add `nosemgrep` only for intentional exceptions (e.g. probe SSH key read, nmap/system execs).

## Entrypoint

`cmd/nyx/main.go` calls `cli.Execute()`. If it returns an error, `os.Exit(2)`. Exit code 1 is set inside the audit command when status is `StatusFail`.

Audit flow: `YAML spec → intent.LoadSpec → audit.Engine.Run → []CheckResult → report.Render`.

`internal/service` (`CheckService`) wraps the default backend and exposes the single-command checks (`route_check`, `vpn_route`, `ping`, `interfaces`) shared by both the CLI and the MCP server. Add new such checks here, not in `internal/mcp/`.

## Provider Registration

New providers require **two changes**:
1. Create the provider package (e.g. `internal/providers/foo/foo.go`) with an `init()` that calls `providers.Register()`.
2. Add a blank import in `cmd/nyx/main.go` (e.g. `_ "github.com/jpvelasco/nyx/internal/providers/foo"`).

Omitting the blank import means the provider is silently absent at runtime.

Provider-specific CLI commands (`nyx <vendor> info|import|check`) are built dynamically from the provider's `Capabilities()` — no separate CLI wiring needed.

### OPNsense Provider

Fully implements `Info`, `ImportSpec`, and `Check`. Uses API key/secret auth (not username/password). TLS verification is disabled (self-signed cert). ImportSpec builds networks from interfaces, policies from deny/block/reject firewall rules, and estimates host counts from **Dynamic Host Configuration Protocol (DHCP)** leases only.

## Assertion Timeouts

Per-assertion timeouts in `internal/audit/engine.go`:
- `subnet_discovery`: 90s
- All others: 30s

These are hardcoded constants — no per-assertion override via spec.

## Nmap Dependency

The `nmap` backend spawns `nmap` as a subprocess. Tests in `backends/nmap` call `nmap.Available()` and skip when missing. Any integration test or live run requires nmap installed on **$PATH (environment variable for executable search path)**.

`internal/audit` has 5 integration tests that run **real nmap sweeps** when nmap is installed (~80s for the whole package, was ~180s). They scan small dead ranges (`10.255.255.0/30`) or a `/24` derived from the machine's own virtual adapters (`audit.VirtualIfaceNetworks()`, skips when none). They skip instantly on CI (no nmap). Do not "fix" them by shortening test budgets below ~2 minutes — a timed-out run is normal for the old pre-shrink targets, not a hang.

`nyx init` hard-requires nmap and fails fast with a clear error if it is missing.

## Platform-Specific Code

`internal/backends/system` uses Go build tags: `system_linux.go`, `system_darwin.go`, `system_windows.go`. Only `system.go` is shared. When adding system calls, provide all three platform files.

## Omada Backend

- The HTTP client (`internal/backends/omada`) is **concurrency-safe**: requests are serialised through an internal mutex. It retries transient failures (network errors, HTTP 5xx) with exponential backoff (3 retries, 500ms base capped at 5s) and, on a session-expired response, performs a **single automatic re-login** using the credentials from the last successful `Login` before retrying the request.
- `Login` retains the username/password in memory for automatic session refresh; `Logout` clears them. Credentials are **never** written to logs, evidence, or recommendations.
- Optional structured operation logging (login, re-login, session expiry, retries) via `Client.SetLogger(*logger.Logger)`; wired from the CLI through `providers.ImportOptions.Logger`. Log fields never include credentials, hostnames, or IP addresses.
- `acl_check` assertions read Omada credentials from env vars (`OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`, `OMADA_SITE`), not from spec or flags.
- TLS verification is intentionally disabled (self-signed cert).

## Probe System

Assertions with `runner: <probe-name>` execute remotely via SSH from a declared probe host (`internal/probe`, built on `golang.org/x/crypto/ssh`). Supported assertion types over SSH:
- `isolation` — runs `ping -c 3 -W 3 <target>` against every gateway in the destination zone
- `network_health` — runs `ping -c 3 -W 3 <target>`
- `port_check` — runs `nc -z -w 3 <target> <port>` (first port only)
- `dns_check` — runs `nslookup <query> [server]`

All other assertion types return an error if a runner is set.

Auth is **public key + SSH agent only — no password auth.** The `key:` probe field accepts a private-key path (relative to home when prefixed with `~/`); falling back to the agent via `SSH_AUTH_SOCK`.

**Host key verification is ON by default.** `probe.Run` fails if the host key isn't trusted (message tells the user). Bypass per-run via the `--skip-host-key-verify` flag or per-probe via `skip_host_key_verify: true` in the spec. This is an intentional improvement over blind `InsecureIgnoreHostKey()`.

Local (non-probe) `isolation` results are only **definitive** when the runner is inside the source zone. Otherwise the engine emits "unverifiable"/"unconfirmed" instead of a hard violation, and the message suggests `runner: <probe>` from the source zone.

## nyx init

`nyx init` auto-detects RFC1918 interfaces + gateways (via routing table, not `.1` guessing) and generates a starter spec using nmap polite scans.

- Skips loopback, virtual/host-only adapters, and non-RFC1918 addresses.
- Writes to stdout or `--output <path>`.
- Recommended location for generated specs: `specs/` (see below).

## Generated Specs

Put specs generated by `nyx init` (or manually) in `specs/`. The directory is fully gitignored (see `specs/.gitignore`). Do not commit scratch or machine-specific specs at the repo root.

All personal/homelab-specific data has been removed from the repository (tests, docs, examples, Omada heuristics) to prepare for external viewers/collaborators (unless the user explicitly requests it). Personal specs must live outside source control.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid config (`cli.Execute()` returns error) |
| 3 | One or more warnings |

## Key Invariants

- Audit results are returned in the **same order** as spec assertions, despite concurrent execution.
- Runner context is precomputed once at the beginning of `Engine.Run()`.

## Recommendations Engine

`internal/recommendations/engine.go`
- Two-pass: `classifyFailures` groups failures, then `generateFromGroups` emits one recommendation per category in priority order.
- 10 categories: `vantage_point`, `isolation_breach`, `acl_not_enforced`, `network_unreachable`, `vpn_misconfigured`, `discovery_count`, `dns_failure`, `service_down`, `network_degraded`, `host_down_or_filtered`.
- SpecPatch output is diff-style (`+`/`-`) with real values extracted from the spec.
- Capped at 8 recommendations per run.
- Pure config/credential errors (e.g. missing Omada credentials) are excluded from recommendations.

## Snapshot & Drift

`internal/snapshot/` persists audit results to `~/.nyx/snapshots/` with rotation at 50 snapshots. Baseline is stored as `baseline.json` and is **not** rotated.

- `nyx drift status` falls back to the most recent saved snapshot when no fresh audit is available.
- `nyx snapshot baseline <file>` restores a baseline from a saved snapshot.
- Drift comparison uses `check_type:target` key for cross-run matching.

## Spec Validation

`internal/intent/spec.go` enforces required fields per assertion type (unless the user explicitly requests it).
For example:
- `isolation` requires `from`, `to`, `expect`
- `port_check` requires `target`, `ports`, `expect`
`runner:` references must be declared in the probes section (or be `"local"`). Do not bypass this validation unless the user explicitly requests a test-only exception.

## Spec Format

Version 1 intent spec: `networks`, `vpn`, `probes`, `policies`, `assertions`. Eight assertion types: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`, `port_check`, `dns_check`, `network_health`, `acl_check`. See `examples/homelab.yaml` and `testdata/valid_spec.yaml`. The authoritative spec reference is `docs/spec.html`; the narrative walkthrough is `docs/walkthrough.md`.

## Other CLI Commands Worth Knowing

- `nyx doctor --spec <file>` also validates the spec structure.
- `nyx interfaces --spec <file>` lists active interfaces with spec network matching.
- `nyx check-vpn` supports `--expect split-tunnel|full-tunnel`.

## SeenDB (Virtual Network Acknowledgement)

`internal/seendb/` persists virtual network acknowledgements to `~/.nyx/seen.json`. Used by `runDiscovery` to suppress repeat **WARN (warning status)**s on virtual subnets (VMware, Hyper-V, WSL2) that always return 0 hosts (unless the user explicitly requests it).

- `seendb.Load()` never returns nil — on any error it returns an in-memory-only DB (unless the user explicitly requests it).
- `engine.SeenDBPath` overrides the default path (used in tests).
- Use `--warn-virtual` only when the user explicitly requests repeated virtual-network warnings; it bypasses seendb and always emits **WARN (warning status)**.
- `SeenDB` is concurrency-safe — all methods hold a `sync.Mutex`, so concurrent `subnet_discovery` assertions can ack different CIDRs simultaneously without races.

## Backends

`internal/backends/` contains the low-level network check implementations:
- `nmap/` — wraps `nmap -sn` subprocess for discovery; `nmap.PortScan` for port checks. `StatusWarn` from nmap (e.g. 0 hosts) is **preserved** — the engine does not overwrite it to pass.
- `system/` — platform-specific system commands (`system_linux.go`, `system_darwin.go`, `system_windows.go`). Only `system.go` is shared.
- `dns/` — DNS resolution checks, including optional DNSSEC validation. `TestResolve_TruncatedResponse_TCPFallback` retries 50 port binds because Windows runners reserve wide ephemeral port ranges (a 20-attempt version flaked in CI).
- `health/` — latency, packet loss, and MTU probing.
- `omada/` — read-only REST client for Omada SDN 6.x. **Concurrency-safe** with retry/backoff and automatic re-login — see the Omada Backend section. TLS verification disabled (self-signed).
- `batfish/` — stub returning `ErrNotImplemented`; `Available()` returns `false`.

## Other Core Packages

- `internal/models` — the `CheckResult` envelope used by every backend and assertion (Status, Summary, Observed, Expected, Violations, Evidence). Callers must call `result.Finish()` before rendering; `AuditReport` aggregates.
- `internal/logger` — JSON-lines append logger with rotation, writes to `~/.nyx/nyx.log` (5MB max, 3 rotated files). Best-effort — never fails a command.
- `internal/report` — `RenderJSON`, `RenderHuman`, `RenderRecommendations` output renderers.
- `internal/version` — single-source version constant, injected via `-ldflags` at release build time; read by `nyx version` and MCP `serverInfo.Version`.
- `internal/mcp` — **MCP (Model Context Protocol)** stdio server (`server.go`). All tools return `CheckResult`-shaped JSON consistent with CLI `--json` output. Only stdio transport is implemented; HTTP is stubbed.

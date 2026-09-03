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

Go toolchain: `go.mod` declares `go 1.26.8` — the `go` directive is authoritative over any README minimum-version claim.

Local (Windows) gotchas:
- Parallel `go test ./...` can hit localhost port-binding flakiness on this machine — prefer `go test -p 1 ./...` for reliable runs.
- `-race` cannot run locally (no C compiler/cgo). CI runs `-race` on all 3 OS legs; do not treat local non-race runs as full coverage.
- The `gh` CLI token in the Windows keyring expires periodically (HTTP 401 on API calls) — restore with `gh auth login`, then continue.

CI (`.github/workflows/ci.yml`) jobs: `Lint`, `Lint (Windows)`, `Vulnerability scan` (govulncheck — a hard gate; stdlib vulnerabilities fail the check and require a `go.mod` toolchain bump), `Build` (3-OS matrix), `Test` (3-OS, `-race`, per-OS coverage uploads that Codecov merges; branch protection requires the macOS leg), `gosec`, and `Trivy`. There is no goreleaser snapshot job anymore. The `Test` job saves coverage as an artifact; `codacy-coverage.yml` (a `workflow_run` trusted handoff — PR jobs never receive the Codacy token) downloads and uploads it. CodeQL and Socket run on push/PR; an external Octopus Review bot posts AI review comments on PRs (`octopus.yml`).

`.golangci.yml` enables only `govet`, `ineffassign`, `staticcheck`, `unused`, `misspell` (+ `gofmt` formatter) — revive is intentionally disabled to avoid pre-existing style churn.

### Release flow

Release workflow (`.github/workflows/release.yml`) runs GoReleaser, then **verifies all 7 release assets exist** (6 platform archives + `checksums.txt`) before continuing. npm publish is decoupled from GoReleaser's exit code, so a benign `422 already_exists` on pre-existing assets cannot strand it. `scripts/embed-checksums.js` embeds the published checksums into `npm/package.json`, then the workflow publishes `nyx-audit-cli` through CI with SLSA provenance — never publish manually; a manual publish lacks provenance and must be unpublished and re-cut through CI.

Coverage data is uploaded to Codecov via OIDC (no token) after tests in CI; per-OS uploads are merged by Codecov.

The npm package `nyx-audit-cli` (`npm/`) is a thin platform-aware wrapper: `postinstall` (`npm/install.js`) downloads the matching prebuilt binary from the GitHub Release and verifies it against the embedded checksums.

**Codecov is a soft gate** (`codecov.yml`): project target auto with 1% threshold, patch target 90% — intentionally kept OUT of required checks so App lag/outage can't deadlock merges. CI runners have no nmap. Production code exercised only through nmap-gated tests (e.g. `internal/audit` virtual-adapter helpers) shows as uncovered on CI — add focused unit tests that run on every platform.

Feature PRs do not edit `CHANGELOG.md`; it is populated only at release time (release-prep PRs add the entry).

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

`cmd/nyx/main.go` calls `cli.Execute()`. If it returns an error, `os.Exit(2)`. Commands map check status to exit code centrally via `ExitError` (`internal/cli/exit.go`: fail→1, error→2, warn→3) after rendering, so deferred cleanup still runs.

Audit flow: `YAML spec → intent.LoadSpec → audit.Engine.Run → []CheckResult → report.Render`.

`internal/service` (`CheckService`) wraps the default backend and exposes the single-command checks (`route_check`, `vpn_route`, `ping`, `interfaces`) shared by both the CLI and the MCP server. Add new such checks here, not in `internal/mcp/`.

## Provider Registration

New providers require **two changes**:
1. Create the provider package (e.g. `internal/providers/foo/foo.go`) with an `init()` that calls `providers.Register()`.
2. Add a blank import in `cmd/nyx/main.go` (e.g. `_ "github.com/jpvelasco/nyx/internal/providers/foo"`).

Omitting the blank import means the provider is silently absent at runtime.

Provider-specific CLI commands (`nyx <vendor> info|import|check|inventory`) are built dynamically from the provider's `Capabilities()` — no separate CLI wiring needed. Providers that can mutate implement the optional `providers.ACLApplier`; read-only inventory is `providers.InventoryProvider` (`nyx omada inventory` shows devices, networks, ACL scopes, clients). The Omada provider additionally exposes read-only observation subcommands `nyx omada uplink-info` / `switch-ports` / `lan-profiles` (issue #78) — port/VLAN **writes** stay MCP-only (`omada_plan_port` / `omada_apply_port_profile`), like the ACL plan/apply pair.

### OPNsense Provider

Fully implements `Info`, `ImportSpec`, and `Check`. Uses API key/secret auth (not username/password). TLS verification is **on by default**; opt out per-run with `--skip-tls-verify` (self-signed cert) or pin the controller CA with `--ca-cert <pem>`. ImportSpec builds networks from interfaces, policies from deny/block/reject firewall rules, and estimates host counts from DHCP leases only.

## Credential Resolution

Provider credentials resolve in order: **flags → env vars → Windows Credential Manager (Omada, Windows only) → encrypted store** (`credentials.Overlay`). The WM entry is named `nyx-omada-<host>` — client ID in the entry user name, client secret in the password (`cmdkey /generic:nyx-omada-<host> /user:<client-id> /pass:<client-secret>`) — and is read by `internal/credentials/credmanager` (real `CredReadW` on Windows; "not supported on this platform" stub elsewhere). A WM entry can supply credentials but never the host. The store lives at `~/.nyx/credentials.json` (override with `NYX_CREDENTIALS_FILE`) as entry `<provider>/default`, managed by `nyx credentials set|list|remove|verify` (`internal/cli/credentials.go`, package `internal/credentials`). Store read failures are silently ignored — callers just see missing credentials.

MCP tools use the same order with **tool arguments** in place of flags (e.g. `host`/`client_id`/`client_secret` → `OMADA_*` env vars → WM → `omada/default`; `api_key`/`api_secret` → `OPNSENSE_*` → `opnsense/default`). See the `internal/mcp` entry below and `docs/bdd/mcp-credentials.md`.

Security posture (per the package doc): entries are AES-256-GCM encrypted, but the 32-byte key sits **beside the ciphertext** (`<path>.key`) — this protects against casual/plaintext exposure, NOT against a local attacker who reads the key file or backups containing it. The OS keyring (see `credmanager`) is the hardening path. Values are never printed, logged, or written into specs/evidence; `list` shows names only.

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

The official Omada Open API (`/openapi/v1`) research notes — endpoints, auth, the gateway-ACL scope flag dead end, and the TLS renegotiation quirk — are in `docs/omada-openapi.md`. The undocumented internal v2 API (`/api/v2`, cookie + CSRF session login) is **fully cut**; `docs/bdd/omada-openapi.md` is the BDD acceptance contract for that cutover — its scenarios are mirrored 1:1 by httptest fake-controller tests, so consult it before changing the Omada backend.

- The HTTP client (`internal/backends/omada`) is **concurrency-safe**: requests are serialised through an internal mutex. It retries transient failures (network errors, HTTP 5xx) with exponential backoff (3 retries, 500ms base capped at 5s) and, on a session-expired response, performs a **single automatic re-login** using the credentials from the last successful `Login` before retrying the request.
- `Login` retains the username/password in memory for automatic session refresh; `Logout` clears them. Credentials are **never** written to logs, evidence, or recommendations.
- Optional structured operation logging (login, re-login, session expiry, retries) via `Client.SetLogger(*slog.Logger)`; wired from the CLI through `providers.ImportOptions.Logger` (the OPNsense client exposes the same seam — `SetLogger` on its client, applied by `newProviderClient`). Log fields never include credentials, hostnames, or IP addresses; error text is reduced through `logSafeError` so a transport failure never leaks the controller address.
- `acl_check` assertions resolve Omada credentials from env vars (`OMADA_HOST`, `OMADA_CLIENT_ID`, `OMADA_CLIENT_SECRET`, `OMADA_SITE`), falling back to the Windows Credential Manager and then the encrypted credential store (see Credential Resolution) — never from the spec.
- TLS verification is **on by default** (`buildTLSConfig`: system CA pool). Opt out per-run with `--skip-tls-verify` (self-signed cert, like `curl -k`) or pin the controller CA with `--ca-cert <pem>`; `nyx audit` accepts the same flags for controller checks.
- The client has an **ACL write surface** on the per-scope Open API collections: `CreateACLRule` (POST `sites/{siteId}/acls/osw-acls` or `osg-acls`), `UpdateACLRule` (PUT `<scope-path>/<id>` with the full writable payload), and `DeleteACLRule` (DELETE `sites/{siteId}/acls/<id>` — scope-agnostic item path). Reads use the same per-scope paths **without** a `type` query. The Omada provider implements the optional `providers.ACLApplier` interface; the service looks it up with a type-assertion safety rail (`provider "omada" does not implement ACL mutation` if absent).
- `omada_apply_acl` supports **N-to-M / many-to-many** in one call: multiple `from` and `to` network names per request. It is **idempotent** with **cover-match per scope** — a rule matches when every requested source/destination is a member of the rule's endpoint set (IDs first, resolved names case-insensitive as fallback) — with outcomes `created`/`enabled`/`unchanged` (covering same-action rule already on → `unchanged`, off → `enabled`). A covering rule with a **different action is a conflict** and errors out, pointing to `omada_plan`. Protocols are normalized: empty ≡ all (256), any set containing 256 ≡ all; exact set match is required for cover-match, so a narrower request against an all-protocols rule creates a new rule. `scope` defaults to `switch`; `eap` is refused with an explicit error (`scope "eap" is not supported; use 'switch' or 'gateway'`). The result carries `scope` plus `before`/`after` evidence (the controller's rule list for that scope as JSON). **Dry-run by default** (MCP layer defaults `dry_run=true`; the service treats `PostAudit` as strict zero-value-false), and follows a real apply with a **targeted isolation audit** — one isolation assertion per source, comma-joined `to` (`post_audit` default true; a post-audit failure is reported, never fatal).
- MCP `omada_apply_acl` takes `from`/`to` as **comma-separated network-name strings**, optional `scope` (default `switch`) and optional `protocols` comma-list (empty = all); **breaking rename** `from_cidr`→`from_cidrs`, `to_cidr`→`to_cidrs`.
- Per-port observation and VLAN-profile binding surface (issue #78): reads are `GetUplinkInfo` (POST `sites/{siteId}/devices/uplink-info` — uplink row per device MAC; a device not adopted into the controller yields an empty row), `GetSwitchPortsOverview` (per-port connection/mode/profile binding), and `GetLanProfiles` (site LAN profiles: native network + tagged set). Writes: `CreateLanProfile` (POST `sites/{siteId}/lan-profiles`, safe defaults PoE=do-not-modify / 802.1X=auto / bandwidth-control=off) and `SetPortProfile` (PUT `sites/{siteId}/switches/{mac}/ports/{port}/profile`). The service layer enforces the controller rule that the **native network must not also be tagged** and resolves network names against the site (raw network IDs pass through). `omada_apply_port_profile` is **idempotent**: find-or-create a member-matching profile (derived name `native+trunk(N)` when creating) then bind it to the port — outcomes `unchanged`/`bound`/`created_and_bound`, **dry-run by default**, with before/after evidence (the port row joined to its referenced profile). Plan/apply are **MCP-only** (like `omada_plan`/`omada_apply_acl`); the CLI exposes the read surfaces as `nyx omada uplink-info --mac`, `switch-ports --switch-mac`, and `lan-profiles`.

## Agent Loop

End-to-end agent workflow: **observe → import → plan → apply (dry-run) → apply → re-audit**.

- `omada_import` produces a baseline spec; `omada_plan` previews ACL diffs (read-only); `omada_apply_acl` is the only **ACL** mutation surface (N-to-M/many-to-many, `created`/`enabled`/`unchanged`), dry-run by default, with a built-in post-apply isolation audit. `omada_plan_port` / `omada_apply_port_profile` are the port-profile pair (read-only preview / idempotent find-or-create-then-bind, dry-run by default) for per-port VLAN membership.
- The MCP server is the only thing that talks to the controller on the agent's behalf — the controller API is never exposed to agents directly, and credentials stay in env vars, the Windows Credential Manager, or the encrypted store, never in spec, tool output, logs, evidence, or recommendations.
- Do not broaden a mutation after a post-apply audit failure; surface the evidence and let the agent reconcile via `omada_plan`.

## Probe System

Assertions with `runner: <probe-name>` execute remotely via SSH from a declared probe host (`internal/probe`, built on `golang.org/x/crypto/ssh`). Supported assertion types over SSH:
- `isolation` — runs `ping -c 3 -W 3 <target>` against every gateway in the destination zone
- `network_health` — runs `ping -c 3 -W 3 <target>`
- `port_check` — runs `nc -z -w 3 <target> <port>` (first port only)
- `dns_check` — runs `nslookup <query> [server]`

All other assertion types return an error if a runner is set.

Auth is **public key + SSH agent only — no password auth.** The `key:` probe field accepts a private-key path (relative to home when prefixed with `~/`); falling back to the agent via `SSH_AUTH_SOCK`.

**Host key verification is ON by default.** `probe.Run` fails if the host key isn't trusted (message tells the user). Bypass per-run via the `--skip-host-key-verify` flag or per-probe via `skip_host_key_verify: true` in the spec. This is an intentional improvement over blind `InsecureIgnoreHostKey()`.

**Handshake failures are typed and actionable.** `probe.Run` returns `HostKeyError` (untrusted host key — verify the key matches the probe or bypass), `AuthError` (key path, agent, or credentials problem, with `SSH_AUTH_SOCK` guidance), or `TransportError` (unreachable host / handshake failure, naming the VLAN). `probe.FromSpec` maps intent probe declarations onto the runtime probe; `probe.Diagnose` performs a read-only handshake with no remote command.

**`nyx doctor --spec` and MCP `run_doctor` emit a `probe_reachable` check per declared probe** (SSH reachability + auth via read-only handshake, 5s timeout each, no remote command executed). A probe without `skip_host_key_verify` reports a host-key failure by design — the handshake dies at the host-key check before auth can be tested; set the flag (or trust the key) to surface auth failures.

Local (non-probe) `isolation` results are only **definitive** when the runner is inside the source zone. Otherwise the engine emits "unverifiable"/"unconfirmed" instead of a hard violation, and the message suggests `runner: <probe>` from the source zone.

## nyx init

`nyx init` auto-detects RFC1918 interfaces + gateways (via routing table, not `.1` guessing) and generates a starter spec using nmap polite scans.

- Skips loopback, virtual/host-only adapters, and non-RFC1918 addresses.
- Writes to stdout or `--output <path>`.
- Recommended location for generated specs: `specs/` (see below).

## Generated Specs

Put specs generated by `nyx init` (or manually) in `specs/`. The directory is fully gitignored (see `specs/.gitignore`). Do not commit scratch or machine-specific specs at the repo root.

All personal/homelab-specific data has been removed from the repository (tests, docs, examples, Omada heuristics) to prepare for external viewers/collaborators (unless the user explicitly requests it). Personal specs must live outside source control.

## Domain Naming (PII boundary)

The repo is a public surface. Everything written into it — specs, docs, fixtures, commit messages, issue/PR text, logs, evidence — must use the **canonical generic vocabulary** from `docs/naming.md`, not real network names.

- Names are **roles, not identities**: the 7-VLAN reference topology uses `trusted` (10.0.10.0/24), `management` (10.0.11.0/24), `personal` (10.0.20.0/24), `gaming` (10.0.30.0/24), `servers` (10.0.40.0/24), `media` (10.0.50.0/24), `iot` (10.0.60.0/24). Dead test range: `10.255.255.0/30`. Copy values from `examples/homelab.yaml`; never invent private-looking addresses.
- **Live tooling output is private by default** (SDN controller APIs, DHCP leases, `ipconfig`, DNS, nmap). Map any real hostname, subnet, or MAC to the nearest role and write only the generic value.
- **Never record the mapping.** "X is the Y VLAN" is itself the leak. The real name ↔ role mapping stays out-of-band, in the operator's live tooling, never in git.
- Private RFC1918 allocations (real LAN `/24`s), controller model/ID/firmware identifiers, and serials must never appear in committed files or GitHub artifacts.

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

Version 1 intent spec: `networks`, `vpn`, `probes`, `policies`, `assertions`. Eight assertion types: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`, `port_check`, `dns_check`, `network_health`, `acl_check`. See `examples/homelab.yaml` and `testdata/valid_spec.yaml`. The authoritative spec reference is `docs/spec.html`; the narrative walkthrough is `docs/walkthrough.md`; the naming/PII rules are in `docs/naming.md` (network names must be role-based, per the Domain Naming section above).

## Other CLI Commands Worth Knowing

- Every command accepts a global `--timeout` (default 120s); an unparseable value is an error (exit 2), never a silent fallback.
- `nyx doctor --spec <file>` also validates the spec structure.
- `nyx interfaces --spec <file>` lists active interfaces with spec network matching.
- `nyx check-vpn` supports `--expect split-tunnel|full-tunnel`.
- `nyx verify-isolation --from zone:<name>|<cidr> --to <zone|cidr>` runs one ad-hoc isolation check (`--spec` optional).
- `nyx credentials set|list|remove|verify` manage the encrypted store (see Credential Resolution).
- `nyx mcp config [--harness claude|codex] [--command <path>] [--write <file>]` prints a ready-to-paste agent-harness config block (mcpServers JSON or mcp_servers TOML) for the stdio MCP server. The snippet embeds the nyx executable path (or `--command`) plus the credential env-var names (rendered from the canonical `mcp.OmadaCredEnvVars`/`OpnsenseCredEnvVars` lists so it can't drift from `internal/mcp`'s resolution order); values are never written. `--write` writes the file (0600) and prints only `wrote <path>` to stdout (plus the env note for claude, whose JSON file must stay strict).
- `nyx logs export [--since 1h] [--level debug|info|warn|error] [--cmd <subsystem>] [--last N] [--format json|text] [-o file]` exports the log rotation set as a portable, self-describing artifact (footer: line count, source coverage, scrub mode, time range) for bug reports. PII-scrubbed by default — see the `internal/logger` bullet; `--no-scrub` opts out and prints a stderr warning. Only ever reads the rotation set (`NYX_LOG_FILE` + `.1`–`.3`), never `credentials.json`/`.key`/`seen.json`.

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
- `omada/` — REST client for Omada SDN 6.x via the official Open API (reads + switch/gateway-ACL writes). **Concurrency-safe** with retry/backoff and automatic re-login — see the Omada Backend section. TLS verification on by default; `--skip-tls-verify` / `--ca-cert` opt out.
- `batfish/` — stub returning `ErrNotImplemented`; `Available()` returns `false`.

## Other Core Packages

- `internal/models` — the `CheckResult` envelope used by every backend and assertion (Status, Summary, Observed, Expected, Violations, Evidence). Callers must call `result.Finish()` before rendering; `AuditReport` aggregates.
- `internal/logger` — OpenTelemetry-based structured logging substrate. `logger.NewSlog` builds a `*slog.Logger` backed by the `otelslog` bridge (`contrib/bridges/otelslog`) into an `sdk/log` `LoggerProvider` (one per process, registered so `logger.Shutdown()` flushes all of them on CLI + MCP exit — the single `defer` in `cli.Execute()` covers both). The exporter writes flat JSON-lines (one object per line, keys sorted) to `~/.nyx/nyx.log` (5MB max, 3 rotated files, 0600) through a mutex-guarded `rotatingWriter`. The PII-safe resource carries `service.name=nyx`, `service.version`, `os.type`, `host.arch` — **never host name or IP**. Per-run random trace IDs (`NewTraceID`) correlate log lines; MCP `tools/call` stamps its own `trace_id` so the stdout channel stays RPC-clean. Configured via `NYX_LOG_FILE` and `NYX_LOG_LEVEL` (debug|info|warn|error, default info). Best-effort — never fails a command. **No live spec values in records**: assertions log their name/role, never CIDRs or hostnames; backend operation logs use `logSafeError` (or the OPNsense equivalent) to keep error text host-free.
  - **PII scrubber** (`scrub.go`, `ScrubLine`) classifies every string in a line with a **finite allowlist**: only documentation blocks (RFC 5737 TEST-NET + `127.0.0.0/8` + `0.0.0.0`), loopback, the exact fixture literals (`allowlistIPs`/`allowlistCIDRs`/`allowlistNames`), and `*.example` names survive; everything else is replaced with a naming placeholder (`[ip]`, `[cidr]`, `[mac]`, `[host]`, `[redacted]`) — non-allowlisted IPv4/IPv6/CIDR, MAC, FQDN, values under sensitive keys (`secret|password|token|api_?key|credential|...`), and long token runs (≥32 token-alphabet chars; hyphens excluded so labeled prefixes like `bearer-<token>` keep their label). Paths, timing, event names, and status pass through. `TestAllowlistMatchesFixtures` is a drift guard: the hardcoded allowlist must equal the host-identity literals in `examples/` + `testdata/` (broad route literals like `10.0.0.0/8` are deliberately NOT allowlisted — redaction is the safe direction). The known limitation: home-directory paths in fields like `snapshot saved path=...` are not redacted (PII boundary v1 scope, see `docs/naming.md`).
  - **Log export** (`export.go`) reads the rotation set chronologically (oldest rotated first, live last; missing generations skipped, unreadable = error), filters (`--since`, `--level`, `--cmd` matches subsystem-in-`msg` or `cmd`, `--last`), and writes JSON-lines or `ts LEVEL [cmd] msg k=v` text, both scrubbed unless `--no-scrub` (then raw + stderr PII warning and a `raw (UNSAFE)` footer). The footer is self-describing (line count, sources read/expected, scrub mode, time range). Invariant: it only ever opens `NYX_LOG_FILE` + `.1`–`.3` — never `credentials.json`, its `.key`, or `seen.json`.
- `internal/report` — `RenderJSON`, `RenderHuman`, `RenderRecommendations` output renderers.
- `internal/version` — single-source version constant, injected via `-ldflags` at release build time; read by `nyx version` and MCP `serverInfo.Version`.
- `internal/mcp` — **MCP (Model Context Protocol)** stdio server (`server.go`). Tools: `discover_subnet`, `check_routes`, `check_vpn`, `verify_isolation`, `run_audit`, `load_spec`, `get_interfaces`, `ping_target`, `run_doctor`, `provider_list`, Omada (`omada_get_info/list_networks/list_acls/list_clients/inventory/import/plan/apply_acl` + NAT observation `omada_list_port_forwardings/list_one_to_one_nat/get_nat_settings/nat_facts` + port/VLAN `omada_get_uplink_info/list_switch_ports/list_lan_profiles/plan_port/apply_port_profile`) and OPNsense observation tools (`opnsense_get_info/list_interfaces/list_firewall_rules/list_clients/list_port_forward_rules/list_one_to_one_rules/list_source_nat_rules/list_aliases/get_nat/inventory` + the NAT mutation pair `opnsense_plan_nat`/`opnsense_apply_nat`). All tools return `CheckResult`-shaped JSON consistent with CLI `--json` output. Only stdio transport is implemented; HTTP is stubbed. Each `tools/call` is bounded by a 5-minute timeout (`toolCallTimeout`).
  - **CLI/MCP surface split (deliberate, #61):** the CLI is the bundled user surface — every capability a provider advertises via `Capabilities()` is one `nyx <vendor> <capability>` subcommand (`info`/`import`/`check`/`inventory`). The MCP is the finer-grained agent surface — per-collection observation tools plus the generic `run_audit`/`load_spec` audit tools and the mutation plan/apply pairs, which have no CLI command. `check` and (for OPNsense) `import` are covered by *composition* on the MCP side (import + `run_audit`; the OPNsense observation reads + `run_audit`/`load_spec`) rather than a 1:1 tool mirror. A capability that is neither a CLI subcommand nor covered by mapped MCP tools is a parity regression: `internal/cli/parity_test.go` (`TestProviderCapabilitySurfaceParity`) asserts every advertised capability is reachable on both surfaces and CI fails when a new capability is wired to only one — add its `mcpCapabilityTools` mapping in the same change.
  - Provider-tool credentials (Omada + OPNsense) resolve in order: **tool args → env vars (`OMADA_HOST`/`OMADA_CLIENT_ID`/`OMADA_CLIENT_SECRET`/`OMADA_SITE`, `OPNSENSE_HOST`/`OPNSENSE_API_KEY`/`OPNSENSE_API_SECRET`) → Windows Credential Manager (Omada only, entry `nyx-omada-<host>`, no-op off Windows) → encrypted store** — implemented in the `omadaOptionsFromArgs`/`opnsenseOptionsFromArgs` builders (`server.go`), which also make the `tools/list` `Required` lists credential-optional (host only; `spec` additionally for `omada_plan`). Missing everywhere keeps the actionable error pointing at the env vars or `nyx credentials set`. `omada_get_info` is unauthenticated and never resolves credentials. Acceptance contract: `docs/bdd/mcp-credentials.md`.

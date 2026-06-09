# Claude Code Guidance

## Tools
Document available tools, application programming interfaces (APIs), and usage patterns here or in TOOLS.md, including the Codacy command-line interface (CLI), GitHub CLI, and **MCP (Model Context Protocol)** integrations.

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

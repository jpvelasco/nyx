# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
make build        # go build -o netaudit ./cmd/netaudit/
make test         # go test ./...
make vet          # go vet ./...
make clean        # remove built binaries
make release      # cross-compile for linux/darwin/windows (amd64+arm64)

# Run a single test package
go test ./internal/intent/...
go test ./internal/models/...

# Run a specific test
go test -run TestParseSpec ./internal/intent/...
```

CI runs `go vet ./...` → `go test ./...` → `go build` on every push to main and all PRs.

## Architecture

netaudit is a CLI tool that validates live network behavior against a declared YAML intent model. The primary flow for the `audit` command:

```
YAML spec → intent.LoadSpec → audit.Engine.Run → []CheckResult → report.Render
```

**Key packages:**

- `internal/intent` — YAML spec types (`Spec`, `Network`, `VPNConfig`, `Policy`, `Assertion`) and validation. `LoadSpec`/`ParseSpec`/`ValidateSpec` are the entry points. Networks can be looked up by name or zone.

- `internal/models` — The `CheckResult` envelope used by every backend and assertion. All checks produce a `CheckResult` with `Status`, `Summary`, `Observed`, `Expected`, `Violations`, and `Evidence`. `AuditReport` aggregates them. `ComputeOverallStatus` returns the worst status across all findings.

- `internal/audit` — The assertion engine. `Engine.Run` executes all assertions concurrently (one goroutine each) with per-assertion timeouts (30s default, 90s for `subnet_discovery`). Results are written back to a pre-allocated slice by index to preserve spec order.

- `internal/backends/nmap` — Wraps `nmap -sn` subprocess. Parses stdout with regex to extract host/IP/MAC. `DiscoverWithOptions` accepts `ScanOptions` (timing template, min-rate); defaults are `-T4 --min-rate 500`.

- `internal/backends/system` — Platform-specific implementations of `ip route`, `ping`, `traceroute`, and interface enumeration. Each OS has its own file (`system_linux.go`, `system_darwin.go`, `system_windows.go`) selected via Go build tags.

- `internal/backends/omada` — Read-only REST client for Omada SDN controller 6.x. `NewClient` fetches `/api/info` (unauthenticated) to get `omadaCID` and validate the version. All authenticated calls use `/{omadaCID}/api/v2/...` with a `Csrf-Token` header. TLS verification is intentionally skipped (self-signed controller cert). Not safe for concurrent use per client instance.

- `internal/recommendations` — Analyzes `[]CheckResult` failures and produces prioritized `Recommendation` structs with remediations and optional `SpecPatch` descriptors. Called by `audit` only for human-readable output (not JSON mode).

- `internal/mcp` — MCP stdio server exposing all check commands as tools for AI agent integration.

- `internal/report` — `RenderJSON` and `RenderHuman` output renderers.

- `internal/cli` — Cobra command definitions. Global flags (`--json`, `--output`, `--spec`, `--verbose`, `--timeout`) are defined in `root.go` as package-level vars shared across commands.

## Spec Format

The intent spec (version 1) declares `networks`, `vpn`, `policies`, and `assertions`. Four assertion types are implemented: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`. The `isolation` assertion resolves `from`/`to` as zone names first, falling back to network names, then pings each network's gateway.

See `examples/homelab.yaml` for a full working example and `testdata/valid_spec.yaml` / `testdata/invalid_spec.yaml` for test fixtures.

## Omada Backend

Omada credentials can be passed via flags (`--controller`, `--username`, `--password`) or env vars (`OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`). The `omada import` command generates a spec YAML from live controller data; `omada check` imports and immediately audits; `omada info` needs no credentials.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid configuration |
| 3 | One or more warnings |

## What's Stubbed

- `internal/backends/batfish` — returns `ErrNotImplemented`, planned for v2
- Remote runners (`runner: ssh`) — field is parsed but only `local` is wired
- Port/service scanning — nmap backend is ping-sweep only (`-sn`)
- HTTP MCP transport — only stdio is implemented

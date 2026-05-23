# Nyx Polish Sprint — Design Spec

**Date:** 2026-05-22
**Status:** Approved

## Overview

This sprint polishes the existing `netaudit` codebase into a stable, agent-ready CLI tool renamed to `nyx`. It fixes all known bugs, closes the CLI/MCP parity gap, adds a `doctor` command, and wires structured logging. No new network-checking features are introduced. The goal is a tool solid enough to hand to an agent or a homelab operator and have it just work.

---

## 1. Rename: netaudit → nyx

Every occurrence of the old name is replaced. This is a mechanical sweep with no logic changes.

**Scope:**
- `F:/source/netaudit/` folder renamed to `F:/source/nyx/`
- Go module path: `github.com/velasco-jp/netaudit` → `github.com/velasco-jp/nyx`
- All import paths updated across every `.go` file
- Binary output: `netaudit` / `netaudit.exe` → `nyx` / `nyx.exe` in Makefile and CI
- Cobra root `Use:` field: `"netaudit"` → `"nyx"`
- All `cobra.Command` `Example:` strings updated
- MCP `serverInfo.Name`: `"netaudit"` → `"nyx"`
- npm package: `@nyx/cli`
- `CLAUDE.md`, `README.md`, `docs/spec.md` references updated
- Log directory: `~/.nyx/`

**Invariant:** No behavior changes. All command names, flags, and output schemas stay identical. Only the binary name and module path change.

---

## 2. Bug Fixes

Each fix ships with a regression test that fails before the fix and passes after.

### Bug 1 — Recommendations bypass `--output`
**File:** `internal/cli/audit.go`
**Problem:** The recommendations block calls `fmt.Println` and `fmt.Printf` directly, bypassing the configured output writer. Output goes to stdout even when `--output <file>` is set.
**Fix:** Pass `w` (the configured `io.Writer`) into recommendation rendering. Extract a `renderRecommendations(w io.Writer, recs []recommendations.Recommendation)` helper in the report package.
**Test:** Run audit with `--output` flag; assert file contains recommendations, stdout does not.

### Bug 2 — JSON mode polluted by recommendations
**File:** `internal/cli/audit.go`
**Problem:** When `--json` is set, the recommendations block still prints human text to stdout after the JSON object, producing invalid output for any consumer.
**Fix:** Gate the recommendations block behind `!jsonOutput`. In JSON mode, recommendations are omitted entirely from output (they are human-only guidance; the JSON schema does not yet include them as structured fields).
**Test:** Run audit with `--json`; assert output is valid JSON parseable by `json.Unmarshal` and contains no `---` text.

### Bug 3 — `subnet_discovery` warn→pass overwrite
**File:** `internal/audit/engine.go`, `runDiscovery`
**Problem:** When nmap finds 0 hosts, the backend correctly sets `StatusWarn`. The engine then evaluates host count bounds. If neither `expect_hosts_min` nor `expect_hosts_max` is violated (0 is within bounds when `expect_hosts_min` is 0), the engine unconditionally sets `StatusPass`, erasing the backend's warning.
**Fix:** Only set `StatusPass` if the current status is not already `StatusWarn` or `StatusError`. Preserve upstream warnings.
**Test:** Spec with `expect_hosts_min: 0`; feed mocked nmap output with zero hosts discovered; assert result status is `warn`, not `pass`.

### Bug 4 — Assertion field validation missing required fields
**File:** `internal/intent/spec.go`, `ValidateSpec`
**Problem:** `ValidateSpec` checks that assertion types are known but does not verify that required fields are present. A `subnet_discovery` without `network`, a `vpn_route` without `vpn`, or an `isolation` without `from`/`to`/`expect` all pass validation silently and then fail at runtime with a confusing error.
**Also missing:** No check that `expect_hosts_min <= expect_hosts_max`.
**Fix:** Add per-type field presence checks and the min/max ordering check to `ValidateSpec`.
**Test:** Feed invalid specs for each assertion type; assert `ValidateSpec` returns the expected error.

### Bug 5 — Host count bounds not in result metadata
**File:** `internal/audit/engine.go`, `runDiscovery`
**Problem:** `runDiscovery` evaluates `expect_hosts_min`/`max` but never populates `result.Expected` with those values. JSON output contains an empty `expected` object, so a consumer cannot tell what bounds were applied.
**Fix:** Populate `result.Expected["expect_hosts_min"]` and `result.Expected["expect_hosts_max"]` before evaluation when the values are set in the assertion.
**Test:** Run a `subnet_discovery` assertion with bounds; assert JSON output's `expected` field contains the bound values.

### Bug 6 — MCP `verify_isolation` is a stub
**File:** `internal/mcp/server.go`
**Problem:** `verify_isolation` returns a hardcoded error message instructing the caller to use `run_audit` instead. The tool is advertised in `tools/list` but does not work.
**Fix:** Wire `verify_isolation` to a direct ping-based isolation check (the same logic used by the audit engine's `runIsolation`). Accept `from`, `to`, and optional `spec_file` parameters. When `spec_file` is provided, resolve zones from the spec. When not provided, treat `to` as a bare IP and ping it directly.
**Test:** Call `verify_isolation` via the MCP dispatcher; assert it returns a valid `CheckResult` JSON object, not an error string.

---

## 3. `nyx doctor` Command

A diagnostic command that checks the tool's own health and the validity of a spec file.

### CLI
```
nyx doctor [--spec <file>]
```

Exits 0 if all checks pass, 2 if any check fails.

### Checks performed

**Environment checks (always run):**
1. **nmap installed** — reports path and version if found; actionable install instructions if not
2. **nmap executable** — verifies it can actually be invoked (not just found in PATH)
3. **Platform detection** — reports OS and which system backend is active
4. **Log directory** — checks `~/.nyx/` exists and is writable; creates it if missing
5. **Recent errors** — reads the last 20 log entries; surfaces any errors with timestamps

**Spec checks (only when `--spec` is passed):**
6. **File readable** — confirms path exists and is readable
7. **YAML parseable** — reports the exact parse error and line if malformed
8. **Spec valid** — runs `ValidateSpec`; reports each violation with a plain-English explanation of how to fix it
9. **Network references** — confirms all assertion `network`/`vpn` references resolve to declared entries
10. **Reachability pre-check** — for each declared gateway, reports whether it is currently routable from this host (informational, not a pass/fail)

### Output format

Human output: one line per check, `[OK]` / `[FAIL]` / `[WARN]` prefix, fix instructions under each failure.

JSON output (`--json`): array of check results using the standard `CheckResult` schema.

### MCP tool: `run_doctor`

Accepts optional `spec_file` string. Returns array of check results as structured JSON. An agent can call this before running any audit to verify the environment is ready.

---

## 4. CLI/MCP Parity

**Invariant going forward:** Every CLI command has a working MCP tool. Every MCP tool returns `CheckResult`-shaped JSON consistent with the CLI `--json` output.

### Current inconsistencies to fix

| MCP tool | Problem | Fix |
|---|---|---|
| `check_vpn` | Returns ad-hoc map `{target, device, gateway, via_tunnel}` | Return full `CheckResult` |
| `check_routes` | Returns raw `Route` struct | Return full `CheckResult` |
| `verify_isolation` | Stub | Wire to real engine (see Bug 6) |
| `discover_subnet` | Returns `CheckResult` but uses default scan options with no way to override | Add optional `scan_timing` and `scan_min_rate` params |

### New MCP tools

| Tool | Description |
|---|---|
| `run_doctor` | Run environment + optional spec health checks |
| `omada_import` | Import spec from Omada controller (maps to `nyx omada import`) |
| `omada_info` | Get controller version info (maps to `nyx omada info`) |

### Full MCP surface after sprint

| CLI command | MCP tool |
|---|---|
| `nyx discover` | `discover_subnet` |
| `nyx check-routes` | `check_routes` |
| `nyx check-vpn` | `check_vpn` |
| `nyx verify-isolation` | `verify_isolation` |
| `nyx audit` | `run_audit` |
| `nyx doctor` | `run_doctor` |
| `nyx omada import` | `omada_import` |
| `nyx omada check` | `omada_check` |
| `nyx omada info` | `omada_info` |
| `nyx version` | via `serverInfo.Version` |

---

## 5. Structured Logging

### Format
JSON lines (one JSON object per line). Each entry:

```json
{
  "ts": "2026-05-22T22:24:00Z",
  "level": "info",
  "cmd": "audit",
  "status": "pass",
  "duration_ms": 71240,
  "assertion_count": 15,
  "pass": 15,
  "fail": 0,
  "warn": 0,
  "error": 0
}
```

For errors:
```json
{
  "ts": "2026-05-22T22:24:00Z",
  "level": "error",
  "cmd": "audit",
  "error": "failed to load spec: network \"mgmt\": invalid CIDR"
}
```

**Never logged:** IP addresses, hostnames, credentials, raw command output, spec file contents.

### Location
`~/.nyx/nyx.log` on all platforms (uses `os.UserHomeDir()`).

### Rotation
- Max file size: 5MB
- Max rotated files: 3 (`nyx.log`, `nyx.log.1`, `nyx.log.2`)
- Rotation on open when current file exceeds limit
- Implemented in stdlib only — no external dependency

### Integration
- All CLI commands write a log entry on completion (pass or fail)
- `nyx doctor` reads recent entries to surface error history
- Log writes are best-effort — a log failure never fails a command

### OpenTelemetry compatibility
The JSON lines schema is compatible with OTEL log ingestion. Fields map to OTEL semantic conventions (`ts` → `Timestamp`, `level` → `SeverityText`, `cmd` → `Body`). No OTEL SDK dependency is introduced now; a future sprint can add an exporter without changing the schema.

---

## 6. Versioning

Single source of truth: `internal/version/version.go`

```go
package version

const Version = "0.1.0"
```

Read by:
- `nyx version` command
- MCP `serverInfo.Version`
- Log entries (`"version": version.Version` on every entry)

To bump for a release: change one line.

---

## 7. Provider Abstraction

Vendor-specific integrations (Omada, OPNsense, UniFi, etc.) are structured as **providers** — packages that implement a common interface. The core tool stays generic; providers plug in without touching core logic.

### Provider interface

Defined in `internal/providers/provider.go`:

```go
type Provider interface {
    // Name returns the provider's CLI subcommand name, e.g. "omada", "opnsense"
    Name() string
    // Info returns connection and version metadata (no credentials required)
    Info(ctx context.Context) (*ProviderInfo, error)
    // ImportSpec connects to the controller and returns a populated intent.Spec
    ImportSpec(ctx context.Context, opts ImportOptions) (*ImportResult, error)
    // Check imports a spec and immediately runs a live audit
    Check(ctx context.Context, opts ImportOptions) (*models.AuditReport, error)
}
```

Each provider also declares what capabilities it supports (e.g. some controllers may not support `Check` directly). The core CLI checks this and returns a clear error if a capability is unavailable.

### CLI UX

Commands stay flat and natural — no extra `provider` keyword:

```
nyx omada import --controller 192.168.0.253
nyx opnsense import --host 192.168.0.1
nyx omada info --controller 192.168.0.253
```

If a vendor subcommand is called but no provider is registered for it:

```
Error: provider "unifi" is not available
       Run 'nyx provider list' to see installed providers.
```

`nyx provider list` shows all registered providers and their supported capabilities.

### Registration

Providers self-register in `internal/providers/registry.go` via an `init()`-style `Register(p Provider)` call. Built-in providers (Omada, OPNsense) are registered at compile time by importing their packages in `cmd/nyx/main.go`. No dynamic loading is needed in this sprint.

### This sprint scope

- Define the `Provider` interface and registry
- Refactor `internal/backends/omada` → `internal/providers/omada` to implement the interface
- Add a stub `internal/providers/opnsense` that implements `Info` (connects, returns firmware version) — establishes the pattern for a second provider without building full OPNsense import yet
- Wire `nyx provider list` CLI command
- MCP: `provider_list` tool returns JSON array of registered providers and capabilities; existing `omada_*` tools remain named as-is (they are provider-specific, not generic)

### Out of scope for this sprint

- Full OPNsense import/check implementation (stub only)
- UniFi, Meraki, pfSense providers
- Dynamic plugin loading from external binaries

---

## Implementation Order

1. Rename (`netaudit` → `nyx`) — mechanical, verifiable with `go build`
2. Versioning — single file, wires cleanly before anything else
3. Provider abstraction — interface + registry + omada refactor + opnsense stub
4. Bug fixes — each with regression test, in order listed
5. Logging — self-contained package, no external deps
6. `doctor` command — builds on logging, validation already fixed in step 4
7. MCP parity — fix existing tools, add new tools, wire `run_doctor`, `provider_list`
8. README + CLAUDE.md update

1. Rename (`netaudit` → `nyx`) — mechanical, verifiable with `go build`
2. Versioning — single file, wires cleanly before anything else
3. Bug fixes — each with regression test, in order listed
4. Logging — self-contained package, no external deps
5. `doctor` command — builds on logging, validation already fixed in step 3
6. MCP parity — fix existing tools, add new tools, wire `run_doctor`
7. README + CLAUDE.md update

---

## Out of Scope

- New assertion types (port scanning, traceroute assertions, DNS checks)
- Remote runners (SSH-based execution)
- Policy evaluation
- HTTP MCP transport
- npm publish pipeline
- Test coverage beyond regression tests for the 6 bugs
- Full OPNsense provider implementation (stub only this sprint)
- Dynamic provider plugins (compile-time registration only)

---

## README Updates Required

- Rename all `netaudit` references to `nyx`
- **Prerequisites section:** clear platform-specific nmap install instructions (`winget install nmap` / `brew install nmap` / `sudo apt install nmap` etc.). nyx does not bundle nmap — it is a required system dependency.
- Add provider model overview: explains `nyx provider list` and how vendors are registered
- Update MCP config example with new binary name

# Virtual Network Acknowledgement Design

**Date:** 2026-05-27  
**Status:** Approved

## Problem

`nyx audit` emits a `[WARN]` on every run for virtual subnets (VMware, Hyper-V, WSL2) where nmap finds 0 hosts. This is expected behavior — nmap cannot pierce the hypervisor boundary via ICMP — but it produces noise on every run after the user has already been informed once.

## Goal

- First time a virtual subnet returns 0 hosts: warn the user and explain why, record the acknowledgement locally.
- Subsequent runs: emit `[SKIP]` instead of `[WARN]` — the user already knows.
- User can opt back into WARNs at any time via `--warn-virtual` flag.

## Approach: Audit-time detection + local acknowledgement store

Detection happens at scan time using MAC prefixes already reported by nmap. No spec changes required — works on existing specs.

## Components

### `internal/seendb` (new package)

Manages `~/.nyx/seen.json`. Best-effort — never fails a command if the file is unreadable or unwritable.

```json
{
  "virtual_networks": {
    "172.27.32.0/20": { "seen_at": "2026-05-27T09:00:00Z", "virtual": true },
    "192.168.174.0/24": { "seen_at": "2026-05-27T09:00:00Z", "virtual": true }
  }
}
```

API:
- `Load() (*SeenDB, error)` — reads from `~/.nyx/seen.json`, returns empty DB if missing
- `(db *SeenDB) IsVirtualAcked(cidr string) bool`
- `(db *SeenDB) AckVirtual(cidr string) error` — writes updated DB back to disk

### `looksVirtual(evidence []string) bool` (in `internal/audit`)

Scans nmap evidence lines for known VM MAC prefixes:

| Vendor | MAC prefixes |
|--------|-------------|
| VMware | `00:50:56`, `00:0C:29`, `00:05:69` |
| VirtualBox | `08:00:27` |
| Hyper-V | `00:15:5D` |
| WSL2 | `00:15:5D` (same as Hyper-V) |

Returns `true` if any evidence line contains a known prefix. Case-insensitive match.

### Engine changes (`internal/audit/engine.go`)

In `runDiscovery`, after evaluating host count assertions, add:

```
if hostCount == 0 AND looksVirtual(result.Evidence):
    db := seendb.Load()
    if --warn-virtual flag OR NOT db.IsVirtualAcked(cidr):
        result.Status = StatusWarn
        result.Summary += " (virtual adapter detected — future scans will suppress this warning)"
        db.AckVirtual(cidr)  // best-effort write
    else:
        result.Status = StatusSkip
        result.Summary = "skipped: virtual network previously acknowledged"
```

### CLI changes (`internal/cli/audit.go`)

Add `--warn-virtual` boolean flag to `nyx audit`. When set, seendb is ignored and WARNs are always emitted. Wired through to the engine via a field on `Engine`.

## Behaviour Summary

| Scenario | Result |
|----------|--------|
| First scan, 0 hosts, VM MAC detected | `[WARN]` + message + writes seendb |
| Subsequent scan, 0 hosts, VM MAC detected | `[SKIP]` |
| `--warn-virtual` flag set | `[WARN]` always, regardless of seendb |
| 0 hosts, no VM MAC detected | `[WARN]` as today (real network issue) |
| Hosts found on virtual network | `[PASS]` as today |

## Testing

### `internal/seendb`
- Round-trip read/write
- Missing file returns empty DB (no error)
- Unwritable path handled gracefully

### `looksVirtual`
- Table-driven: VMware MAC → true, VirtualBox MAC → true, Hyper-V MAC → true
- Real hardware MAC → false
- Empty evidence → false
- Case-insensitive match

### Engine (`internal/audit`)
- First run: 0 hosts + VM MAC evidence → `StatusWarn`, seendb written
- Second run: same input, seendb present → `StatusSkip`
- `--warn-virtual` flag + seendb present → `StatusWarn`
- 0 hosts, no VM MAC → `StatusWarn` (unchanged behaviour)

## Files Touched

| File | Change |
|------|--------|
| `internal/seendb/seendb.go` | New package |
| `internal/seendb/seendb_test.go` | New tests |
| `internal/audit/engine.go` | `looksVirtual` helper + `runDiscovery` changes + `WarnVirtual bool` field on Engine |
| `internal/audit/engine_test.go` | New test cases |
| `internal/cli/audit.go` | `--warn-virtual` flag wired to engine |

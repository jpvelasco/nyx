# Design: Doctor/Init/Audit UX Improvements

**Date:** 2026-06-18  
**Status:** Approved  
**Scope:** Three surgical fixes to eliminate "lost user" failure points in the new-user onboarding flow

## Problem

A first-time user on Ubuntu followed this path and got stuck:

1. `nyx doctor` → FAIL (nmap missing) → told to `sudo apt install nmap`
2. `nyx init --output my-network.yaml` → FAIL (nmap missing, before install)
3. Installed nmap
4. Skipped `nyx init` (no prompt to re-run it)
5. Ran `sudo nyx audit --spec my-network.yaml` → two simultaneous failures:
   - `sudo nyx: command not found` (sudo's restricted PATH doesn't include nyx's install location)
   - spec file doesn't exist (never ran `nyx init`)

Root causes:
- `nmapInstallHint()` uses `sudo apt install` which teaches users to reach for sudo
- `doctor` nmap PASS output doesn't clarify that nyx itself never needs root
- `doctor` success message doesn't tell users what to do next
- `audit` emits a generic `os.Open` error when the spec file doesn't exist

## Design: Approach A — Surgical Fixes

Three targeted changes, no structural refactoring.

### Change 1: `nmapInstallHint()` in `doctor.go`

Append a platform-aware "no sudo/admin needed" note to each install hint string.

| Platform | Appended note |
|----------|--------------|
| Linux    | `After installing, run nyx normally — no sudo required` |
| macOS    | `After installing, run nyx normally — no sudo required` |
| Windows  | `After installing, run nyx normally — no admin required` |

The note piggybacks on the existing violation hint display (the `→` indented line under `[FAIL]`), so it appears exactly where the user reads after the nmap failure.

### Change 2: nmap PASS summary in `doctor.go`

When nmap is found, append `(no root/admin needed to run nyx)` to the summary line:

```
[ OK ] nmap: Nmap version 7.94 ... (no root/admin needed to run nyx)
```

This reinforces the no-sudo message for users who run `doctor` again after installing nmap.

### Change 3: Missing spec file error in `audit.go`

Before calling `intent.LoadSpec`, stat the file. If it doesn't exist, return a structured error with the exact remediation commands using the user's own filename:

```
spec file "my-network.yaml" not found

  Create one with:
    nyx init --output my-network.yaml

  Then run:
    nyx audit --spec my-network.yaml
```

This replaces the raw `open my-network.yaml: no such file or directory` error from the OS.

## What This Does Not Change

- No new abstractions or helper packages
- No changes to `init.go`, `root.go`, or any other command
- No changes to JSON output format
- No changes to exit codes

## Files Changed

- `internal/cli/doctor.go` — changes 1 and 2
- `internal/cli/audit.go` — change 3

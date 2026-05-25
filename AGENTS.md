# AGENTS.md

## Build & Test

```bash
make build          # go build -o nyx ./cmd/nyx/
make test           # go test ./...
make vet            # go vet ./...
make release        # cross-compile linux/darwin (amd64+arm64) + windows/amd64
```

CI order: `go vet ./...` → `go test ./...` → `go build -o nyx ./cmd/nyx/`. Follow that order for local validation.

## Provider Registration

New providers require **two changes**:
1. Create the provider package (e.g. `internal/providers/foo/foo.go`) with an `init()` that calls `providers.Register()`.
2. Add a blank import in `cmd/nyx/main.go` (e.g. `_ "github.com/velasco-jp/nyx/internal/providers/foo"`).

Omitting the blank import means the provider is silently absent at runtime.

## Assertion Timeouts

Per-assertion timeouts in `internal/audit/engine.go`:
- `subnet_discovery`: 90s
- All others: 30s

These are hardcoded constants — no per-assertion override via spec.

## Nmap Dependency

The `nmap` backend spawns `nmap` as a subprocess. Tests in `backends/nmap` call `nmap.Available()` and skip when missing. Any integration test or live run requires nmap installed on `$PATH`.

## Platform-Specific Code

`internal/backends/system` uses Go build tags: `system_linux.go`, `system_darwin.go`, `system_windows.go`. Only `system.go` is shared. When adding system calls, provide all three platform files.

## Omada Backend Gotchas

- Not concurrency-safe — do not call its methods from multiple goroutines.
- `acl_check` assertions read Omada credentials from env vars (`OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`), not from flags.
- TLS verification is intentionally disabled (self-signed cert).

## Probe System

Assertions with `runner: <probe-name>` execute remotely via SSH. The probe system supports `isolation`, `network_health`, `port_check`, and `dns_check` over SSH. Other assertion types return an error if a runner is set.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid config (used by `main.go` when `cli.Execute()` returns error) |
| 3 | One or more warnings |

## Key Invariants

- `StatusWarn` from nmap (e.g. 0 hosts found) is **preserved** — the engine does not overwrite it to pass.
- Audit results are returned in the **same order** as spec assertions, despite concurrent execution.
- `internal/backends/batfish` and `internal/providers/opnsense` (beyond `info`) are stubs returning `ErrNotImplemented` / `ErrCapabilityUnsupported`.


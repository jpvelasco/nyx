# Observability: logs, traces, and metrics

nyx writes structured JSON-lines logs to `~/.nyx/nyx.log` (rotating, 5 MB × 3
files, owner-only) and can export the same telemetry — logs, traces, and
metrics — over OTLP/HTTP to a collector of your choice. The file log is
always on; OTLP export is opt-in and disabled by default.

## Configuration

| Environment variable | Meaning | Default |
|---|---|---|
| `NYX_OTLP_ENDPOINT` | OTLP/HTTP base URL, e.g. `http://localhost:4318`. The scheme picks plain HTTP vs TLS (`https://`). An explicit `http(s)://` URL is required; anything else is rejected at startup with a warning. | unset — OTLP disabled |
| `NYX_OTLP_HEADERS` | Optional comma-separated `key=value` pairs sent as headers on every export (e.g. `authorization=Bearer …`). Each pair splits on the first `=`. | unset |
| `NYX_LOG_FILE` | Log file path override. | `~/.nyx/nyx.log` |
| `NYX_LOG_LEVEL` | Minimum level (debug, info, warn, error). | `info` |

Example:

```bash
NYX_OTLP_ENDPOINT=http://localhost:4318 nyx audit --spec homelab.yaml
```

Any OTLP/HTTP collector works: an OpenTelemetry Collector, Grafana Alloy,
Grafana Cloud, or anything speaking OTLP/HTTP on ports `/v1/logs`,
`/v1/traces`, and `/v1/metrics`.

To disable export, simply unset `NYX_OTLP_ENDPOINT` — the rotating file log
remains the whole pipeline.

## What is emitted

All three signals carry the same PII-safe OTel resource: `service.name=nyx`,
`service.version`, `os.type`, `host.arch` — never host name or IP.

**Logs** — the same records as the rotating file log (one JSON object per
line, flattened). The records themselves carry no live spec values by
construction: assertions log their name/role, backends log through
`logSafeError` so error text never leaks controller addresses, and secrets
are never logged, written to spec files, or returned by `List`.

**Traces** — one span per audit run (`nyx.audit.run`) plus one span per
assertion (`nyx.assertion.<type>`), so a trace shows the shape and duration
of every audit. Span attributes carry only the assertion type — never
CIDRs, hostnames, or targets.

**Metrics**:

- `nyx_audit_assertions_total` — counter, attributes `type` (assertion
  type) and `status` (result status), one increment per finding.
- `nyx_audit_run_duration_ms` — histogram, total audit run duration in
  milliseconds.

## Security notes

- Exported payloads are secret-free by default: the same record contract as
  the file log applies (see `docs/naming.md`).
- Point `NYX_OTLP_ENDPOINT` at a collector you trust — exported telemetry
  is telemetry about your audit activity. For local collection, an
  `http://localhost:...` endpoint keeps traffic on the loopback
  interface.
- `NYX_OTLP_HEADERS` values are read from the environment and sent to the
  collector only; they are never logged, exported, or written to disk by
  nyx itself.
- The OTLP pipeline is best-effort: a collector outage never fails a nyx
  command, and telemetry flushes on process exit.

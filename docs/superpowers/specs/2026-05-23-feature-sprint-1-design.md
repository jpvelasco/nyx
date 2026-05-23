# Nyx Feature Sprint 1 — Design Spec

**Date:** 2026-05-23
**Status:** Approved

## Overview

This sprint adds four new assertion types, an SSH remote probe architecture, and a drift detection / scheduled audit system with webhook notifications. The goal is to close the gap between declared SDN intent and live network reality — specifically the case where a controller (e.g. Omada) reports a VLAN as isolated but traffic can still cross VLAN boundaries in practice.

---

## 1. New Assertion Types

All new types fit into the existing `assertions` array. The spec `version` remains `1`.

### 1.1 `port_check`

Verifies TCP/UDP port reachability on a target. Extends the nmap backend from ping-sweep only to port scanning.

**Fields:**

| Field | Required | Description |
|---|---|---|
| `target` | yes | IP address or declared network name |
| `ports` | yes | List of port numbers to check |
| `expect` | yes | `open` or `closed` |
| `protocol` | no | `tcp` (default) or `udp` |
| `scan_mode` | no | `polite` (default), `normal`, `aggressive` |
| `runner` | no | Probe name to run check from (see Section 2) |

**Example:**
```yaml
- type: port_check
  target: 10.0.40.5
  ports: [22, 443, 8096]
  expect: open
  scan_mode: polite
```

**Behavior:**
- Runs `nmap` with port list against target.
- `polite` mode: `-T2 --min-rate 50 --max-rate 100`. Will not trigger Omada flood detection.
- `normal` mode: `-T4 --min-rate 500` (current defaults).
- `aggressive` mode: `-T5`, full speed. Explicit opt-in only.
- Pass when all listed ports match `expect`. Fail when any port mismatches.
- Evidence includes per-port state.

---

### 1.2 `dns_check`

Verifies DNS resolution correctness and optionally DNSSEC chain validation.

**Fields:**

| Field | Required | Description |
|---|---|---|
| `query` | yes | Hostname to resolve |
| `expect_ip` | no | Expected resolved IP address |
| `server` | no | DNS server to query. Uses system resolver if omitted |
| `dnssec` | no | `true` to validate DNSSEC chain. Default `false` |
| `runner` | no | Probe name to run check from |

**Example:**
```yaml
- type: dns_check
  query: nas.home.lan
  expect_ip: 10.0.40.5
  server: 10.0.10.1
  dnssec: true
```

**Behavior:**
- Resolves `query` using the specified or system resolver.
- Pass if resolved IP matches `expect_ip` (when set).
- If `dnssec: true`, validates the full DNSSEC chain using `dig +dnssec` or equivalent. Fail if chain is broken or unsigned when expected to be signed.
- Evidence includes raw resolver response.

---

### 1.3 `network_health`

Checks latency, packet loss, and MTU path between the runner and a target.

**Fields:**

| Field | Required | Description |
|---|---|---|
| `target` | yes | IP address or network name (probes gateway) |
| `expect_latency_ms` | no | Maximum acceptable average RTT in ms |
| `expect_loss_pct` | no | Maximum acceptable packet loss percentage (0–100) |
| `expect_mtu` | no | Expected MTU path size in bytes |
| `runner` | no | Probe name to run check from |

**Example:**
```yaml
- type: network_health
  target: 10.0.10.1
  expect_latency_ms: 10
  expect_loss_pct: 0
  expect_mtu: 1500
```

**Behavior:**
- Sends 10 ICMP pings, records RTT and loss. Uses system backend (already cross-platform).
- If `expect_mtu` set: probes path MTU by sending progressively-sized packets with DF bit set until fragmentation occurs. Reports discovered MTU.
- Fail if observed latency or loss exceeds declared maximums.
- Warn (not fail) if MTU is lower than declared but within 10% (fragmentation may be intentional).
- Evidence includes raw ping output and MTU probe steps.

---

### 1.4 `acl_check`

Validates that live controller ACL rules match a declared policy in the spec. Catches the case where Omada reports a VLAN as isolated but the ACL rules are incomplete or missing.

**Fields:**

| Field | Required | Description |
|---|---|---|
| `provider` | yes | Provider name (e.g. `omada`) |
| `policy` | yes | Name of a policy declared in the spec's `policies` section |
| `expect` | yes | `enforced` or `not_enforced` |

**Example:**
```yaml
- type: acl_check
  provider: omada
  policy: iot-isolation
  expect: enforced
```

**Behavior:**
- Fetches ACL rules from the named provider.
- Resolves the named `policy` from the spec's `policies` section.
- Checks whether a matching ACL rule exists that enforces the declared `from`→`to` `action`.
- Pass when `expect: enforced` and a matching ACL rule is found.
- Fail when `expect: enforced` and no matching rule exists — this is the gap between what Omada shows in the UI and what is actually configured.
- Violations include which rules are present vs. what would be needed.
- Evidence includes the raw ACL rule list from the provider.

---

## 2. SSH Remote Probe Architecture

Enables assertions to run from a node on a different VLAN, enabling true isolation verification rather than local-host approximations.

### 2.1 Probe Declaration

Probes are declared at the top level of the spec:

```yaml
probes:
  - name: laptop
    host: 192.168.30.45
    user: jp
    key: ~/.ssh/id_ed25519   # optional, falls back to ssh-agent
    vlan: iot                # informational: which network this probe lives on
```

**Fields:**

| Field | Required | Description |
|---|---|---|
| `name` | yes | Unique identifier, referenced in assertions |
| `host` | yes | IP or hostname of the probe node |
| `user` | yes | SSH username |
| `key` | no | Path to private key. Falls back to ssh-agent if omitted |
| `vlan` | no | Which network this probe is on (informational, used in reports) |

### 2.2 Assertion Usage

Any assertion that supports `runner` can reference a probe by name:

```yaml
- type: isolation
  from: iot
  to: home
  expect: deny
  runner: laptop
```

When `runner` is set:
- nyx SSHes into the probe node.
- Runs the equivalent check command remotely using only tools expected to be present on the probe (`ping`, `nc`, `nslookup`, `dig`). No nyx required on probe.
- Captures stdout/stderr, parses results locally.
- Returns a standard `CheckResult` — the caller sees no difference from a local check.
- Evidence includes the SSH target and remote command that was run.

When `runner` is omitted: runs locally as today.

### 2.3 Connection Handling

- SSH connection is established per-assertion (not pooled). Acceptable for on-demand audit runs.
- Connection timeout: 10 seconds.
- If the probe is unreachable, the assertion returns `error` status with a clear message: `probe "laptop" unreachable at 192.168.30.45:22 — is the host on VLAN iot and SSH running?`
- `nyx doctor --spec <file>` checks probe reachability as part of its pre-flight.

### 2.4 Security

- Private keys are read from the declared path or ssh-agent. Never stored in the spec.
- Only outbound SSH from the nyx host to the probe. No inbound connections.
- Remote commands are constructed as fixed argument lists, never shell-interpolated from spec input. No command injection surface.

---

## 3. Scan Mode Defaults

All scan-based assertions (`subnet_discovery`, `port_check`) default to `polite` mode going forward.

| Mode | nmap flags | Use case |
|---|---|---|
| `polite` | `-T2 --min-rate 50 --max-rate 100` | Default. Safe on Omada and other SDN controllers that have flood detection |
| `normal` | `-T4 --min-rate 500` | Faster scans on trusted networks |
| `aggressive` | `-T5` | Explicit opt-in only. Not recommended on production networks |

**Migration:** Existing `subnet_discovery` assertions that do not set `scan_timing` will move from effective `-T4` to `-T2`. This is a behavior change but the right default. The `nyx doctor` output will note when `normal` or `aggressive` mode is in use.

---

## 4. Drift Detection

Detects when a network's live behavior changes between runs and notifies the operator.

### 4.1 State Snapshots

Each audit run writes a state snapshot to `~/.nyx/snapshots/<site>-latest.json`. The snapshot contains the full `AuditReport` from that run.

Previous snapshots are rotated: `<site>-latest.json`, `<site>-prev.json`, `<site>-2.json` (up to 5). This gives a short history without unbounded disk use.

### 4.2 Drift Detection

After each audit, nyx compares the new report to `<site>-prev.json`. A **drift event** is recorded when:
- Any check changes status (pass→fail, fail→pass, pass→warn, etc.)
- A new violation appears in a previously-passing check
- A previously-failing check is now passing (recovery is also a drift event worth notifying)

Drift is not triggered by timing changes (duration_ms) or evidence changes that don't affect status.

### 4.3 `nyx drift status`

Shows the diff between the last two snapshots:

```
nyx drift status [--site home-lab]
```

Output example:
```
Drift detected since 2026-05-23 08:12:01

  iot-isolation (acl_check)     pass → fail
    new violation: no ACL rule found for iot → home deny

  clients subnet (subnet_discovery)  warn → pass
    recovered: host count 3 (was 0)

Last clean run: 2026-05-22 22:05:44
```

With `--json`: returns structured diff as JSON.

### 4.4 Scheduled Audits

```
nyx watch --spec homelab.yaml --interval 1h
```

Runs in the foreground, executing `audit` on the given interval. On each run:
1. Writes a snapshot.
2. Computes drift.
3. If drift detected: fires configured notifications.
4. Logs the run result.

For background/system scheduling, nyx emits a ready-made cron line on setup:

```
nyx watch --spec homelab.yaml --cron-install
# prints: 0 * * * * /path/to/nyx audit --spec /path/to/homelab.yaml --snapshot
```

The `--snapshot` flag on `nyx audit` writes a snapshot and computes drift without the watch loop — composable with any external scheduler (cron, systemd timer, Task Scheduler).

### 4.5 Notifications

Notifications are configured in a separate config file at `~/.nyx/notify.yaml` (not in the spec, since they're per-operator not per-network):

```yaml
notify:
  on: [drift, error]   # drift = status change, error = audit couldn't run

  webhook:
    url: https://ntfy.sh/my-nyx-alerts
    method: POST
    headers:
      Title: "nyx drift detected"
      Priority: "high"

  smtp:                 # optional
    host: smtp.example.com
    port: 587
    from: nyx@example.com
    to: [jp@example.com]
    username: nyx@example.com
    password_env: NYX_SMTP_PASSWORD
```

**Webhook** is the primary channel — works with ntfy.sh, Slack, Discord, Home Assistant webhooks, anything HTTP. **SMTP** is optional. If no `notify.yaml` exists, drift is still recorded locally — notifications are opt-in.

Notification payload (webhook body):

```json
{
  "site": "home-lab",
  "run_at": "2026-05-23T09:00:01Z",
  "drift": true,
  "changes": [
    {"check": "iot-isolation", "from": "pass", "to": "fail"},
    {"check": "clients subnet", "from": "warn", "to": "pass"}
  ],
  "report_url": null
}
```

---

## 5. Spec Changes Summary

New top-level field: `probes`. Everything else extends existing structures.

```yaml
version: 1
site: home-lab

probes:
  - name: laptop
    host: 192.168.30.45
    user: jp
    vlan: iot

networks: [...]
vpn: [...]
policies: [...]
assertions:
  - type: port_check
    target: 10.0.40.5
    ports: [22, 443]
    expect: open

  - type: dns_check
    query: nas.home.lan
    expect_ip: 10.0.40.5
    dnssec: true

  - type: network_health
    target: 10.0.10.1
    expect_latency_ms: 10
    expect_loss_pct: 0

  - type: acl_check
    provider: omada
    policy: iot-isolation
    expect: enforced

  - type: isolation
    from: iot
    to: home
    expect: deny
    runner: laptop
```

---

## 6. Implementation Order

1. **Scan mode defaults** — change `subnet_discovery` default to `polite`, add `scan_mode` field to spec and nmap backend. Fast, safe, unblocks everything else.
2. **`port_check`** — extends nmap backend, new assertion type, new engine handler.
3. **`dns_check`** — new system backend function (`dig`/`nslookup`), new assertion type.
4. **`network_health`** — extends system backend ping (already exists), adds MTU probe.
5. **SSH probe architecture** — `probes` spec field, SSH executor, `runner` wiring in engine.
6. **`acl_check`** — extends Omada backend to expose ACL rules, new assertion type.
7. **Drift detection + snapshots** — `--snapshot` flag, snapshot writer/reader, diff engine.
8. **`nyx drift status`** — CLI command over snapshot diff.
9. **`nyx watch`** — scheduled loop, `--cron-install` helper.
10. **Notifications** — `~/.nyx/notify.yaml`, webhook sender, SMTP sender.
11. **`nyx doctor` updates** — probe reachability pre-flight, scan mode warnings.
12. **MCP parity** — new MCP tools for all new assertion types + `drift_status`.
13. **Spec validation** — extend `ValidateSpec` for all new types and `probes`.
14. **Examples + CLAUDE.md update**.

---

## 7. Out of Scope

- UniFi, pfSense, Meraki providers (OPNsense already stubbed)
- Full OPNsense ACL check (Omada only this sprint)
- BGP/OSPF state checks
- Passive traffic analysis / packet capture
- Web UI or dashboard
- nyx installed on probe nodes (probe runs raw shell commands only)
- HTTP MCP transport
- Dynamic provider plugins

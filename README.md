<p align="center">
  <a href="https://github.com/jpvelasco/nyx/actions/workflows/ci.yml"><img src="https://github.com/jpvelasco/nyx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jpvelasco/nyx/releases/latest"><img src="https://img.shields.io/github/v/release/jpvelasco/nyx" alt="Release"></a>
  <a href="https://github.com/jpvelasco/nyx/blob/main/LICENSE"><img src="https://img.shields.io/github/license/jpvelasco/nyx" alt="License"></a>
  <a href="https://github.com/jpvelasco/nyx/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/jpvelasco/nyx" alt="Go"></a>
  <a href="https://www.npmjs.com/package/nyx-audit-cli"><img src="https://img.shields.io/npm/v/nyx-audit-cli" alt="npm"></a>
</p>

# nyx

Your homelab should be doing what you think it's doing. **nyx** proves it.

Validate your network behavior against a declared YAML intent model — VLAN isolation, VPN routing, host counts, route correctness — all verified with live network checks. When something drifts, nyx tells you exactly what changed and how to fix it.

Every command produces structured JSON for automation and AI agent consumption.

**Install from npm:** [`nyx-audit-cli`](https://www.npmjs.com/package/nyx-audit-cli) — `npm install -g nyx-audit-cli`

## Quick Start

```bash
# Install prebuilt binary (recommended)
npm install -g nyx-audit-cli

# If npm blocked the postinstall script (Ubuntu 26+, hardened envs), just run nyx once —
# it detects the missing binary and downloads it automatically. Or manually:
#   node $(npm root -g)/nyx-audit-cli/install.js

# Or build from source (requires Go 1.25+)
git clone https://github.com/jpvelasco/nyx.git && cd nyx && make build

# Discover hosts on a subnet
sudo nyx discover --subnet 10.0.10.0/24

# Run a full audit from a spec file
sudo nyx audit --spec examples/homelab.yaml

# Check environment health
nyx doctor
```

### Longer-Term Confidence

Once you've verified your network is behaving correctly, lock in that baseline. Future drift checks will show you exactly what changed — new failures, degradations, or fixes — so you can sleep at night knowing your segmentation and policies are still holding.

```bash
# After a clean audit, save the baseline from the persisted snapshot
sudo nyx audit --spec examples/homelab.yaml
nyx snapshot list
nyx snapshot baseline ~/.nyx/snapshots/snapshot-YYYYMMDD-HHMMSS.json

# Days or weeks later, re-audit and check drift
sudo nyx audit --spec examples/homelab.yaml && nyx drift status
```

For the full story of what this feels like on a real multi-VLAN homelab (including when things go wrong and drift catches it), see [docs/walkthrough.md](docs/walkthrough.md).

## Prerequisites

- **Go 1.25+** — to build from source
- **nmap** — required for `discover` and `subnet_discovery` assertions

  nyx does not bundle nmap. Install it for your platform:

  | Platform | Command |
  |----------|---------|
  | Ubuntu/Debian | `sudo apt install nmap` |
  | Fedora/RHEL | `sudo dnf install nmap` |
  | Arch Linux | `sudo pacman -S nmap` |
  | macOS | `brew install nmap` |
  | Windows | `winget install nmap` |

  If nmap is missing, `nyx doctor` will show the exact install command for your system.

- Root/sudo — required for nmap subnet scans on some platforms

## Commands

| Command | Description | Backends Used |
|---------|-------------|---------------|
| `discover` | Discover hosts in a subnet via nmap ping sweep | nmap |
| `check-routes` | Validate route and gateway to a target IP | system (ip route) |
| `check-vpn` | Verify traffic routes through a VPN tunnel | system (ip route) |
| `verify-isolation` | Check that a target is unreachable (isolation) | system (ping) |
| `audit` | Run all assertions from a YAML spec file | nmap + system |
| `doctor` | Check environment health and optional spec validation | all |
| `provider` | Provider management (`list` subcommand) | all |
| `omada` | Omada SDN vendor commands (`info`, `import`, `check`) | omada backend |
| `opnsense` | OPNsense vendor commands (`info`, `import`, `check`) | opnsense backend |
| `snapshot` | Manage audit history (`baseline`, `list`, `delete`, `clear-baseline`) | — |
| `drift` | Detect drift in audit results (`status`, `compare`) | — |
| `mcp serve` | Start MCP server for AI agent integration | all |
| `version` | Print version | — |

### Global Flags

```
--json            Output as JSON (available on all commands)
--output <path>   Write output to file instead of stdout
--spec <file>     Path to YAML spec file (used by audit)
--verbose         Verbose output with additional evidence
--timeout <dur>   Timeout for operations (default 120s)
```

## YAML Spec Format

nyx validates your network against a declared intent model:

```yaml
version: 1
site: home-lab

networks:
  - name: trusted
    cidr: 10.0.10.0/24
    gateway: 10.0.10.1
    zone: trusted
    vlan: 10
  - name: iot
    cidr: 10.0.60.0/24
    gateway: 10.0.60.1
    zone: iot
    vlan: 60
  # ... more VLANs

vpn:
  - name: home-wg
    type: wireguard
    interface: wg0
    expected_routes:
      - 10.0.0.0/8
    mode: split-tunnel

policies:
  - name: iot-to-trusted-deny
    from: iot
    to: trusted
    action: deny

assertions:
  - type: subnet_discovery
    network: trusted
    expect_hosts_min: 10
    expect_hosts_max: 30
  - type: isolation
    from: iot
    to: trusted
    expect: deny
  - type: vpn_route
    vpn: home-wg
    target: 10.0.20.50
    expect_tunnel: true
  - type: route_check
    target: 10.0.10.1
```

See `examples/homelab.yaml` for the complete realistic 7-VLAN example used throughout this document.  
See the [full structured spec reference](docs/spec.html) (modern HTML).  
See `docs/walkthrough.md` for the full narrative — what it actually feels like to land on a complex network, hit real problems, get useful recommendations, and use drift to sleep better at night.

### Assertion Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `subnet_discovery` | Count hosts in a network | `network`, `expect_hosts_min`, `expect_hosts_max` |
| `isolation` | Verify zone-to-zone unreachability | `from`, `to`, `expect: deny` |
| `vpn_route` | Check traffic routes through VPN | `vpn`, `target`, `expect_tunnel` |
| `route_check` | Verify route exists to target | `target` |
| `port_check` | Verify TCP ports are open | `target`, `ports`, `expect: open` |
| `dns_check` | Verify DNS resolution | `query`, `expect_ip`, `server` |
| `network_health` | Verify latency and packet loss | `target`, `expect_latency_ms`, `expect_loss_pct` |
| `acl_check` | Verify controller policy enforcement | `provider`, `policy`, `expect: enforced` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid configuration |
| 3 | One or more warnings |

## Snapshot & Drift Detection

After a clean audit, save the result as a baseline:

```bash
nyx snapshot baseline
```

Later, after re-running an audit, check what changed:

```bash
nyx drift status
```

The drift report shows new failures, degradations, fixes, and improvements with a clear net change summary. You can also restore a previous baseline from a saved snapshot:

```bash
nyx snapshot baseline ~/.nyx/snapshots/snapshot-20250601-140000.json
```

### Snapshot Commands

| Command | Description |
|---------|-------------|
| `nyx snapshot baseline` | Set current audit as baseline |
| `nyx snapshot baseline <file>` | Restore baseline from saved snapshot |
| `nyx snapshot list` | List all saved snapshots |
| `nyx snapshot delete [name]` | Delete a snapshot (or all if no name given) |
| `nyx snapshot clear-baseline` | Remove the current baseline |
| `nyx drift status` | Compare latest audit against baseline |
| `nyx drift compare <snap1> <snap2>` | Compare any two snapshots |

Snapshots are stored in `~/.nyx/snapshots/` with automatic rotation at 50 snapshots.

## MCP Server

nyx includes a Model Context Protocol server for AI agent integration:

```bash
nyx mcp serve --transport stdio
```

### Claude Code Integration

Add to your MCP config:

```json
{
  "mcpServers": {
    "nyx": {
      "command": "/path/to/nyx",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `discover_subnet` | Discover hosts in a subnet (supports `scan_timing`, `scan_min_rate`) |
| `check_routes` | Check route to a target — returns CheckResult |
| `check_vpn` | Check VPN tunnel routing — returns CheckResult |
| `verify_isolation` | Verify network isolation |
| `run_audit` | Run full audit from spec |
| `load_spec` | Load and validate a spec file |
| `get_interfaces` | List network interfaces |
| `ping_target` | Ping a target |
| `run_doctor` | Check environment health + optional spec validation + probe SSH reachability/auth (read-only) |
| `provider_list` | List registered providers |
| `omada_get_info` | Fetch Omada controller metadata (no auth) |
| `omada_list_networks` | List Omada LAN networks/VLANs for a site |
| `omada_list_acls` | List Omada ACL + gateway ACL rules for a site |
| `omada_list_clients` | List Omada connected clients for a site |
| `omada_import` | Import Omada state into an intent spec (networks, policies, assertions) |
| `omada_plan` | Preview ACL rule differences between the controller and a proposed spec (read-only) |
| `omada_apply_acl` | Apply an ACL policy change: create a rule or enable a disabled matching rule. Dry-run is the default; a real apply is followed by a targeted isolation audit |
| `opnsense_get_info` | Fetch OPNsense firmware metadata |
| `opnsense_list_interfaces` | List OPNsense interfaces with IP configuration |
| `opnsense_list_firewall_rules` | List OPNsense firewall filter rules |
| `opnsense_list_clients` | List OPNsense DHCP leases (host inventory) |

### Agent Workflow: Observe → Plan → Apply → Verify

nyx supports a closed loop for enforcing intent on Omada:

1. **Observe** — `run_audit` against a spec, or `omada_list_networks` / `omada_list_acls` / `omada_list_clients` to inspect controller state.
2. **Import** — `omada_import` builds a baseline intent spec from the controller (networks, policies, assertions).
3. **Plan** — `omada_plan` previews the ACL differences between the controller and a proposed spec. Nothing is changed.
4. **Apply (dry-run)** — `omada_apply_acl` with `dry_run=true` (the default) previews the mutation: outcome (`created`/`enabled`/`unchanged`) and the resulting rule state. Nothing is written.
5. **Apply (real)** — repeat with `dry_run=false` to create the rule or enable a disabled matching rule.
6. **Verify** — a real apply runs a targeted isolation audit of the changed endpoints (`post_audit=true` by default). Run `run_audit` again to confirm the whole spec still passes.

Safety rails:

- `omada_apply_acl` is **dry-run by default**; a real apply requires an explicit `dry_run=false`.
- Mutation is idempotent and limited to creating rules or enabling disabled matching rules. A conflicting rule with a different policy is rejected, and the agent is pointed at `omada_plan` to reconcile.
- Credentials come from environment variables (`OMADA_HOST`, `OMADA_CLIENT_ID`, `OMADA_CLIENT_SECRET`, `OMADA_SITE`) — never from spec, flags, or tool arguments — and never appear in tool output.
- A post-apply audit failure is reported but never fatal; the agent decides the next step from the evidence.

## Providers

nyx supports multiple network backends via a provider system. Vendors register at startup and expose vendor-specific commands.

### List Providers

```bash
nyx provider list
```

### Omada SDN

Omada provider supports Omada SDN controller 6.x. Pass your controller address (usually on your management VLAN):

```bash
# Example using a typical management IP
nyx omada info --host 192.168.11.20

# Generate spec from controller
nyx omada import --host 192.168.11.20 --client-id <client-id> --client-secret <client-secret>

# Import and audit in one step
nyx omada check --host 192.168.11.20 --client-id <client-id> --client-secret <client-secret> --spec examples/homelab.yaml
```

Credentials can be passed via flags or env vars: `OMADA_HOST`, `OMADA_CLIENT_ID`, `OMADA_CLIENT_SECRET`.

### OPNsense

OPNsense provider supports info, import, and check. Use your OPNsense address (typically the LAN or a management IP):

```bash
# Example using a typical management IP
nyx opnsense info --host 192.168.11.1 --api-key <key> --api-secret <secret>

# Generate spec from OPNsense
nyx opnsense import --host 192.168.11.1 --api-key <key> --api-secret <secret>

# Import and audit in one step
nyx opnsense check --host 192.168.11.1 --api-key <key> --api-secret <secret> --spec examples/homelab.yaml
```

## Project Structure

```
nyx/
  cmd/nyx/              # CLI entry point
  internal/
    cli/                # Cobra command definitions
    models/             # Result envelope, report types
    intent/             # YAML spec loader and validation
    audit/              # Audit engine
    backends/
      nmap/             # Nmap subprocess wrapper
      system/           # Platform-specific system commands
      omada/            # Omada SDN client (low-level)
      batfish/          # Stub, planned for v2
    providers/          # Provider interface + registry
      omada/            # Omada provider (wraps backends/omada)
      opnsense/         # OPNsense provider
    mcp/                # MCP stdio server
    report/             # Output renderers
    recommendations/    # Failure analysis and remediation hints
    snapshot/           # Audit history and drift detection
    logger/             # JSON-lines rotating logger (~/.nyx/nyx.log)
    version/            # Single-source version constant
  examples/             # Example YAML specs
  testdata/             # Test fixtures
  .github/workflows/    # CI/CD
```

## Development

```bash
make build    # Build binary
make test     # Run tests (fast, no coverage)
make coverage # Run tests with coverage output
make check    # Full CI suite: gosec → vet → coverage → build
make vet      # Run go vet
make clean    # Remove built binaries and coverage.out
make release  # Cross-compile for all platforms
```

## Platform Support

| Platform | Status | Commands Used |
|----------|--------|---------------|
| Linux | Full support | `ip route`, `ip route get`, `ip addr show`, `ping -c -W`, `traceroute -n` |
| macOS | Full support | `netstat -rn`, `route -n get`, `ifconfig`, `ping -c -t`, `traceroute -n` |
| Windows | Full support | `route print`, `ping -n -w`, `tracert -d`, Go `net.Interfaces()` |

All three platforms cross-compile from any OS. Platform-specific code uses Go build tags.

## Distribution & Releases

Official binaries are published automatically on every `v*` tag via GitHub Releases.

```bash
# Build from source (recommended for development)
make build

# Or install via npm (once a release exists)
npm install -g nyx-audit-cli
```

The npm package (`nyx-audit-cli`) is a thin platform-aware wrapper that downloads the matching prebuilt binary from the GitHub Release.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) (or the release workflow) for the exact tagging process.

## License

MIT

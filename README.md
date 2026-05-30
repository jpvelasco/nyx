# nyx

Your homelab should be doing what you think it's doing. **nyx** proves it.

Validate your network behavior against a declared YAML intent model — VLAN isolation, VPN routing, host counts, route correctness — all verified with live network checks. When something drifts, nyx tells you exactly what changed and how to fix it.

Every command produces structured JSON for automation and AI agent consumption.

## Quick Start

```bash
# Build from source (requires Go 1.22+)
git clone https://github.com/velasco-jp/nyx.git && cd nyx && make build

# Discover hosts on a subnet
sudo nyx discover --subnet 192.168.0.0/24

# Run a full audit from a spec file
sudo nyx audit --spec examples/homelab.yaml

# Check environment health
nyx doctor
```

### Longer-Term Confidence

Once you've verified your network is behaving correctly, lock in that baseline and track drift over time:

```bash
# After a clean audit, save the baseline
nyx snapshot baseline

# Days or weeks later, re-audit and check drift
sudo nyx audit --spec examples/homelab.yaml && nyx drift status
```

The drift report tells you exactly what's new, what's fixed, and what's degraded — so you always know if your segmentation is still holding.

## Prerequisites

- **Go 1.22+** — to build from source
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
--timeout <dur>   Timeout for operations (default 60s)
```

## YAML Spec Format

nyx validates your network against a declared intent model:

```yaml
version: 1
site: home-lab

networks:
  - name: main
    cidr: 192.168.0.0/24
    gateway: 192.168.0.254
    zone: trusted
    vlan: 1
  - name: iot
    cidr: 192.168.60.0/24
    gateway: 192.168.60.1
    zone: iot
    vlan: 60
  # ... more VLANs

vpn:
  - name: home-wg
    type: wireguard
    interface: wg0
    expected_routes:
      - 192.168.0.0/16
    mode: split-tunnel

policies:
  - name: iot-to-trusted-deny
    from: iot
    to: trusted
    action: deny

assertions:
  - type: subnet_discovery
    network: main
    expect_hosts_min: 10
    expect_hosts_max: 30
  - type: isolation
    from: iot
    to: trusted
    expect: deny
  - type: vpn_route
    vpn: home-wg
    target: 192.168.20.15
    expect_tunnel: true
  - type: route_check
    target: 192.168.0.254
```

See `examples/homelab.yaml` for the full 7-VLAN example. See `docs/walkthrough.md` for a step-by-step walkthrough from zero to drift detection.

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
| `run_doctor` | Check environment health + optional spec validation |
| `provider_list` | List registered providers |

## Providers

nyx supports multiple network backends via a provider system. Vendors register at startup and expose vendor-specific commands.

### List Providers

```bash
nyx provider list
```

### Omada SDN

Omada provider supports Omada SDN controller 6.x:

```bash
# Get info (no auth required)
nyx omada info --host 192.168.10.20

# Generate spec from controller
nyx omada import --host 192.168.10.20 --username admin --password password

# Import and audit in one step
nyx omada check --host 192.168.10.20 --username admin --password password --spec examples/homelab.yaml
```

Credentials can be passed via flags or env vars: `OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`.

### OPNsense

OPNsense provider supports info, import, and check:

```bash
# Get info
nyx opnsense info --host 192.168.10.1 --api-key <key> --api-secret <secret>

# Generate spec from OPNsense
nyx opnsense import --host 192.168.10.1 --api-key <key> --api-secret <secret>

# Import and audit in one step
nyx opnsense check --host 192.168.10.1 --api-key <key> --api-secret <secret> --spec examples/homelab.yaml
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
make test     # Run tests
make vet      # Run go vet
make clean    # Remove built binaries
make release  # Cross-compile for all platforms
```

## Platform Support

| Platform | Status | Commands Used |
|----------|--------|---------------|
| Linux | Full support | `ip route`, `ip route get`, `ip addr show`, `ping -c -W`, `traceroute -n` |
| macOS | Full support | `netstat -rn`, `route -n get`, `ifconfig`, `ping -c -t`, `traceroute -n` |
| Windows | Full support | `route print`, `ping -n -w`, `tracert -d`, Go `net.Interfaces()` |

All three platforms cross-compile from any OS. Platform-specific code uses Go build tags.

## npm Distribution

```bash
npm install -g @nyx/cli
```

The npm package is a thin wrapper that downloads the prebuilt Go binary for your platform. For v0.1.0, build from source instead (binaries not yet published to GitHub Releases).

## License

MIT

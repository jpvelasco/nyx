# nyx

Network intent validation tool for homelabs. Validate your network behavior against a declared YAML intent model using live network checks (nmap, ping, traceroute, route inspection).

nyx verifies VLAN isolation, VPN routing, subnet discovery, and topology correctness. Every command produces structured JSON for automation and AI agent consumption.

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

## Quick Start

```bash
# Build from source (requires Go 1.22+)
git clone https://github.com/velasco-jp/nyx.git
cd nyx
make build

# Discover hosts on a subnet (requires nmap)
sudo nyx discover --subnet 10.0.20.0/24 --json

# Check route to a target
nyx check-routes --target 10.0.30.10

# Check VPN routing
nyx check-vpn --target 10.0.20.15

# Verify isolation
nyx verify-isolation --from zone:clients --to 10.0.30.1

# Run a full audit from a spec file
sudo nyx audit --spec examples/homelab.yaml --json

# Check environment health
nyx doctor

# List registered providers
nyx provider list
```

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
| `opnsense` | OPNsense vendor commands (`info`) | opnsense backend |
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
  - name: mgmt
    cidr: 10.0.10.0/24
    gateway: 10.0.10.1
    zone: management
  - name: clients
    cidr: 10.0.20.0/24
    gateway: 10.0.20.1
    zone: clients
  - name: iot
    cidr: 10.0.30.0/24
    gateway: 10.0.30.1
    zone: iot

vpn:
  - name: home-wg
    type: wireguard
    interface: wg0
    expected_routes:
      - 10.0.0.0/16
    mode: split-tunnel

policies:
  - name: iot-isolation
    from: iot
    to: management
    action: deny
    except:
      - protocol: tcp
        port: 443
        target: 10.0.10.5

assertions:
  - type: subnet_discovery
    network: mgmt
    expect_hosts_max: 30
  - type: isolation
    from: clients
    to: iot
    expect: deny
  - type: vpn_route
    vpn: home-wg
    target: 10.0.20.15
    expect_tunnel: true
  - type: route_check
    target: 10.0.10.1
```

See `examples/homelab.yaml` for a full example.

### Assertion Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `subnet_discovery` | Count hosts in a network | `network`, `expect_hosts_min`, `expect_hosts_max` |
| `isolation` | Verify zone-to-zone unreachability | `from`, `to`, `expect: deny` |
| `vpn_route` | Check traffic routes through VPN | `vpn`, `target`, `expect_tunnel` |
| `route_check` | Verify route exists to target | `target` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more assertions failed |
| 2 | Execution error or invalid configuration |
| 3 | One or more warnings |

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
nyx omada info --host 10.0.10.20

# Generate spec from controller
nyx omada import --host 10.0.10.20 --username admin --password password

# Import and audit in one step
nyx omada check --host 10.0.10.20 --username admin --password password --spec examples/homelab.yaml
```

Credentials can be passed via flags or env vars: `OMADA_HOST`, `OMADA_USERNAME`, `OMADA_PASSWORD`.

### OPNsense

OPNsense provider (info only):

```bash
# Get info
nyx opnsense info --host 10.0.10.1 --username admin --password password
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
      opnsense/         # OPNsense provider stub (Info only)
    mcp/                # MCP stdio server
    report/             # Output renderers
    recommendations/    # Failure analysis and remediation hints
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

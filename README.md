# netaudit

Validate private network behavior against intended state. Built for homelabs, labs, and developer-operated environments.

netaudit combines live network checks (nmap, ping, traceroute, route inspection) with a YAML-based intent model to verify VLAN isolation, VPN routing, subnet discovery, and topology drift. Every command produces structured JSON for automation and AI agent consumption.

## Quick Start

```bash
# Build from source (requires Go 1.22+)
git clone https://github.com/velasco-jp/netaudit.git
cd netaudit
make build

# Discover hosts on a subnet (requires nmap)
sudo netaudit discover --subnet 10.0.20.0/24 --json

# Check route to a target
netaudit check-routes --target 10.0.30.10

# Check VPN routing
netaudit check-vpn --target 10.0.20.15

# Verify isolation
netaudit verify-isolation --from zone:clients --to 10.0.30.1

# Run a full audit from a spec file
sudo netaudit audit --spec examples/homelab.yaml --json
```

## Requirements

- **Go 1.22+** — to build from source
- **Linux** — primary target platform; uses `ip`, `ping`, `traceroute`
- **nmap** — required for `discover` and spec-based discovery assertions
  - Install: `sudo apt install nmap` / `sudo dnf install nmap`
- Root/sudo — required for nmap subnet scans and some route operations

## Commands

| Command | Description | Backends Used |
|---------|-------------|---------------|
| `discover` | Discover hosts in a subnet via nmap ping sweep | nmap |
| `check-routes` | Validate route and gateway to a target IP | system (ip route) |
| `check-vpn` | Verify traffic routes through a VPN tunnel | system (ip route) |
| `verify-isolation` | Check that a target is unreachable (isolation) | system (ping) |
| `audit` | Run all assertions from a YAML spec file | nmap + system |
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

netaudit validates your network against a declared intent model:

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
| 3 | One or more assertions returned a warning |

## MCP Server

netaudit includes a Model Context Protocol server for AI agent integration:

```bash
netaudit mcp serve --transport stdio
```

### Claude Code Integration

Add to your MCP config:

```json
{
  "mcpServers": {
    "netaudit": {
      "command": "/path/to/netaudit",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `discover_subnet` | Discover hosts in a subnet |
| `check_routes` | Check route to a target |
| `check_vpn` | Check VPN tunnel routing |
| `verify_isolation` | Verify network isolation |
| `run_audit` | Run full audit from spec |
| `load_spec` | Load and validate a spec file |
| `get_interfaces` | List network interfaces |
| `ping_target` | Ping a target |

## npm Distribution

```bash
npm install -g @netaudit/cli
```

The npm package is a thin wrapper that downloads the prebuilt Go binary for your platform. For v0.1.0, build from source instead (binaries not yet published to GitHub Releases).

## Project Structure

```
netaudit/
  cmd/netaudit/           # CLI entry point
  internal/
    cli/                  # Cobra command definitions
    models/               # Result envelope, report types
    intent/               # YAML spec loader and validation
    audit/                # Audit engine (orchestration, assertion evaluation)
    backends/
      nmap/               # Nmap subprocess wrapper and output parser
      system/             # Linux system commands (ip, ping, traceroute)
      batfish/            # Stub for v2 Batfish integration
    mcp/                  # MCP stdio server
    report/               # Human and JSON output renderers
  examples/               # Example YAML specs
  npm/                    # npm distribution scaffold
  testdata/               # Test fixtures
  .github/workflows/      # CI/CD
```

## Development

```bash
make build    # Build binary
make test     # Run tests
make vet      # Run go vet
make clean    # Remove built binaries
make release  # Cross-compile for all platforms
```

## v0.1.0 Status

### Implemented and Working

- All 6 CLI commands with `--json` support
- Nmap backend: `nmap -sn` ping sweep with output parsing
- System backend: `ip route`, `ip route get`, `ping`, `traceroute`, interface detection
- WireGuard/VPN interface detection
- YAML spec loading with validation (version, CIDR, gateway, policy, assertion types)
- Audit engine: runs all assertions, aggregates results, correct exit codes
- MCP stdio server with 8 read-only tools
- Result envelope normalization
- Human and JSON report rendering
- Unit tests for spec parsing (9 tests) and result normalization (4 tests)
- npm distribution scaffold
- CI workflow for GitHub Actions
- Example homelab.yaml

### Stubbed / Not Yet Implemented

- **Batfish backend** — stubbed, returns `ErrNotImplemented`. Planned for v2.
- **Remote runners** — SSH-based remote execution not yet wired. Engine supports `runner` field but only `local` works.
- **Service/port scanning** — nmap backend only does `-sn` ping sweep. Port and service scanning deferred to v1.1.
- **HTTP MCP transport** — only stdio is implemented. HTTP listener deferred to v1.1.
- **`explain` command** — mentioned in spec, deferred to v1.1.
- **Snapshot/history** — no persistence of past audit results yet.
- **NetBox integration** — deferred to v2.
- **Device API backends** (OPNsense, UniFi, Omada) — deferred to v2.

### Platform Support

| Platform | Status | Commands Used |
|----------|--------|---------------|
| Linux | Full support | `ip route`, `ip route get`, `ip addr show`, `ping -c -W`, `traceroute -n` |
| macOS | Full support | `netstat -rn`, `route -n get`, `ifconfig`, `ping -c -t`, `traceroute -n` |
| Windows | Full support | `route print`, `ping -n -w`, `tracert -d`, Go `net.Interfaces()` |

All three platforms cross-compile from any OS. Platform-specific code is in `system_linux.go`, `system_darwin.go`, and `system_windows.go` using Go build tags. The nmap backend, spec loader, audit engine, MCP server, and CLI are fully portable.

## License

MIT

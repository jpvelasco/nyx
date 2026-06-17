# nyx-audit-cli

**Your homelab should be doing what you think it's doing. nyx proves it.**

[npm](https://www.npmjs.com/package/nyx-audit-cli) · [GitHub](https://github.com/jpvelasco/nyx) · [Spec reference](https://github.com/jpvelasco/nyx/blob/main/docs/spec.html)

Cross-platform CLI that audits **live network behavior** against a declared YAML intent model — VLAN isolation, VPN routing, host counts, DNS, ports, ACLs, and drift over time. Every command emits structured JSON for automation and AI agents.

<p align="center">
  <a href="https://github.com/jpvelasco/nyx/actions/workflows/ci.yml"><img src="https://github.com/jpvelasco/nyx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jpvelasco/nyx/releases/latest"><img src="https://img.shields.io/github/v/release/jpvelasco/nyx" alt="Release"></a>
  <a href="https://www.npmjs.com/package/nyx-audit-cli"><img src="https://img.shields.io/npm/v/nyx-audit-cli" alt="npm"></a>
  <a href="https://www.npmjs.com/package/nyx-audit-cli"><img src="https://img.shields.io/npm/dm/nyx-audit-cli" alt="npm downloads"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
</p>

## Install

```bash
npm install -g nyx-audit-cli
```

Try without a global install:

```bash
npx nyx-audit-cli version
npx nyx-audit-cli doctor
```

Works on **macOS**, **Linux**, **Windows**, and **WSL** — `x64` and `arm64`. Postinstall downloads the matching prebuilt binary from GitHub Releases with embedded SHA-256 verification.

> **npm 9+ / Ubuntu 26+ note:** npm's `allow-scripts` security policy may block the postinstall
> script, so the binary won't be downloaded at install time. No worries — if `nyx` is invoked
> without a binary present it detects this and downloads automatically. You can also trigger it
> manually:
> ```bash
> node $(npm root -g)/nyx-audit-cli/install.js
> ```

## Quickstart

```bash
# 1. Install (above)

# 2. Check prerequisites (nmap, interfaces, spec hints)
nyx doctor

# 3. Generate a starter spec from your machine's RFC1918 networks
nyx init --output my-network.yaml

# 4. Run a full audit against declared intent
sudo nyx audit --spec my-network.yaml
```

After a clean audit, lock in a baseline from the saved snapshot (each audit writes to `~/.nyx/snapshots/`):

```bash
sudo nyx audit --spec my-network.yaml
nyx snapshot list
nyx snapshot baseline ~/.nyx/snapshots/snapshot-YYYYMMDD-HHMMSS.json
```

Compare later when something feels off:

```bash
sudo nyx audit --spec my-network.yaml && nyx drift status
```

## What it does

```
sudo nyx audit --spec homelab.yaml
```

One spec file. Eight assertion types. Concurrent live checks:

1. **Subnet discovery** — host counts per VLAN (`nmap -sn`)
2. **Isolation** — prove zones cannot reach each other
3. **VPN routing** — split-tunnel vs full-tunnel behavior
4. **Route checks** — gateway and path correctness
5. **Port checks** — TCP reachability
6. **DNS checks** — resolution and optional DNSSEC
7. **Network health** — latency, loss, MTU
8. **ACL checks** — Omada / OPNsense policy alignment

Results preserve spec order, include evidence, and map to exit codes (`0` pass, `1` fail, `2` error, `3` warn).

## Why nyx?

| Ad-hoc checks | nyx |
|---------------|-----|
| Ping one host, hope VLANs are fine | Declared intent across every network |
| "It worked yesterday" | Snapshot baseline + drift diff |
| Tribal knowledge in your head | Versioned YAML spec in git |
| Scattered shell one-liners | One audit, structured JSON output |
| Manual firewall spot-checks | `acl_check` against Omada / OPNsense |

Built for **homelab operators**, **platform engineers**, and **SREs** who run segmented networks and need proof — not vibes.

## Assertion types

| Type | Validates |
|------|-----------|
| `subnet_discovery` | Host count in a CIDR |
| `isolation` | Zone-to-zone deny/allow |
| `vpn_route` | Traffic uses the expected tunnel |
| `route_check` | Route to a target exists |
| `port_check` | TCP ports open/closed |
| `dns_check` | Resolution (+ optional DNSSEC) |
| `network_health` | Latency, loss, MTU |
| `acl_check` | Controller policy enforcement |

Remote probes: set `runner:` on assertions to execute checks over SSH from another VLAN.

## Vendor integrations

| Provider | Commands | What you get |
|----------|----------|--------------|
| **Omada SDN** | `nyx omada info \| import \| check` | Import networks/policies into a spec |
| **OPNsense** | `nyx opnsense info \| import \| check` | API-driven spec from live firewall |

## AI agent integration (MCP)

Built-in [Model Context Protocol](https://modelcontextprotocol.io/) server — audit, discover, route-check, and drift tools for Claude Code, Cursor, and other MCP clients.

**Claude Code:**

```bash
claude mcp add nyx -- npx -y nyx-audit-cli mcp serve --transport stdio
```

**Claude Desktop / Cursor:**

```json
{
  "mcpServers": {
    "nyx": {
      "command": "npx",
      "args": ["-y", "nyx-audit-cli", "mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

## Prerequisites

- **nmap** — required for discovery (`nyx doctor` prints the install command for your OS)
- **sudo** — needed for some subnet scans on Linux/macOS

## Commands

| Command | Purpose |
|---------|---------|
| `audit` | Run all assertions from a YAML spec |
| `init` | Auto-detect networks and generate a starter spec |
| `doctor` | Environment and spec validation |
| `discover` | nmap host discovery for a subnet |
| `check-vpn` | Split-tunnel vs full-tunnel check |
| `drift status` | Compare latest audit to baseline |
| `snapshot baseline` | Lock in a known-good audit |
| `mcp serve` | Start MCP stdio server |
| `omada` / `opnsense` | Vendor import and check |

Global flags: `--json`, `--spec`, `--verbose`, `--timeout`.

## Documentation

- **Spec reference:** [docs/spec.html](https://github.com/jpvelasco/nyx/blob/main/docs/spec.html)
- **Walkthrough:** [docs/walkthrough.md](https://github.com/jpvelasco/nyx/blob/main/docs/walkthrough.md)
- **Repository:** [github.com/jpvelasco/nyx](https://github.com/jpvelasco/nyx)

## License

MIT — see [LICENSE](https://github.com/jpvelasco/nyx/blob/main/LICENSE).

nyx is independent tooling — not affiliated with TP-Link/Omada, OPNsense, or the nmap project.
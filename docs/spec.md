# netaudit Product and Behavior Spec

> **Note:** This is the original Markdown specification document.  
> The current, modern reference is available at [docs/spec.html](../spec.html).

## Purpose

`netaudit` is a CLI-first network intent validation tool for private SDN-style networks, especially homelabs, labs, and developer-operated environments.

The tool helps answer whether a home or lab network is architected and implemented correctly by comparing declared intent against live network behavior. It is not a general vulnerability scanner. It is an assertion runner for network design questions such as:

- Are declared subnets discoverable?
- Are host counts within expected bounds?
- Are VLANs or zones isolated as intended?
- Are required routes present?
- Does VPN-bound traffic actually use a tunnel?
- Has controller-derived network state drifted from expectations?

The CLI is intended to be usable directly by a human and also by an AI agent through structured JSON output or an MCP server. The AI agent can load the tool, run checks, inspect findings, and guide follow-up investigation.

## Primary Users

- A homelab or small-network operator validating their own network design.
- A developer or infrastructure operator checking private lab environments.
- An AI agent assisting a user by running the CLI or MCP tools and interpreting results.

## Design Goals

- Be simple enough to run locally from a laptop or management host.
- Represent intended network behavior in a readable YAML file.
- Return deterministic, machine-readable results for automation and agent use.
- Provide human-readable output that is useful during manual troubleshooting.
- Prefer explicit assertions over broad scanning.
- Keep checks explainable: every result should include enough observed data, expected data, violations, or evidence to justify the status.
- Support imported SDN/controller state as a starting point, not as the only source of truth.

## Non-Goals

- Full vulnerability scanning.
- Passive traffic analysis.
- Continuous monitoring or long-term storage.
- Full firewall policy verification across all packet types.
- Replacing controller/firewall configuration management.
- Inferring complete network topology without user intent.

## Core Workflow

1. The user creates or imports a YAML intent spec.
2. The user runs `netaudit audit --spec <file>`.
3. `netaudit` executes each assertion against the local environment.
4. The tool emits a report with status, findings, observed values, expected values, violations, and evidence.
5. A human or AI agent reviews the results and decides what to investigate or remediate.

## Intent Spec

The YAML spec is the canonical input model.

```yaml
version: 1
site: home-lab

networks:
  - name: clients
    cidr: 10.0.20.0/24
    gateway: 10.0.20.1
    zone: clients
    vlan: 20

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

assertions:
  - type: subnet_discovery
    network: clients
    expect_hosts_min: 1
    expect_hosts_max: 50
```

### Top-Level Fields

- `version`: Spec format version. Current supported version is `1`.
- `site`: Human-readable site name.
- `networks`: Declared network segments.
- `vpn`: Declared VPN configurations.
- `policies`: Intended access policies. Current code validates these structurally but does not yet fully evaluate them.
- `assertions`: Concrete checks to run.

### Network Fields

- `name`: Unique network identifier.
- `cidr`: CIDR block.
- `gateway`: Optional gateway IP.
- `zone`: Logical zone name, such as `management`, `clients`, `iot`, `guest`, or `servers`.
- `vlan`: Optional VLAN ID.

### VPN Fields

- `name`: Unique VPN identifier.
- `type`: VPN type, currently treated generically with WireGuard defaults.
- `interface`: Expected tunnel interface, such as `wg0`.
- `expected_routes`: Routes expected to use the VPN.
- `mode`: Expected mode, such as `split-tunnel` or `full-tunnel`.

### Policy Fields

- `name`: Unique policy identifier.
- `from`: Source zone or network.
- `to`: Destination zone or network.
- `action`: `allow` or `deny`.
- `except`: Optional exceptions by protocol, port, and target.

Policies express design intent. Assertions are the executable checks. A future version should derive suggested assertions from policies or evaluate policies more directly.

## Assertion Types

### `subnet_discovery`

Checks active hosts in a declared network using `nmap -sn`.

Required fields:

- `network`

Optional fields:

- `expect_hosts_min`
- `expect_hosts_max`
- `scan_timing`
- `scan_min_rate`

Expected behavior:

- Resolve `network` to a declared CIDR.
- Run an nmap ping sweep.
- Record discovered hosts and total count.
- Fail if the host count is outside specified bounds.
- Warn, rather than pass silently, when no hosts are discovered and no explicit minimum allows that result.

### `route_check`

Checks whether the local host has a route to a target.

Required fields:

- `target`

Expected behavior:

- Query the OS route table for `target`.
- Pass if a route is found.
- Error if route lookup fails.
- Record gateway and device when available.

### `vpn_route`

Checks whether traffic to a target uses a VPN/tunnel interface.

Required fields:

- `vpn`
- `target`

Optional fields:

- `expect_tunnel`

Expected behavior:

- Resolve `vpn` to a declared VPN config.
- Query the OS route to `target`.
- Compare the route device with the configured VPN interface.
- Also allow platform-specific tunnel-interface detection.
- Fail when `expect_tunnel: true` and the route does not use a tunnel.

### `isolation`

Checks whether one zone or network can reach another.

Required fields:

- `from`
- `to`
- `expect`

Supported expectations:

- `deny`: destination should not be reachable.
- Any non-`deny` value currently behaves as an allow/connectivity expectation.

Expected behavior:

- Resolve `to` as a zone first, then as a network name.
- Probe target gateways for reachability.
- Pass when `expect: deny` and tested targets are unreachable.
- Fail when `expect: deny` and any tested target is reachable.
- Warn when the result is unverifiable from the current host.

Important limitation:

Current checks run from the local machine. If the local machine is not actually inside the `from` zone, isolation results may not represent true zone-to-zone behavior. The report should make this limitation clear.

## Result Model

Every check returns a normalized result.

Fields:

- `tool`: Backend or subsystem, such as `nmap`, `system`, or `audit`.
- `check_type`: Assertion/check type.
- `runner`: Execution context, currently usually `local`.
- `target`: Target network, IP, zone pair, or route destination.
- `status`: `pass`, `fail`, `warn`, `error`, or `skip`.
- `summary`: Human-readable one-line result.
- `observed`: Structured observed data.
- `expected`: Structured expected data.
- `violations`: Specific mismatches.
- `evidence`: Supporting command output or probe evidence.
- `started_at`, `finished_at`, `duration_ms`: Timing metadata.

## Status Semantics

- `pass`: The assertion was evaluated and matched intent.
- `fail`: The assertion was evaluated and contradicted intent.
- `warn`: The assertion produced an inconclusive or degraded result that needs attention.
- `error`: The assertion could not run correctly due to invalid input, missing dependencies, command failure, timeout, or platform error.
- `skip`: The assertion was intentionally not run.

Overall audit status should use this precedence:

1. `error`
2. `fail`
3. `warn`
4. `pass`

## Output Modes

### Human Output

Human output should be concise and diagnostic:

- Audit name and overall status.
- One line per finding.
- Violations under the relevant finding.
- Evidence under the relevant finding.
- Summary totals.
- Optional recommendations when findings are actionable.

When `--output <path>` is used, all normal report output should go to that path. Warnings about report generation may go to stderr.

### JSON Output

JSON output is the stable automation interface for CLI-driven agents.

Rules:

- `--json` should emit only valid JSON to the configured output writer.
- Human recommendations must not be appended to JSON unless they are added as structured fields in the JSON schema.
- Diagnostics that are not part of the result should go to stderr.

## MCP Role

The MCP server exposes read-only network audit operations to AI agents.

The MCP layer should:

- Provide the same core operations as the CLI.
- Return structured results consistent with the CLI JSON model.
- Avoid hidden state when possible.
- Let an agent load specs, run targeted checks, run full audits, and inspect interfaces/routes.

The MCP server is not a separate product surface. It is an agent-friendly control plane for the same audit engine.

## Controller Import Role

The Omada import path exists to bootstrap an intent spec from controller state.

Expected behavior:

- Connect to an Omada controller.
- Discover sites, networks, gateways, VLANs, and available metadata.
- Generate a valid YAML spec.
- Preserve enough comments or metadata to show where the file came from.

Imported specs are starting points. The user is expected to edit zones, policies, and assertions to express actual design intent.

## Recommendations

Recommendations are optional guidance generated from failed or errored findings.

They should:

- Be derived from structured findings, not only summary text.
- Be included for both `fail` and `error` statuses where useful.
- Respect the output writer.
- Avoid corrupting JSON output.
- Include affected targets when known.
- Prefer concrete next steps over generic advice.

Recommendation output should eventually be represented in the report schema rather than printed as an unrelated post-processing block.

## Validation Requirements

Spec validation should catch structural errors before any network checks run.

Minimum validation:

- `version` must be supported.
- `site` must be set.
- network names must be unique.
- network CIDRs must be valid.
- gateways must be valid IPs when present.
- policy actions must be `allow` or `deny`.
- assertion types must be known.
- each assertion type must include its required fields.
- assertion references must point to declared networks or VPNs when applicable.
- host-count minimum must not exceed maximum.
- nmap timing should be in the valid range.
- min-rate should be non-negative.

## Platform Expectations

The code has platform-specific system backends for Linux, macOS, and Windows.

Expected support:

- Linux: primary operational target.
- macOS: supported for local route/interface/ping checks.
- Windows: supported for local route/interface/ping checks.
- nmap must be installed for discovery.

Platform differences should appear in evidence and backend implementation, not in result schema.

## Known Current Gaps

These are current implementation gaps observed from the code and should guide cleanup:

- There is no canonical spec document beyond this file and README examples.
- Recommendation output currently bypasses `--output`.
- Recommendation generation is skipped for overall `error` audits.
- Subnet discovery expected host bounds are not copied into result metadata.
- Audit discovery can overwrite backend warnings as passes.
- Assertion validation does not enforce required fields.
- Policies are validated but not deeply evaluated.
- Isolation checks are local-host probes and do not yet run from the declared source zone.
- Tests cover spec parsing and result basics, but not audit behavior, recommendations, CLI output routing, or MCP contracts.

## Compatibility Contract

For future development, preserve these contracts unless a versioned change is introduced:

- YAML `version: 1` remains readable.
- CLI JSON remains parseable and stable.
- Every check returns the normalized result model.
- Audit findings are returned in assertion order.
- Exit codes map to overall status:
  - `0`: pass
  - `1`: fail
  - `2`: error
  - `3`: warn
- Human output may evolve, but should remain concise and diagnostic.


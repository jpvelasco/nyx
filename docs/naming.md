# Domain Naming — Canonical Generic Vocabulary

This document defines the shared language for everything nyx touches — specs,
docs, examples, test fixtures, issue/PR text, logs, and agent conversation.

It exists so that anyone or any agent working on this repo can describe a real
network **without ever writing a private name, subnet, MAC, or controller
identifier** into a repo artifact. The goal is a leak-free boundary: the repo
contains *roles*; reality contains *values*; the mapping happens only at
runtime and is never recorded here.

## Rules

1. **Names are roles, not identities.** Use the canonical names below (or
   plain roles like `lan`, `vantage`) for networks, zones, VLANs, devices, and
   services. A name must be usable in any other homelab with no edits.
2. **Live output is private by default.** Anything returned by live tooling —
   SDN controller APIs, DHCP lease lists, `ipconfig`, `ping`, DNS, nmap — may
   contain real hostnames, subnets, MACs, and device model names. Map it to the
   nearest role and use **only** the generic name in specs, docs, fixtures,
   issues, PRs, commits, logs, and evidence.
3. **Never record the mapping.** A doc, comment, or issue that says
   "`X` is the `Y` VLAN" *is* the leak. The mapping stays in the operator's
   head, their out-of-band tooling, or the live controller — never in git.
4. **No real values, ever.** Do not paste controller IDs, firmware versions
   tied to a real appliance, public IP assignments, or serials into this repo.
   Generic values from the tables below are the only acceptable literals.
5. **Copy fixture values from the canonical sources** — `examples/homelab.yaml`
   and `testdata/` — never invent new private-looking addresses.
6. **Scratch and machine-specific specs stay out of git.** `specs/` and
   `scratch*/` are gitignored for exactly this reason.

## Canonical network roles

The reference topology is the 7-VLAN homelab in `examples/homelab.yaml` and
`docs/walkthrough.md`. Names, CIDRs, and VLAN IDs are fixed and must stay in
sync across `examples/`, `testdata/`, `docs/`, and any new fixtures.

| name | vlan | cidr | role |
|------|-----:|------------|------|
| `trusted` | 10 | `10.0.10.0/24` | desktops, laptops, main workstations |
| `management` | 11 | `10.0.11.0/24` | controllers, switches, monitoring |
| `personal` | 20 | `10.0.20.0/24` | phones, tablets, personal laptops |
| `gaming` | 30 | `10.0.30.0/24` | consoles, handhelds, game PCs |
| `servers` | 40 | `10.0.40.0/24` | NAS, file shares, printers |
| `media` | 50 | `10.0.50.0/24` | streaming, AV, media players |
| `iot` | 60 | `10.0.60.0/24` | smart bulbs, cameras, sensors |

Smaller specs may use a reduced set of roles (e.g. `mgmt` + `clients` as in
`testdata/valid_spec.yaml`); the rule is the same — role name only, generic
values only.

## Canonical test addresses

| address | use |
|---------|-----|
| `10.0.x.0/24` blocks | role networks (see table above) |
| `10.0.0.0/8` | VPN route expectation (e.g. `home-wg`) |
| `10.255.255.0/30` | dead range for nmap integration tests |
| virtual-adapter `/24`s | derived at runtime, never hard-coded |
| `nas.home.example` | example DNS name for `dns_check` fixtures |

**Private RFC1918 space is off-limits in this repo.** `192.168.x.0/24` and
similar real LAN allocations must never appear in committed files; anything
seen in live output gets rewritten to a `10.0.x` role value before it is
recorded.

## Devices and services

Use role-based labels:

- **Gateway / router:** `gateway`, or by network (`trusted-gateway`).
- **SDN controller:** `controller`, `sdn-controller` — no vendor model names
  tied to a real appliance.
- **Switch:** `switch`, `access-switch`.
- **Access point:** `ap`.
- **Management host (the box running nyx):** `mgmt-host`, `vantage`.
- **Probe hosts:** `<role>-probe` (e.g. `iot-probe`).
- **Example endpoints:** `nas.home.example`, `10.0.11.20` (controller),
  `10.0.50.5` (media services), `10.0.60.15` (probe).

## Applying the rules in practice

- **Specs:** `name:` / `zone:` fields use role names only; generated specs
  (see `nyx init`) may arrive with local interface-derived names — rename to
  roles before anything leaves the machine.
- **Issues & PRs:** describe observations by role. If an audit result names a
  real subnet, quote the *assertion*, not the address, or restate it with the
  role value.
- **Evidence & logs:** nyx never writes credentials to logs; the same
  discipline extends to hostnames and subnets in commit messages, PR bodies,
  and issue text.
- **Log exports:** `nyx logs export` produces a PII-scrubbed artifact by
  default. The scrubber keeps a **finite allowlist** — documentation blocks
  (RFC 5737 TEST-NET, loopback, `0.0.0.0`), the exact literals committed in
  `examples/`/`testdata/` (enforced by `TestAllowlistMatchesFixtures`), and
  `*.example` names — and replaces everything else with naming placeholders
  (`[ip]`, `[cidr]`, `[mac]`, `[host]`, `[redacted]`). When asking for logs,
  expect placeholders, not addresses: a log line saying "target `[ip]`
  unreachable" carries the diagnostic (event, subsystem, timing, error
  category) without the subnet identity. Diagnostic fields survive by
  design; if a line is missing context you need, ask for the raw, unshared
  detail by a channel the sender controls (e.g. an on-screen readout), never
  a `--no-scrub` artifact.
- **Examples:** when writing a new example or fixture, start from
  `examples/homelab.yaml`; if a new role is genuinely needed, add it to the
  table above in the same change so the vocabulary stays canonical.

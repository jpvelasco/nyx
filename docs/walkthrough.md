# Walkthrough — From Zero to Sleeping at Night

This is what nyx actually does, step by step, with a real topology.

## Step 1 — You Have a Network

Seven VLANs behind an SDN controller and a router:

```
VLAN 10  (10.0.10.0/24)  — trusted: desktops, laptops, main workstations
VLAN 11  (10.0.11.0/24)  — management: controllers, switches, monitoring
VLAN 20  (10.0.20.0/24)  — personal: phones, tablets, laptops
VLAN 30  (10.0.30.0/24)  — gaming: consoles, handhelds, game PCs
VLAN 40  (10.0.40.0/24)  — servers: NAS, file shares, printers
VLAN 50  (10.0.50.0/24)  — media: Jellyfin, Plex, streaming devices
VLAN 60  (10.0.60.0/24)  — IoT: smart bulbs, cameras, sensors
```

You set up ACLs to isolate IoT from everything else. You wired up WireGuard for remote access. You told yourself "it should be working."

But should it be?

## Step 2 — Declare What You Intend

Write a YAML spec that describes your network. Not the whole thing — just the parts that matter. See `docs/spec.html` for the complete reference, and `examples/homelab.yaml` for a realistic working example. Here's the idea:

```yaml
version: 1
site: home-lab

networks:
  - name: main
    cidr: 10.0.10.0/24
    gateway: 10.0.10.1
    zone: trusted
    vlan: 1
  # ... six more VLANs ...

policies:
  # IoT gets internet only — no internal access
  - name: iot-to-trusted-deny
    from: iot
    to: trusted
    action: deny
  # ... more policies ...

assertions:
  # Make sure VLANs actually have devices on them
  - type: subnet_discovery
    network: main
    expect_hosts_min: 10
    expect_hosts_max: 30

  # IoT should NOT reach management
  - type: isolation
    from: iot
    to: management
    expect: deny

  # Traffic to internal hosts should go through WireGuard
  - type: vpn_route
    vpn: home-wg
    target: 10.0.20.50
    expect_tunnel: true

  # Verify controller says IoT ACL is enforced
  - type: acl_check
    provider: omada
    policy: iot-to-management-deny
    expect: enforced
```

The key insight: **policies are your intent. Assertions are what you actually check.**

## Step 3 — Run the Audit

```bash
sudo nyx audit --spec examples/homelab.yaml
```

nyx runs every assertion against your live network. It talks to nmap for host discovery, checks your routing table for VPN paths, pings gateways for isolation tests, and queries your Omada controller for ACL enforcement.

The output looks like:

```
Site: home-lab
Status: PASS
Running from: 10.0.10.42 (inside: trusted)

--- 14 assertions, evaluated from this vantage point ---

[PASS] subnet_discovery: 18 hosts found on main (expected 10-30)
[PASS] isolation: iot -> management is denied as expected
[PASS] vpn_route: traffic to 10.0.20.50 uses wg0 as expected
[PASS] route_check: route to 10.0.10.1 exists via 10.0.10.1
[PASS] acl_check: policy iot-to-management-deny is enforced
[PASS] network_health: 10.0.10.1 latency 2ms, 0% loss
[PASS] dns_check: nas.home.example resolves to 10.0.50.5 as expected
[PASS] port_check: 10.0.50.5 ports 8096,8920 are open
[PASS] isolation: trusted -> iot is denied as expected
[PASS] isolation: trusted -> management is denied as expected
[PASS] isolation: iot -> management is denied (from iot-laptop probe)
[PASS] subnet_discovery: 5 hosts found on mobile (expected 1-10)
[PASS] subnet_discovery: 3 hosts found on servers (expected 1-10)
[PASS] subnet_discovery: 4 hosts found on media (expected 1-10)

Summary: 14 passed, 0 failed, 0 warnings, 0 errors, 0 skipped
```

First time, everything passes. Your network is doing what you think it's doing.

## Step 4 — Lock It In

```bash
nyx snapshot baseline
```

Baseline captured. Future drift checks will now show exactly what has changed.

This is the moment you can breathe. You just saved a point-in-time record of "network is good."

## Step 5 — Two Weeks Later

You changed something. Maybe you added a new device, maybe a firmware update hit your router, maybe a child messed with the Wi-Fi settings. You don't remember, and you don't care. What matters is: **is it still working?**

```bash
sudo nyx audit --spec examples/homelab.yaml && nyx drift status
```

```
=== Drift Report ===
Baseline: 2025-06-01 14:00:00 (status: pass)
Current:  2025-06-15 09:30:00 (status: fail)
Change:   1 more failures

Summary:
  Baseline: 14 passed, 0 failed, 0 warnings, 0 errors
  Current:  12 passed, 2 failed, 0 warnings, 0 errors
  Net:      2 more failures

New failures (2) — attention needed:
  [FAIL] isolation: iot -> management is reachable (was denied)
  [FAIL] network_health: 10.0.10.1 latency 45ms, 3% loss (expected <10ms, 0%)

Next: investigate the checks that changed. Re-audit from other VLANs with --interface if the vantage point matters.
```

There it is. IoT is no longer isolated from management, and your gateway is slow. Something is wrong.

## Step 6 — Root Cause

Run again with `--json` to get structured output, or just add `--verbose` for more evidence. The `isolation` failure shows the ping evidence — the IoT gateway is responding when it shouldn't be. The `network_health` failure shows the actual ping stats.

You check your router, find that a firmware update disabled the IoT ACL. You re-enable it, re-run the audit, and drift status shows:

```
Fixed (1) — good news:
  [PASS] isolation: iot -> management is denied as expected
```

## Step 7 — You Sleep at Night

You've now got a repeatable, automated way to verify that your network is doing what you intended. Run it manually, or drop it in a cron job, or have an AI agent run it and alert you when things drift.

The spec is your contract with reality. nyx enforces it.

## Tips

- **Vantage point matters.** Isolation checks run from your local machine. If you're on the trusted LAN, checking `from: iot` tests whether IoT can reach you — not whether IoT can reach management. Use `runner:` with a probe to run checks from inside the source VLAN.

- **Start small.** You don't need 14 assertions on day one. Three is enough: one `subnet_discovery`, one `isolation`, one `route_check`. Add more as you get comfortable.

- **Save your spec.** Put it in `specs/` (which is `.gitignore`d), and version-control it separately. Your network intent is a living document — treat it like one.

- **Drift is your friend.** A "no drift" report is the best feeling. It means everything is still holding.

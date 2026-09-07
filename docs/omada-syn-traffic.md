# Omada gateway client-discovery SYN traffic

Research note for issue #17. No live hostnames, firmware strings, or
MACs. Role names follow `docs/naming.md`.

## What generates SYNs

Two independent sources show up in a mixed Omada + nyx lab:

1. **nyx itself.** `subnet_discovery` runs `nmap -sn` (polite by
   default: T2, 50–100 pps). Isolation and `network_health` send ICMP
   echo. Those are operator-initiated and bounded by the spec.
2. **The Omada gateway.** Adopted gateways periodically ARP/ICMP/SYN
   probe clients so the controller can populate the client list and
   "online" state. That traffic is the controller's own discovery, not
   a nyx scan. It continues when nyx is idle.

A SYN from the gateway toward a client on `iot` / `trusted` is
therefore not evidence that nyx is scanning that host.

## What nyx already does

- `scan_mode: polite` is the import default (AGENTS.md). Do not switch
  generated specs to normal/aggressive; those trip SDN SYN-flood
  alarms.
- `seendb` suppresses repeat WARN on virtual adapters (VMware, Hyper-V,
  WSL2) that always return 0 hosts.
- Isolation from outside the source zone is unverifiable, not a hard
  fail — so nyx does not retry louder.

## What nyx must not do

There is no Open API to disable the gateway's own client-discovery
probes. Do not invent a write that claims to turn them off. Do not
rate-limit or drop the gateway's probes from nyx; that would hide
real clients from the controller.

## Operator knobs (controller UI)

If the SYN volume is a problem, the only supported place to change it
is the controller's own client-discovery / device-scan settings (wording
varies by controller major). nyx cannot see or set those.

If a live investigation needs less noise, narrow the spec: drop unused
`subnet_discovery` rows, keep polite, and run isolation via a probe
inside the source zone instead of a wide nmap sweep.

## Conclusion

#17 stays research. Reducing the *gateway's* SYNs is a controller
product setting, not a nyx API. Reducing *nyx's* SYNs is already the
polite-scan default plus seendb. No code change in this issue.

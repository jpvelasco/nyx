# Recommendations Engine Spike - Test Report

**Date:** 2026-05-28  
**Tester:** Grok (autonomous run on JP's machine)  
**Purpose:** Evaluate first lightweight implementation of the Phase 1 Recommendations engine

## Summary

The spike successfully replaced the stub with real, rule-based recommendation logic focused on the highest-value homelab pain points (isolation confidence + VPN/routing issues).

## Test Runs Performed

1. `examples/homelab.yaml` (realistic example spec)
2. `test-recommendations.yaml` (synthetic spec designed to trigger failures)

## Key Observations

### Positive Results

- **Isolation vantage-point detection worked well**
  - On the synthetic spec, it correctly identified the "isolation unconfirmed" WARN and produced:
    > "Isolation result has limited confidence"
    > Remediation: "Run this check using a probe located inside the source zone..."

  This directly addresses one of the top homelab complaints identified in research.

- **VPN routing recommendation fired correctly**
  - Produced actionable guidance when traffic was not going through the expected tunnel.

- **Overall status gating still works** — Recommendations only appear in human mode when appropriate (not on pure ERROR, not in JSON).

- No crashes, no leaked output into JSON.

### Gaps & Improvement Opportunities (for next iteration)

1. **Discovery recommendations are too narrow**
   - A `subnet_discovery` that found 0 hosts did not trigger a recommendation because there was no explicit `expect_hosts_max` violation string.
   - We should also trigger on low host counts when the user has declared any expectation, or when 0 hosts are found in a network that should have devices.

2. **RunnerContext is not yet available**
   - The current function signature only receives a flat networks map. We have rich `RunnerContext` on the `AuditReport`, but it's not passed to `GenerateRecommendations`.
   - This limits how smart vantage-point recommendations can become.

3. **Remediation text quality is good but can be more specific**
   - Some messages are still a bit generic. We can make them reference specific gateways, zones, or observed devices from the CheckResult.

4. **No SpecPatch generation yet**
   - The field exists but is never populated in this spike.

5. **Limited check type coverage**
   - Currently handles isolation, subnet_discovery, vpn_route, route_check.
   - port_check, dns_check, network_health, acl_check still fall through.

6. **No deduplication or clustering**
   - Multiple similar isolation warnings can produce repetitive recommendations.

## Metrics Collected

- Recommendations successfully generated on real failure data: **Yes**
- Relevant categories produced: isolation, vpn, routing
- Quality of remediation (subjective 1-5): **4** (actionable in most cases, room to improve specificity)
- False positive rate on this run: Low
- Time to first useful recommendation: Immediate (no noticeable delay)

## Recommended Focus for Next Iteration

1. Pass `RunnerContext` + richer context into `GenerateRecommendations`.
2. Broaden discovery recommendations (especially 0-host and low-host cases).
3. Start generating simple `SpecPatch` suggestions for common cases.
4. Add basic support for port_check and network_health failures.
5. Improve remediation specificity using data from `Observed`/`Evidence`.

## Files Generated During Testing

- `test-recommendations-run.txt` — Full human output from synthetic test
- `test-recommendations-json.txt` — JSON output
- `test-audit-homelab-output.txt` — Run against examples/homelab.yaml
- `test-recommendations.yaml` — Synthetic test spec (can be deleted)

## Conclusion

The spike has moved the recommendations feature from "completely non-functional" to "actually produces useful guidance on the problems homelab users care most about."

It is now ready for real-world evaluation and iterative improvement.

---
Good night. Ready for next iteration when you are.
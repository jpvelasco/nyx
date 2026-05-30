# Sprint 1: First Contact & "I Got You" (Kickoff)

**Dates:** Starting ~May 29, 2026 (2-week target)

**Theme:** Make the first time someone interacts with nyx feel helpful and like the tool understands their environment.

## Sprint Goals
- Significantly improve the "I just landed" experience in `nyx doctor`.
- Make `nyx audit` without a spec useful instead of just erroring.
- Ensure recommendations are visible even when some assertions error (major pain point from real testing).
- Continue polishing multi-homed experience (smart defaults + clear guidance).

## Key Changes Already Landed in Kickoff
- Changed recommendation rendering logic: We now surface recommendations for actionable FAIL/WARN findings even if the overall audit status is ERROR.
- Created reusable `EnvironmentBriefing` + `RenderEnvironmentBriefing` in `internal/cli/environment.go`.
- Wired nice environment summary into `doctor`, `audit` (no spec), and `init`.
- Improved error explanations for common timeout cases.
- Made Environment Briefing language more conversational and reassuring ("I see you're...", "I couldn't confidently place you...").
- Started making `nyx init` acknowledge the environment briefing at the very start.
- Cleaned up more old cruft in examples/homelab.yaml (old VPN references, outdated targets).

## Validation Runs Captured in This Session
- `sprints/sprint-1-doctor-v1.txt`
- `sprints/sprint-1-audit-default-v1.txt`
- `sprints/sprint-1-audit-wifi-v1.txt`

## Validation Gate (End of Sprint)
Run the following from Valhalla + Nighthawk (and at least one other VLAN):

1. `nyx doctor --spec examples/homelab.yaml`
2. `nyx audit --spec examples/homelab.yaml` (default)
3. `nyx audit --spec examples/homelab.yaml --interface "Wi-Fi"`
4. `nyx audit --spec examples/homelab.yaml --interface "Ethernet"`
5. `nyx init` (quick run, don't have to complete)

**Success Criteria (qualitative + quantitative):**
- The Environment Briefing in doctor feels genuinely helpful on first read.
- At least one meaningful recommendation appears even when the overall run has errors.
- RunnerContext is clean and trustworthy when using `--interface`.
- Multi-homed warning is present but not annoying when using the smart default.

## Open Questions for the Sprint
- How narrative should the doctor output be?
- Should we add a "Suggested next step" at the end of the briefing?
- How far do we push `nyx init` environment awareness in this sprint?

---
**Status:** Sprint kicked off. Let's ship.
# nyx Final Product Delivery Plan

**Goal (Valhalla):**  
A tool that, the first time a homelabber runs it in their environment, feels like it "gets" them. It immediately shows it understands their network layout, gives useful confidence-building feedback (especially around isolation/segmentation), and makes the user think "this thing actually helps me sleep better at night."

---

## Current State (as of late May 2026)

**Strengths**
- Solid recommendations engine foundation with RunnerContext awareness.
- Working `--interface` + `nyx interfaces` command (big win for multi-homed users).
- First Contact / Environment Briefing starting to take shape (in doctor, audit no-spec, init).
- Real topology baseline now exists (`examples/homelab.yaml` + `testdata/user-topology.yaml`).

**Big Gaps to Golden Goal**
- Recommendations are still too generic in many real runs.
- First Contact is promising but not yet delightful or narrative enough.
- `nyx init` is functional but not yet "magical" at producing a good starting spec from what it sees.
- No strong import path beyond basic Omada (OPNsense is still weak).
- Multi-homed experience is much better but not yet "just works" for noobs.
- Many real audits hit ERROR status, which currently hides recommendations.

---

## Phased Delivery Plan

### Phase 0 – Current (Done / In Progress)
- Core engine + context passing
- Interface selection + smart warnings
- Basic Environment Briefing
- Real topology in examples/homelab.yaml

### Phase 1 – "It Gets Me" (First Contact + Confidence) – Target: Next 4-6 weeks
**Goal:** When someone runs nyx for the first time (or after moving to a new machine/VLAN setup), it feels helpful immediately.

Key deliverables:
- Excellent `nyx doctor` as the primary "I just landed" command with narrative summary + clear next steps.
- `nyx audit` (no spec) gives useful environment briefing + suggestions.
- `nyx init` becomes environment-aware and produces a much better starter spec (uses detected interfaces + networks).
- Recommendations engine produces noticeably better, more specific output on real topologies (especially isolation + discovery).
- Multi-homed experience is smooth for noobs (smart default) while giving experts full control.

Success metric: A user on a segmented homelab runs `nyx doctor` or `nyx init` and says "okay, this actually understands my setup."

### Phase 2 – "It Helps Me Fix Things" (Recommendations Maturity)
**Goal:** Recommendations stop feeling like nice-to-have and start feeling like the main reason to use the tool.

Key deliverables:
- High-quality, specific remediation text + useful `SpecPatch` generation for common failure modes.
- Recommendations work even on mixed ERROR/WARN runs (big current gap).
- Tie recommendations more tightly to `nyx init` output.

### Phase 3 – "It Grows With Me" (Import + Polish)
**Goal:** Power users and people with real vendor gear get massive value.

Key deliverables:
- Strong OPNsense import path (symmetric to Omada).
- Better long-term experience (history, drift detection between runs, better probe management).
- Polish: error messages, performance on large networks, documentation.

### Phase 4 – "It Becomes Indispensable" (Ecosystem)
- Community patterns / example topologies.
- Deeper integration with common homelab tools.
- Possibly MCP improvements for agentic use.

---

## Immediate Next Priorities (Next 1-2 Weeks)

1. **Polish First Contact experience** (highest leverage right now)
   - Make doctor the hero command with warm, useful narrative.
   - Improve `nyx audit` no-spec path.
   - Make `nyx init` actually propose networks based on what it detects.

2. **Make recommendations actually good on real data**
   - Fix the "ERROR status hides recommendations" problem.
   - Improve quality of output on the real homelab.yaml.

3. **Clean up the current spec**
   - Fix remaining old references (home-wg VPN, unreachable probes).
   - Add more realistic assertions based on user's actual policies.

4. **Multi-homed polish**
   - Make the smart default even better.
   - Improve how RunnerContext is presented when multi-homed.

---

## Success Criteria for "Final Product"

A user who cares about network segmentation should be able to:
- Run `nyx doctor` or `nyx init` on a new machine and feel like the tool immediately understood their environment.
- Get clear, actionable recommendations that help them improve isolation or discover unexpected exposure.
- Use `--interface` naturally when they have complex setups.
- Feel the tool is "on their side" rather than just another scanner that produces noise.

---

**Status:** This document is superseded by VALHALLA-ROADMAP.md (created May 29 2026), which contains the full Epic-of-Epics + Sprint structure with explicit validation gates on the real homelab.

Sprint 1 ("I Just Landed") has been kicked off. See sprints/sprint-1.md for current sprint tracking.

Next step after this plan: Decide the very next 1-2 concrete tickets to tackle (probably First Contact polish + spec cleanup).

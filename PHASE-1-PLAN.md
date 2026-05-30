# Phase 1 Plan — nyx Recommendations & Confidence

**Status:** Updated after initial recommendations spike testing (2026-05-28)  
**North Star:** Make nyx the lightweight tool that gives homelab users genuine, repeatable confidence in their network segmentation and declared intent — especially around isolation.

## Phase 1 Goal (Unchanged)

By the end of Phase 1, a typical user should be able to generate or import a useful model of their network, run validation (including from different vantage points), and receive clear, actionable guidance when reality doesn’t match intent.

The emotional outcome remains: Users go from “I *think* my isolation is working” to “I have evidence and clear next steps.”

## Key Learnings from Spike Testing

Real audits (on both `examples/homelab.yaml` and controlled failure scenarios) showed:

- The recommendations engine direction is **correct and high-value**.
- Vantage-point / isolation confidence recommendations are already useful even in a lightweight implementation.
- Biggest current limitation: The engine does not receive `RunnerContext` or the full spec, which caps how smart and specific the guidance can be.
- Discovery rules need to be broadened (e.g., 0-host or low-host cases should trigger recommendations).
- We have a clear, validated next step: Prioritize richer context passing before expanding too many new rule categories.

These learnings refine sequencing but do **not** change the overall Phase 1 scope or north star.

## Updated Phase 1 Priorities (Refined Sequencing)

### Tier 1 (Highest Leverage — Do These First)
1. **Pass richer context into recommendations** (`RunnerContext` + full `*intent.Spec`)
   - This is now the #1 priority item based on testing data.
   - Enables dramatically better vantage-point analysis, zone-aware recommendations, and more specific remediation.
2. Broaden and improve discovery recommendations (especially low/zero host counts).
3. Improve remediation specificity and start generating simple `SpecPatch` suggestions where obvious.

### Tier 2 (Core Phase 1 Deliverables)
- Strong `nyx init` improvements focused on common homelab segmentation patterns.
- One high-quality import path (recommended: OPNsense first).
- Probe/vantage-point intelligence and UX improvements.
- General UX polish (error messages, doctor, human reports).

### Explicitly Out of Scope (Phase 1)
- History / drift detection
- Visualization or reachability graphs
- NetBox / Batfish / external integrations
- Scheduled runs or notifications
- Broad multi-vendor support beyond one deep import path

## Success Criteria (Unchanged from earlier scope)

- A user can go from `nyx init` (or basic import) → useful validated spec with meaningful recommendations in one session.
- Common failure modes (especially isolation and discovery) produce clear, actionable remediation.
- Recommendations feel like a standout feature rather than an afterthought.
- Early users describe the tool as reducing real anxiety about segmentation.

## Next Steps After This Document

1. Update `GenerateRecommendations` signature and call site to accept `RunnerContext` + `*intent.Spec`.
2. Refactor recommendations logic to use the new context.
3. Expand discovery rules and add initial `SpecPatch` generation.
4. Continue with `nyx init` and import work.

This plan keeps Phase 1 focused while incorporating real usage data from the first recommendations spike.

---
*Document created and refined during active development. Use as the living reference for Phase 1 scope.*
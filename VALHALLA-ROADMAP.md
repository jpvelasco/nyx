# VALHALLA Roadmap — nyx Path to the Golden Goal

**Golden Goal (Valhalla):**  
The first time a homelabber (especially one who cares about segmentation and sleeps better when they have confidence in their isolation) runs nyx in their environment, the tool feels like it *gets* them. It immediately shows it understands their network, gives clear, actionable confidence-building feedback, and makes them think:  
*"This thing actually helps me understand and improve my network. Where has this been?"*

---

## Living Checklist (Current as of late May 2026)

### Done (High Confidence)
- OPNsense provider now supports info, import, check (ImportSpec + Check implemented)
- History/snapshot system: `nyx snapshot` (baseline, list, delete, clear-baseline)
- Drift detection: `nyx drift status` and `nyx drift compare` with full comparison logic
- Recommendations now included in JSON output (AuditReport.Recommendations)
- Multi-homed detection + `--interface` flag + `nyx interfaces` command (excellent across real dual-homed testing)
- First Contact experience (bare `nyx`, `doctor`, `init`, `audit` no-spec) with Environment Briefing
- Shared `GetEnvironmentBriefing` / `RenderEnvironmentBriefing` across commands
- Real production topology baseline (`examples/homelab.yaml`)
- High-quality error explanations (`explainAssertionError` + causes + suggestions)
- Recommendations engine — complete two-pass classify + generate architecture
- Vantage point awareness using `RunnerContext` + spec zones
- Aggregation of related failures (isolation + discovery timeouts) into single high-signal recs
- `StatusError` results (timeouts, unreachable) now flow into recommendations
- Prescriptive SpecPatch — diff-style patches with real values from spec, all 10 categories covered
- Recommendations visible even on overall ERROR runs
- Zone deduplication in vantage_point descriptions (network names resolved to zone names)
- Affected list presentation (inline ≤4, bulleted >4)
- Warmer, more confident language across all recommendation categories
- `acl_check` classification handler (`acl_not_enforced` category)
- `SpecPatch` for isolation_breach (suggests acl_check assertion)
- Granular service/dns/health categories (`service_down`, `dns_failure`, `network_degraded`)
- Edge-case classification robustness: nil deref, unsafe type assertions, probe zone matching, VPN guard
- All core tests green + real homelab validation runs performed repeatedly

### In Progress / Just Landed
- Sprint 4 complete
- Post-implementation stabilization pass: panic hardening in snapshot CLI, drift logic improvements (Improved category populated, more robust behavior, better exit codes), UX reminders for long-term value features, full test + vet validation green.
- Additional polish pass: Much warmer and more actionable help text + output for snapshot and drift commands, tighter integration of long-term tools into doctor and audit flows, improved list output with guidance, README long-term section added. All tests green.

### Remaining High-Impact Gaps (to Golden Goal)
- Documentation + examples that demonstrate the "wow" experience

---

**Current Estimated Progress Toward Golden Goal: ~96%**

**Primary Remaining Distance:** 
- High-quality, narrative documentation and real-world example walkthroughs that let a new homelabber experience the full "this tool gets me" feeling (First Contact → precise recommendations → drift confidence over time).
- Commit + release hygiene on the large body of recent work.

---

## Current State (Updated late May 2026 — post Recommendations Engine + ERROR Flow work)

**Major capabilities now shipped:**
- Full First Contact experience that orients the user immediately on bare `nyx`, `doctor --spec`, `init`, and `audit` (no spec)
- Excellent multi-homed support (`--interface` + `nyx interfaces --spec` that highlights matching adapters)
- High-quality, context-aware Recommendations engine (two-pass classification, vantage point detection using zones + RunnerContext, aggregation of related failures, now includes StatusError timeouts)
- ERROR results (timeouts, unreachable from current adapter) now produce recommendations instead of being silent
- Prescriptive, diff-style SpecPatch suggestions rendered in human output (all 10 categories)
- Strong error explanations with likely causes + practical next steps
- Real, production-grade topology baseline in `examples/homelab.yaml`
- Environment briefing is consistent and useful across commands

**What still feels short of the "wow" bar:**
- Documentation + examples that demonstrate the "wow" experience

**Current Momentum:** Very high. The core "understand my vantage point and tell me what actually matters" loop is now functional and has been validated on the real network multiple times.

---

## Epic of Epics (High-Level Themes)

### Epic 0: Foundations (Mostly Done)
- Core engine, context passing, interface selection, basic error handling, real topology support.

### Epic 1: First Contact & "I Got You" — Largely Complete (≈90%)
The user feels the tool immediately understands their environment.
- Environment Briefing, multi-homed handling, clear next steps, helpful error framing.
- Remaining: Language warmth and a few more "I see what you're trying to do" moments.

### Epic 2: Recommendations That Deliver Confidence — Major Progress (≈90%)
Recommendations move from "nice to have" to the primary reason people keep using the tool.
- Two-pass engine, vantage point detection, aggregation, ERROR inclusion, SpecPatch, warm tone, granular categories, acl_check coverage.
- Remaining: More prescriptive patches, a few edge-case classification improvements.

### Epic 3: Magical Onboarding & Import — Early Stage
`nyx init` + import paths feel like they were designed for this specific user's network.

### Epic 4: Production-Grade Experience — Early Stage
Error resilience, performance, long-term usage (history, drift), polish.

### Epic 5: Ecosystem & Indispensability — Future
Community, integrations, agentic use (MCP), becomes the default "I trust my segmentation" tool for serious homelabbers.

---

## Sprint Structure & Validation Gates

We will use **2-week sprints** with explicit **Test Run Gates** on the real homelab.

**Primary Validation Environment:** JP's actual network (multiple VLANs, frequent multi-homed testing, real Omada controller).

After every sprint (or at minimum after every Epic), we will run a structured test suite against the real topology and capture:
- `nyx doctor` output
- `nyx audit --spec examples/homelab.yaml` (default + forced interfaces)
- `nyx init` output
- Qualitative notes: "Did this feel like it understood my network?"

---

## Proposed Sprint Breakdown (Living Document)

### Sprint 0 — Current (Completed / In Progress)
**Focus:** Multi-homed support + basic First Contact + real topology baseline

**Key Deliverables (already mostly done):**
- `--interface` + `nyx interfaces`
- Environment Briefing in doctor
- Real topology in examples/homelab.yaml
- Improved error explanations for timeouts

**Validation Gate:** Already partially done via live testing across VLANs.

---

### Sprint 1 — "I Just Landed" (First Contact + Multi-homed) — Largely Complete

**Goal:** Running `nyx doctor`, `nyx init`, or bare `nyx` for the first time feels genuinely helpful and reassuring.

**Work Completed:**
- Environment Briefing made conversational across doctor / init / audit (no-spec)
- Full `--interface` + `nyx interfaces --spec` (highlights matching adapters)
- Recommendations visible on ERROR runs
- Strong timeout + error explanations with causes + suggestions
- Multiple real validation runs across VLANs (Valhalla, Arcade, Nightfall, dual-homed)

**Remaining Polish (low effort, high perceived quality):**
- A few more "I got you" phrasing tweaks in briefings and recommendations
- Minor noise reduction in multi-homed warnings

---

### Sprint 2 — "This Actually Helps" (Recommendations That Deliver) — COMPLETE

**Goal:** Recommendations become the standout reason a user keeps coming back. When they run an audit on their real network and get failures, they feel *helped*, not just diagnosed.

**Major Work Completed (this phase):**
- Complete rewrite of recommendations engine (two-pass classify + generate using RunnerContext + zones)
- Vantage point detection and aggregation (isolation failures + discovery timeouts now collapse into one rec)
- `StatusError` results (timeouts, unreachable) now flow into recommendations
- Prescriptive, diff-style SpecPatch generation + human rendering (all 10 categories covered)
- Renderer fixes so Affected lists and patches are actually shown
- Real validation on `examples/homelab.yaml` from multiple vantage points

**Current Remaining in This Epic (Quality Focus):**
- Documentation + examples

**Success Criteria / Test Run Gate (End of This Phase):**
- Running the real `homelab.yaml` from nightfall (or any single VLAN) produces at least one recommendation that makes you say "yes, that's exactly the problem and what I should do about it."
- The top 3-4 failure categories the user actually hits produce specific, actionable output (including suggested spec additions).
- The output feels like a knowledgeable friend, not a scanner.

---

### Sprint 2 — Recommendations That Matter — Target: 3 weeks

**Goal:** Recommendations are the standout feature that makes people go "this is actually useful."

**Tickets / Work:**
- Fix the "ERROR status hides recommendations" problem (critical).
- Significantly raise quality of remediation text on real topologies (especially isolation violations).
- Basic but useful `SpecPatch` generation for the top 3-4 failure modes.
- Better handling of vantage point / runner context in recommendations.

**Success Criteria / Test Run Gate:**
- When running the real `homelab.yaml` from different VLANs, at least 60-70% of failures produce recommendations that feel specific and actionable (not generic).
- You can point to specific recommendations that would have helped you in the past.

---

### Sprint 3 — Magical Onboarding — Target: 3 weeks

**Goal:** `nyx init` + import feel like they were built for *your* network.

**Tickets / Work:**
- Make `nyx init` produce a dramatically better starter spec by leveraging detected interfaces + networks.
- Strong OPNsense import path (at minimum parity with basic Omada).
- Polish the "generate → customize → validate" flow.

**Success Criteria / Test Run Gate:**
- Running `nyx init` on a fresh machine in your environment produces something you would actually keep and iterate on, rather than throw away.
- Importing from a real controller (Omada or OPNsense) produces useful assertions quickly.

---

### Sprint 4 — Resilience & Polish — Target: 3 weeks

**Goal:** The tool stops feeling brittle on real networks.

**Tickets / Work:**
- Make recommendations visible even when some assertions error.
- Better timeout handling + partial results.
- Performance work on larger networks.
- General UX polish (error messages, progress, output formatting).

**Success Criteria / Test Run Gate:**
- You can run a full audit against your real topology and get useful output (including recommendations) even if some checks fail.

---

### Sprint 5 — Long-term Value + Ecosystem — Target: 4+ weeks

**Goal:** The tool becomes something you want to keep using over months/years.

**Tickets / Work:**
- Basic history / comparison between runs.
- Drift detection (at least for isolation policies).
- Better probe management and reliability.
- Community-friendly example topologies and documentation.

---

## Overall Timeline (Aggressive but Realistic)

- **End of June 2026**: End of Sprint 1 (strong First Contact)
- **Mid July 2026**: End of Sprint 2 (recommendations start feeling valuable)
- **End of July / early August**: End of Sprint 3 (init + import feel magical)
- **September 2026**: End of Sprint 4 (resilient enough for daily/weekly use)
- **Q4 2026**: Sprint 5 and beyond (long-term value + ecosystem)

---

## Guiding Principles

1. **Validate on real networks constantly.** Your homelab (with its multi-homed testing, real Omada, and actual isolation policies) is the primary source of truth. Fake test specs are only for unit/integration tests.

2. **Noob first, expert always.** Every major feature should have a smooth default path + power-user escape hatches (`--interface`, verbose flags, JSON, etc.).

3. **"I got you" over cleverness.** The tool should feel like a knowledgeable friend who just landed in your network and is helping you understand it, not like a fancy scanner.

4. **Error states are part of the product.** Many real runs will have partial failures. The tool must remain useful and insightful even then.

---

## Current Phase Focus (Right Now)

**Sprint 3 — Magical Onboarding (COMPLETE):**
1. ~~Make `nyx init` propose meaningful zone/network names~~ ✅
2. ~~Add policies section detection/generation~~ ✅
3. ~~Add probes section suggestion~~ ✅
4. ~~OPNsense provider beyond info~~ ✅

**Sprint 4 — Resilience & Long-Term Value (COMPLETE):**
1. ~~History/snapshot system~~ ✅ — persist audit results, enable drift detection
2. ~~Drift detection~~ ✅ — `nyx drift status` to compare against baseline
3. ~~Recommendations in JSON output~~ ✅ — include in AuditReport struct
4. ~~Edge-case classification robustness~~ ✅ — nil deref, unsafe type assertions, probe zone matching, VPN guard
5. ~~Prescriptive SpecPatch~~ ✅ — diff-style patches, real spec values, all 10 categories covered

**Target for Sprint 4:** Repeated runs produce actionable drift reports. The tool stops feeling like a one-time scanner.

---

## Overall Timeline (Updated)

- **Late May 2026**: End of major Recommendations engine + ERROR flow work (current)
- **Early June 2026**: End of current quality polish pass on recommendations (zone/language/SpecPatch)
- **Mid June onward**: Epic 3 (Magical `nyx init`) + remaining Epic 2 coverage
- **July–August 2026**: Resilience, long-term value features, broader provider support

---

## Guiding Principles (Unchanged, Reinforced)

1. **Validate on real networks constantly.** Your homelab is the source of truth.
2. **Noob first, expert always.**
3. **"I got you" over cleverness.**
4. **Error states are part of the product.** The tool must remain useful and insightful even on partial runs.

---

**This is a living document.**  
It will be updated after every significant validation run on the real network.

Next action: Execute the small quality polish pass outlined in the "Current Phase Focus" section above, then re-evaluate the % and remaining checklist.
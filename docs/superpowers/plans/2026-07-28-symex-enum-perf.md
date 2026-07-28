# Symex Enumeration Performance Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking.
> Execute task-by-task; every task ends with the repo green.

**Goal:** Full symex regen (enumeration + witness solving) for the rung-4a
`linux_flow_dissector` IR in **under 1 minute wall**, without changing
parser semantics or the enumerated path set. Baseline (2026-07-28):
enumeration alone is ~55 min wall / ~30 CPU min (vs 4.4 min pre-tunnel);
witness solving is already parallel + length-ladder. Escape hatch: if the
target is proven unreachable, the deliverable becomes a written
impossibility analysis backed by profiling data (which levers were tried,
measured effect of each, why the residue is irreducible z3 work).

**Why:** Rung-4a vectors regen and any future `max_depth` raise are blocked
on this (see the amended max_depth decision in
`2026-07-28-flow-dissector-rung4a.md`); rung 4b (GRE) multiplies the path
space again. Incremental enumeration was flagged as the critical lever —
this plan executes it plus the cheaper levers around it.

**Where the time goes:** `engine.rs` DFS calls `Solver::check()` at every
select arm, default, body-truncation, and oob fork. Each call
(`z3solver.rs`) builds a FRESH `z3::Solver`, re-asserts the entire
constraint prefix from the root, solves, and discards learned clauses.
Deep tunnel prefixes re-pay depths 1..d-1 at every node; siblings share
nothing; the phase is serial (wall ≈ 2× CPU: not even one core saturated).
Pathological clusters are chained symbolic offsets (ipv4.options → tunnel
→ ext_opt bodies) blasting full-width barrel shifters per fresh check.

## Global Constraints

- **Path-set identity:** for every gallery example, the enumerated path
  set (IDs + `PathKind`s) must be byte-identical before/after each perf
  lever. Perf work must not change which arms are feasible. This is the
  soundness guardrail — a fast path that misjudges SAT/UNSAT silently
  changes parser coverage.
- **Semantics frozen:** `max_depth`, `TESTGEN_LOOP_UNROLL`, `SANITY_BYTES`,
  the oob/trunc fork structure, and `FeasibilityLog` behavior (lint
  depends on it) are not modified.
- Committed golden suites are never re-minted in a perf commit; their
  `testgen::replay` stays green. Witness BYTES may change once lever 4
  lands (constructive synthesis) — that is acceptable because vectors are
  interp-checked at generation time and rung-4a vectors are not yet
  committed; committed suites are only replayed, not regenerated.
- Every commit leaves the full gate green:
  `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --features symex && buf lint && cd py && ruff check . && pyright && pytest'`.
- Commit style: `perf(symex): ...` one lever per commit, before/after
  numbers in the message, repo Co-Authored-By trailer.
- Never iterate against the 55-minute run: use the proxy bench (Task 1)
  for the inner loop; full rung-4a timings only at lever boundaries, run
  in the background with generous timeouts. The enumeration heartbeat
  prints `ENUM PROGRESS` every 25 paths — treat silence as a hang only if
  the heartbeat is stale.

## Decisions (fixed here so the tasks are mechanical)

- **Target:** rung-4a `linux_flow_dissector` full regen < 1 min wall
  (enumeration well under that). Interim milestones: enum < 3 min after
  levers 1–2, < 1 min after lever 3.
- **Lever order:** (1) ground/constructive feasibility fast path →
  (2) incremental z3 push/pop → (3) parallel enumeration →
  (4) constructive witness synthesis. Measured effect after each; a lever
  that lands < 1.5× may be reverted to keep the code simple.
- **Cross-check mode:** while any fast path is under development, a
  debug/feature-gated mode asserts fast-path SAT/UNSAT verdicts against
  z3 on every query; the full gallery runs under it at least once before
  the lever's commit. The mode stays in-tree (cheap insurance for future
  IR features that widen the ground fragment).
- **Width anchoring (lever 2 prerequisite):** MSB-first `Term::Extract`
  offsets are anchored to the packet BV's total width, which grows with
  `cursor_max` along a path — naive push/pop breaks anchoring. Resolve by
  one of: (a) LSB-anchored internal offsets (translate at model-read
  time), or (b) a fixed per-path width bound (allocate the BV at the
  path's `expr_max`-derived cap up front). Decide by measuring which keeps
  z3 queries cheap; document the choice in the design notes of the
  implementing commit.
- **Parallel enumeration (lever 3):** DFS children at a select are
  independent; the only obstacle is the shared `&mut dyn Solver`.
  Per-worker solvers, work-queue pattern mirroring `solve_all` in
  `testgen.rs`. Paths are sorted by ID at the end of `enumerate`, so
  output determinism survives. `FeasibilityLog` merges as set unions.
- **Constructive witness synthesis (lever 4):** a path whose constraints
  are all ground (concrete offsets, `Value`/`Masked`/`Range` entries on
  disjoint fields) gets its packet bytes built directly — keyset values
  written at field offsets, free bits zero, length from the solved-free
  ladder floor. z3 remains the fallback for symbolic-offset paths.
  Generated vectors stay interp-checked (`vector_for` already
  round-trips through `run_bits`), so a synthesis bug cannot produce a
  wrong vector, only a bailed generation.

## Tasks

- [ ] **1. Bench harness + instrumentation baseline.** Add a
  `--features symex` bench/bin that times enumeration and solve phases
  separately for a named example; add per-check instrumentation
  (count, ground-vs-symbolic classification, time histogram) behind a
  flag. Pick/build a mid-size proxy IR that enumerates in seconds and
  exhibits tunnel-style symbolic-offset checks (candidate: a trimmed
  two-level encap parser) for inner-loop iteration. Kick off ONE
  background baseline run on rung-4a capturing (a) phase timings,
  (b) the full path inventory (IDs + kinds) to a scratch file — this is
  the identity reference for every later lever. Commit the harness.
- [ ] **2. Lever 1 — ground/constructive feasibility fast path.**
  Classify `Term`s: ground (Const, concrete-offset Extract chains over
  otherwise-unconstrained disjoint fields, post-substitution metadata
  constants) vs symbolic (`ExtractAt`, computed metadata). Answer ground
  checks in Rust (constant eval + per-field keyset set-algebra including
  first-match negation); fall through to z3 otherwise. Land with
  cross-check mode green over the gallery + proxy. Record check-count
  reduction and proxy/rung-4a timings.
- [ ] **3. Lever 2 — incremental z3 along the DFS.** Resolve the width
  anchoring decision, then restructure enumeration to one solver with
  push/pop at fork points (or prefix-assert + `check_assumptions`, the
  pattern already in `solve_witness`). Verify path-set identity vs the
  Task-1 inventory. Record timings.
- [ ] **4. Lever 3 — parallel enumeration.** Per-worker solvers +
  work queue; deterministic output (sort preserved, log merged as
  unions). Verify path-set identity. Record timings; check wall ≪ CPU.
- [ ] **5. Lever 4 — constructive witness synthesis.** Ground-path
  packet building with z3 fallback; interp round-trip stays the
  correctness gate. Record solve-phase timings and the synthesized/z3
  split.
- [ ] **6. Proof + docs.** One clean timed full regen of rung-4a from
  scratch: report enumeration wall, solve wall, total; compare to the
  55-min/4.4-min baselines; confirm path-set identity, gallery gate
  green, committed suites replay green. Update `memory` symex-perf notes
  and the rung-4a plan's max_depth decision note (incremental lever now
  landed — record what a `max_depth` raise would newly cost). If the
  <1 min target was NOT reached, write the impossibility analysis
  (per-lever measured effects, profile of the residue, why it is
  irreducible) as a spec-style note in `docs/superpowers/specs/`.

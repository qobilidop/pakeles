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
- **Lever order (AMENDED 2026-07-28 after Task-1 measurement).** The
  `encap_proxy` baseline (137 paths, 147 checks, enum 124.5s) shows
  **100.0% of check wall in ExtractAt-bearing checks** — past the first
  var-length region every downstream check carries a symbolic offset, so
  the originally-planned ground fast path has ~no headroom on tunnel
  IRs. The cost is the ENCODING: every check bit-blasts full-packet-width
  barrel shifters in a fresh solver. Replaced lever order:
  1. **Field-variable feasibility encoding.** Every `Term` atom reads a
     placed field region (engine only builds `Extract`/`ExtractAt` from
     the placed map); within a path, placements are pairwise disjoint
     (the cursor advances by each fixed width; bodies are non-negative),
     and structurally equal terms denote the same placement. So mapping
     each distinct read term to a fresh 64-bit variable (bounded
     `< 2^len`) is equisatisfiable with the packet encoding: a field
     model extends to a packet (disjoint regions, values fit widths),
     a packet model restricts to field values, and every constraint
     atom evaluates identically. Feasibility answers are IDENTICAL by
     construction — path-set identity is a theorem, not a hope — and
     checks become width-independent 64-bit arithmetic (no packet BV,
     no shifters).
  2. **Field-variable witness synthesis** (subsumes the old constructive
     lever): solve the small field system, then CONSTRUCT packet bytes
     by concatenation — lengths are concrete in the model, offsets
     follow, body bytes free. z3 solves tiny systems; the packet BV
     disappears from testgen entirely. Interp round-trip stays the
     correctness gate.
  3. **Incremental push/pop** along the DFS — only if still needed once
     checks are field-variable (they may drop to µs each).
  4. **Parallel enumeration** — only if still needed.
  Measured effect after each; a lever that lands < 1.5× may be reverted
  to keep the code simple.
- **Cross-check mode:** while the encoding change is under development,
  an env-gated mode (`PAKELES_SYMEX_XCHECK=1`) answers every feasibility
  query under BOTH encodings and panics on disagreement; the proxy and
  full gallery run under it at least once before the lever's commit. The
  mode stays in-tree (cheap insurance for future IR features that could
  violate the disjoint-regions premise, e.g. overlapping reads).
- **Parallel enumeration (lever 4, if needed):** DFS children at a select
  are independent; the only obstacle is the shared `&mut dyn Solver`.
  Per-worker solvers, work-queue pattern mirroring `solve_all` in
  `testgen.rs`. Paths are sorted by ID at the end of `enumerate`, so
  output determinism survives. `FeasibilityLog` merges as set unions.

## Tasks

- [x] **1. Bench harness + instrumentation baseline.** DONE (951b9e5):
  `symex_bench` bin (phase timings, inventory dump), `EnumStats`
  check telemetry (always-on), `builder::encap_proxy` (137 paths,
  enum 124.5s, 100.0% of check wall symbolic — the measurement that
  amended the lever order). Rung-4a background baseline launched
  (full run: phase timings + `.bench/baseline-rung4a.inv` identity
  reference, inventory written before the solve phase starts).
- [ ] **2. Lever 1 — field-variable feasibility encoding.** New
  `Solver::feasible(cs) -> bool` decided over per-region 64-bit
  variables (fresh var per structurally-distinct read term, bounded
  `< 2^len`); engine checks drop the packet BV and width argument.
  Cross-check mode (`PAKELES_SYMEX_XCHECK=1`) runs both encodings and
  panics on disagreement — proxy + gallery green under it before
  commit. Verify path-set identity (proxy inventory; rung-4a inventory
  when the baseline lands). Record proxy timings.
- [ ] **3. Lever 2 — field-variable witness synthesis.** Solve the
  field system, evaluate lengths from the model, construct packet
  bytes by concatenation (free bits zero); z3 only ever sees the small
  field system. Witness BYTES may change (allowed); interp round-trip
  in `vector_for` stays the correctness gate; committed suites replay
  green. Record solve-phase timings.
- [ ] **4. Levers 3–4 if still needed — incremental checks, parallel
  enumeration.** Only if the field-variable encoding leaves the target
  unmet; re-measure first, per-lever commits as above.
- [ ] **6. Proof + docs.** One clean timed full regen of rung-4a from
  scratch: report enumeration wall, solve wall, total; compare to the
  55-min/4.4-min baselines; confirm path-set identity, gallery gate
  green, committed suites replay green. Update `memory` symex-perf notes
  and the rung-4a plan's max_depth decision note (incremental lever now
  landed — record what a `max_depth` raise would newly cost). If the
  <1 min target was NOT reached, write the impossibility analysis
  (per-lever measured effects, profile of the residue, why it is
  irreducible) as a spec-style note in `docs/superpowers/specs/`.

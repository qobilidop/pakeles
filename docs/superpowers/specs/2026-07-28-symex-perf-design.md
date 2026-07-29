# Symex Performance: Design Notes

How `linux_flow_dissector` (rung 4a) symex regen went from *could not
finish* to **7.8 seconds**, and where each factor of the speedup comes
from. Companion to the plan
(`../plans/2026-07-28-symex-enum-perf.md`); commits `951b9e5` →
`92a2cbf`, all 2026-07-28.

## Headline numbers

| Workload | Before | After | |
|---|---|---|---|
| `encap_proxy` full regen (137 paths) | 137.7s | **0.037s** | ~3,700× |
| rung-4a enumeration (12,993 paths) | never completed¹ | 4.5s² | — |
| rung-4a full regen (enum + witnesses + vectors) | never completed¹ | **7.83s** | — |

¹ The pre-change encoding produced 125 of 12,993 paths in ~105 minutes
(projected ~1 week). The historical "~55 min enumeration" measurements
were themselves partial runs; no complete rung-4a enumeration existed
before this work.
² Enumeration walk + feasibility checks; the remaining ~3.3s of the
7.83s total is emit-time witness solving (3.1s) and vector assembly +
interp verification (0.26s).

Every number in this doc is from `symex_bench` (release build, in the
dev container) with per-phase telemetry (`EnumStats`, and
`PAKELES_SYMEX_WTIME=1` for the witness-phase breakdown).

## Where the time used to go

The engine enumerates control-flow paths by DFS, calling the solver at
four fork sites (select arm, select default, body-truncation,
out-of-bounds) to prune infeasible branches, and then solving one
witness packet per emitted path. The old architecture paid four
compounding costs:

1. **The packet-bitvector encoding.** Every query modeled the packet as
   one bitvector of the path's width budget (tens of thousands of bits
   on tunnel paths, since each var-length field's *interval max* — e.g.
   2046-byte IPv6 option bodies — is added to the budget). Every field
   read compiled to an extract over that vector.

2. **Barrel shifters for symbolic offsets.** A field placed after a
   var-length region has a symbolic offset, so its read (`ExtractAt`)
   compiled to `packet >> ((w - len) - off)` — a full-width barrel
   shifter that z3 bit-blasts into O(w·log w) circuitry. Tunnel paths
   chain several var-length regions (ipv4 options → tunnel → inner ipv6
   → ext-option bodies), so a single feasibility check could contain
   several full-width shifters. This was measured, not guessed: the
   Task-1 telemetry showed **100.0% of check wall time in
   ExtractAt-bearing checks**, with pathological single checks in the
   1–10s bucket (and, on the real rung-4a IR, historically ~45-minute
   clusters).

3. **A fresh solver per query.** Each check created a new `z3::Solver`,
   re-asserted the *entire* constraint prefix from the DFS root,
   solved, and threw away everything z3 learned. At depth d the check
   re-paid depths 1..d−1; siblings shared nothing. Cost scaled like
   O(nodes × prefix), against a tree whose depth and branching the
   rung-4a tunnel back edges had just multiplied.

4. **A second full pass for witnesses.** After enumeration, testgen
   re-built each path's entire constraint system from scratch in a
   fresh solver (parallel across a thread pool, with a length ladder
   `len ≤ 128B → ≤ 4KB → unbounded` to keep witnesses small) — paying
   cost 1–3 all over again, once per path.

The proxy (`builder::encap_proxy`, built for this work: two mini-IP
header types with var-length regions, cross back edges, a select behind
every symbolic offset) reproduces this cost shape at 2-minute scale:
137 paths, 147 checks, 124.5s of enumeration, 95%+ of it in z3.

A note on the lever that was *dropped*: the original plan's first idea
was a ground-value fast path (answer constant-vs-constant checks in
Rust, skip z3). The Task-1 measurement killed it — past the first
var-length region, *every* downstream check carries an `ExtractAt`, so
the ground fragment is empty exactly where the time goes. The fix had
to change the encoding, not skip the solver.

## Lever 1 — field-variable encoding (`91772dd`)

**Change.** Feasibility queries stop modeling the packet at all.
Each structurally-distinct read term (`Extract`/`ExtractAt`) maps to
one fresh 64-bit variable, constrained to the read's width
(`var < 2^len`); constraint atoms become plain 64-bit arithmetic over
those variables. No packet BV, no shifters, and query cost is
independent of the path's width budget.

**Why it is sound.** The engine only ever constructs read terms from
its `placed` map, so every read denotes a *placed field region*, and:

- regions within a path are pairwise disjoint — the cursor only
  advances (each fixed field by its width, each body by a non-negative
  length), so two placements never overlap;
- structural term equality coincides with region identity — the same
  placement always yields the identical term, and distinct placements
  yield structurally distinct offset terms.

Therefore the encodings are equisatisfiable *query by query*: a field
model extends to a packet (write each region's value at its offset —
disjointness makes the writes conflict-free, the width bound makes
values fit), and a packet model restricts to field values, with every
constraint atom evaluating identically in both directions. Feasibility
answers — and hence the enumerated path set — are unchanged **by
construction**, not merely by testing. (This argument lives in code on
`Term`'s doc comment; it is the invariant future IR features must
preserve, and the cross-check mode exists to catch a violation.)

**Effect.** Proxy enumeration 124.5s → 0.68s (183×); every check under
10ms. On rung 4a this turned enumeration from intractable into 52s —
the first complete enumeration of the tunnel IR (12,993 paths), which
also revealed the true path count (prior estimates, extrapolated from
partial runs, were ~10× low).

## Lever 2 — constructed witnesses (`cdcc725`)

**Change.** `solve_witness` uses the same field system: solve the small
per-region constraint set (same length ladder), read the region values
out of the model, evaluate each region's offset with a Rust evaluator
that mirrors z3's 64-bit wrapping semantics exactly, and *construct*
the packet — region bits at their offsets, everything else zero. z3
never models packet bytes at all.

**Effect.** Proxy witness phase 16.2s → 0.42s; full proxy regen 1.12s.
Two useful side effects: free bytes are zero by construction (the old
model-completion could pick arbitrary junk), and witness bytes are
fully determined by the solved field values — smaller, cleaner
vectors. Correctness does not rest on the construction being right:
every vector still round-trips through the reference interpreter at
generation time (`vector_for` bails on any mismatch), so a synthesis
bug can fail loudly, never emit a wrong vector.

## Lever 3 — incremental session + emit-time witnesses (`2bfb84e`)

At this point rung-4a ran end-to-end in 133s: checks 49.6s (fresh
solver per query — cost 3 above — now dominated, since each query was
cheap but still re-translated and re-solved hundreds of prefix
constraints), witnesses 81.1s (cost 4: the second full pass). One
architectural change removed both.

**Incremental `Session`.** The solver trait gained a session whose
push/pop scopes mirror the DFS exactly: every fork pushes a scope,
asserts only its constraint *delta*, recurses, and pops on backtrack.
The solver stack therefore always equals the current frame's
constraint vector, and z3 keeps its learned state across the
prefix-heavy query stream. Checks: 5,054 queries, 49.6s → 1.1s. (One
subtlety: a region variable's width bound asserted in a sibling scope
has been popped, so every translation batch re-asserts the bounds of
the terms it touches — redundant asserts are cheap, missing ones are
unsound.)

**Witnesses at emit time.** Since the emit sites sit inside the scope
whose stack *is* the path's constraint system, the witness ladder runs
on the already-hot solver instead of rebuilding the system later.
The separate solve phase disappears; testgen's `solve_all` is now just
vector assembly plus the interp round-trip (0.26s serial). `Path`
carries its witness; `bit_len`/`width`/`constraints` fields are gone.

That alone left ~68s of ladder solving, which telemetry
(`PAKELES_SYMEX_WTIME=1`) split as: solve 62.2s, model-extraction
2.5s, packet-build 0.05s — i.e. almost entirely `check_assumptions`
calls (18,986 of them: 12,993 emits plus 5,993 UNSAT rungs). Three
targeted cuts, each measured:

- **Epoch-keyed model cache.** The session tags its stack state with a
  monotonic epoch (bumped on push/pop/assert). Sibling emits at an
  unchanged stack — e.g. the fixed-field truncation forks of one
  state, which share the state-entry stack — reuse the last model and
  only evaluate their own bit-length term: zero solver calls.
- **SAT checks cache their proof model.** Almost every emit is
  immediately preceded by the feasibility check that proved its stack
  SAT (an arm's accept/reject follows the arm check; truncation forks
  follow the state's entry). `Session::check` now stores the model it
  just found, so those emits also hit the cache.
- **Small-enough acceptance rule.** A cached model has no small-length
  bias (only the ladder biases small), so a cache hit is accepted only
  if the bit-length it implies fits the smallest ladder rung not
  statically doomed for this path — the same bound the ladder itself
  could guarantee. Oversized hits fall through to the real ladder.
  Witness-size quality is thus preserved *contractually*, not
  accidentally.
- **Wrap-safe interval minimum (`term_interval`).** The static
  fixed-width lower bound on a path's length missed that constrained
  var-length bodies also floor the length (an IPv6 ext header's
  `(hdrlen+1)*8` is ≥ 8 bytes), so deep paths burned provably-UNSAT
  small rungs — an UNSAT-under-assumption proof each. Interval
  arithmetic over the *substituted term* (reads span their declared
  width; any node where 64-bit wrapping is possible collapses its
  lower bound to 0, since wrapping can make large operands produce
  small values) gives a sound minimum; rungs below it are skipped
  without a solver call. UNSAT rungs burned: 5,993 → 14.

**Effect.** Witness phase 81.1s (parallel, separate pass) → 3.1s
(inline, single-threaded). Rung-4a total: 133.4s → 7.83s. The proxy
runs its entire regen in 0.037s. Parallel enumeration — the plan's
last-resort lever — was never needed.

## Why the path set provably did not change

Perf work on feasibility checks can silently change which arms get
pruned — a soundness bug ordinary tests may not catch. Four
independent guards, all green:

1. **The equisatisfiability argument** (lever 1 above): answers
   identical by construction under the disjoint-regions invariant.
2. **Cross-check mode** (`PAKELES_SYMEX_XCHECK=1`): every feasibility
   query is re-decided under the old packet encoding and any
   disagreement panics. Run green over `encap_proxy` (tunnel-shaped,
   147 queries), `eth_ipvx_l4`, and `counted_items`, plus a forced
   in-test battery. Kept in-tree as insurance for future IR features
   that could violate the invariant (e.g. overlapping reads).
3. **Inventory identity**: `symex_bench --inventory` dumps the full
   path list (kind + id). The proxy inventory captured under the *old*
   encoding is byte-identical under every lever; the rung-4a inventory
   (first produced at lever 2) is byte-identical across all subsequent
   levers, including the final state.
4. **The interp round-trip**: all 12,993 rung-4a vectors (and every
   gallery suite) replay green through the reference interpreter.

One planned artifact could not exist: an old-encoding rung-4a
inventory (the plan's Task-1 baseline). Producing it *is* the
intractable computation this work removed — the attempt was killed at
125/12,993 paths after ~105 minutes. The chain above substitutes for
it; the deviation is recorded in the plan.

## What was deliberately not changed

`max_depth`, `TESTGEN_LOOP_UNROLL`, `SANITY_BYTES`, the
oob/truncation fork structure, and `FeasibilityLog` semantics are
untouched — this was purely a change in how queries are *decided*,
never in which queries are *asked*. Witness bytes did change
(constructed, free bytes zero) — permitted because vectors are
interp-checked at generation and rung-4a vectors were never committed;
committed suites are replayed, not regenerated, and replay green.

## Residual profile and headroom

Of the final 7.83s: ~3.4s DFS walk + constraint/term bookkeeping
(Rust), 1.1s feasibility checks, 3.1s witness ladder, 0.26s assembly +
interp. If a future rung multiplies the path space again, the
remaining levers, in order of expected value:

- **Parallel enumeration** (unused lever 4): DFS children are
  independent; per-worker sessions with the `solve_all`-style work
  queue would divide the whole 7.8s by close to the core count.
- **Model-extraction batching**: `model.eval` per region per emit is
  ~1.3s of the witness phase; iterating the model's assignments once
  would cut most of it.
- **Read-set tracking in the session** (instead of re-walking the
  constraint vector per emit) if `collect_reads` ever shows up in a
  profile.

None are worth their complexity at the current scale.

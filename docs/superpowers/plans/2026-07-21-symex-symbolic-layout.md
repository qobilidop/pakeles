# Symex Symbolic-Layout Rework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. This is a **big-bang** engine rewrite (offsets + `bit_len` become `Term`s at once); it does not compile or validate incrementally until complete, so the "tasks" below are phases with a single continuous green gate at the end, not independently-committable green-tree steps.

**Goal:** Decouple control-flow *path* from concrete *layout* in the symbolic engine — keep var-lengths symbolic, solve ONE (minimal) witness per control-flow path — superseding the min+max/all-SAT length forking.

**Architecture:** `Frame.cursor` and `Path.bit_len` become symbolic `Term`s; a new `Term::ExtractAt { off: Term, len }` reads a field at a symbolic bit offset (validated foundation, `docs/.../2026-07-21-symex-symbolic-layout-design.md` §1). Var-length fields no longer fork per value; they fork control flow only into {continue, body-truncation, out-of-bounds}. Each `Frame` also carries a concrete `cursor_max: usize` width budget (via `codegen::p4::expr_max` interval arithmetic) so the per-path solve BV stays tight. Testgen solves + minimizes `bit_len` per path → small packets.

**Tech Stack:** Rust, z3 (behind the `Solver` trait), `./dev.sh` docker gate.

## Global Constraints

- Reference interpreter (`src/interp/mod.rs`) is normative; generated packets must replay to the recorded outcome. Interp semantics that pin this rework:
  - Fixed field too short → `Reject "out of bounds"`.
  - `ByteLen` field: `len_bytes = eval_expr(...)` (u64 **wrapping**); reject `"out of bounds"` iff `len_bytes*8 + cursor` overflows usize **or** `> avail_bits`. **No SANITY threshold in interp** — wrapping and too-short are the same reject.
- Engine ⟷ pathid segment construction must stay identical (`src/symex/pathid.rs` mirrors `engine.rs`).
- Gate = `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'` + python (ruff/pyright/pytest). Regen = `./dev.sh scripts/gen-examples.sh`.
- `committed_goldens_agree` (kernel projection) is UNAFFECTED (goldens are kernel captures; symex only changes which vectors we generate) — must stay green with no re-mint.
- Path-id `inst.field=NB` length segments are **removed** (both engine + pathid); replaced by `!oob@inst.field` (wrapping/oversize reject) and `!trunc@inst.field` (too-short) on failure, and **no segment** on a successful var-field read.

---

## Design decisions derived beyond the spec (load-bearing)

1. **oob/continue threshold = `SANITY_BITS`, width budget = `8*expr_max`.** The continue/trunc branch constrains `len_term <= SANITY_BITS/8`; the oob branch constrains `len_term > SANITY_BITS/8`. This exactly matches pathid's existing `SANITY_BITS` classifier, so engine and pathid agree on every witness. The width budget uses the tighter `expr_max` (interval max) — sound because `len_term` is a *derived expression* over bounded fields: its non-wrapping feasible values are `<= expr_max`, and the SANITY constraint excludes the wrapping ones, so z3 can never pick a length in `(expr_max, SANITY/8]` (structurally infeasible). Offsets therefore stay `<= cursor_max = width` and `ExtractAt`'s shift never wraps.
2. **`model_packet` must index MSB-first from the true BV size**, taking an `n_bits <= width` parameter, so a minimized `actual_bits`-bit slice of a `width`-bit packet reads the correct top bits.
3. **Minimize `bit_len` per path** (z3 `Optimize`) for small packets — subsumes the max-witness-cap follow-up. Fallback to plain `check` if regen is too slow (packets aren't committed — `vectors.json` is gitignored — so this is a gate-speed/nicety, not correctness).

---

## Task 1 — Solver layer (`src/symex/solver.rs`, `src/symex/z3solver.rs`)

**Files:** Modify `src/symex/solver.rs`, `src/symex/z3solver.rs`.

- `Term`: add `ExtractAt { off: Box<Term>, len: usize }`.
- `Solver` trait: **remove** `all_values`, `min_max`; **add**
  `fn solve_witness(&mut self, width: usize, cs: &[Constraint], len: &Term) -> Option<(Vec<u8>, usize)>` (minimize `len`, return `(actual_bits`-bit packet, actual_bits)). Keep `check`.
- `z3solver.rs`:
  - `term()`: encode `ExtractAt` per design §1 (shift-mask: `packet.bvlshr((w-len)-off).extract(len-1,0).zero_ext(64-len)`, resizing `off` to `w`).
  - Generalize `model_packet(model, packet, n_bits)` to index from `packet.get_size()` and read `n_bits` (decision 2). `check` passes `n_bits == packet_bits` (unchanged behavior).
  - Implement `solve_witness` via `Optimize::minimize(term(len))`; on Sat, `actual = eval(len)`, `bytes = model_packet(model, packet, actual)`.
  - Remove `all_values`/`min_max` impls + their unit tests; add an `extract_at_reads_symbolic_offset` test (design §1) and a `solve_witness` smoke test.

## Task 2 — Engine (`src/symex/engine.rs`)

- Remove `LENGTH_VALUES_CAP` and `SANITY_BITS`-as-reject-limit *usage in the value loop*; keep `SANITY_BITS` const (now the oob threshold) and `TESTGEN_LOOP_UNROLL`. Keep `cyclic_states` (loop cap only).
- `Path`: `bit_len: usize -> Term`; add `width: usize`.
- `Frame`: `cursor: usize -> Term` (start `Term::Const(0)`); `placed: HashMap<_, (usize,usize)> -> (Term, usize)`; add `cursor_max: usize`.
- `term_of_expr` field ref: look up `placed -> (off_term, len)`; if `off_term` is `Const(c)` emit `Term::Extract{c,len}` else `Term::ExtractAt{off_term,len}`.
- `emit(ctx, frame, kind, bit_len: Term, width: usize)`.
- `walk_state` max-depth reject: `emit(.., cursor.clone(), cursor_max)`.
- `walk_extracts`:
  - `Bits(n)`: trunc `emit(.., add(cursor, cst(n-1)), cursor_max + n)`; `placed.insert((inst,field),(cursor.clone(), n))`; `cursor = add(cursor, cst(n))`; `cursor_max += n`.
  - `ByteLen(expr)`: `len_term = term_of_expr(expr)`; `lmax = expr_max(expr, parser)? as usize` (bytes), `lmax_bits = lmax*8`.
    - **oob branch** (emit iff SAT): clone, push `Constraint::InRange(len_term, SANITY_BYTES+1, u64::MAX)` (i.e. `> SANITY_BITS/8`); feasibility `check(cursor_max.max(1), &cs)`; if SAT: seg `!oob@inst.field`, `emit(Reject "out of bounds", cursor.clone(), cursor_max)`.
    - constrain continue world: push `Constraint::InRange(len_term, 0, SANITY_BYTES)`.
    - **body-trunc branch** (emit iff SAT): clone, push `InRange(len_term, 1, SANITY_BYTES)`; feasibility check; if SAT: seg `!trunc@inst.field`, `emit(Truncation, sub(add(cursor, mul(cst8, len_term)), cst1), cursor_max + lmax_bits)`.
    - **continue**: `cursor = add(cursor, mul(cst8, len_term))`; `cursor_max += lmax_bits`; recurse (body opaque, not placed).
  - `Ctx` needs `parser` (already has it) for `expr_max`.
- `walk_transition` / feasibility `check` calls: replace `child.cursor.max(1)` (Term) with `child.cursor_max.max(1)` (usize).
- Small Term helpers: `cst(u64)`, `add`, `sub`, `mul`.
- **Rewrite tests** (design §5): `length_forking` → 1 accept + 1 body-trunc + (oob iff feasible); delete `cyclic_length_forking_bounded_to_min_max` + its `byte_len_witnesses` helper; keep/adapt `cyclic_loop_unroll_capped_for_testgen`, `depth_bound_emits_reject`, `max_depth_reject_on_acyclic_chain`, `linear_accept`, `select_forks`, `shadowed_arm_pruned_and_logged`. Assert `bit_len`/`width` via the new fields (may need to solve to check concrete bit_len, or assert the Term shape / just path counts + ids).

## Task 3 — Testgen (`src/symex/testgen.rs`)

- `vector_for`: replace `solver.check(path.bit_len, &path.constraints)` with `solver.solve_witness(path.width, &path.constraints, &path.bit_len)` → `(bytes, actual_bits)`; build `Bits { bytes, bit_len: actual_bits }`. Rest (interp cross-check, category mapping) unchanged.
- Rewrite `example_suite_shape_and_replay` counts after regen reveals them (structural asserts: unique+sorted ids, replay green, accept/reject/trunc non-zero); pin exact counts once known.

## Task 4 — Pathid (`src/symex/pathid.rs`)

- `ByteLen` arm: drop the unconditional `{inst}.{field}={v}B` push. On success (`Some`): `cursor_bits += v*8`, no segment. On failure (`None`): compute `oob_by_len` (existing `checked_mul(8)+checked_add(cursor)` `> SANITY_BITS`); push `!oob@inst.field` if oob else `!trunc@inst.field`; return. (SANITY_BITS classifier already matches the engine's oob threshold — decision 1.)
- Rewrite `cov::fixture_pcap_coverage` expected ids + `total` after regen.

## Task 5 — Regen + validate (continuous gate)

1. `./dev.sh sh -c 'cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test'` green.
2. `./dev.sh scripts/gen-examples.sh` (regen both examples; observe vector-count delta + packet sizes).
3. Full gate incl. conformance (C/eBPF/Lua/BMv2), `pathid_roundtrips_all_committed_vectors`, `committed_vectors_replay_green`, `committed_goldens_agree`, `committed_ir_json_is_canonical`, buf lint, python.
4. Sanity: vector count dropped sharply (one-per-path), packets small (minimized).
5. Pin the exact counts in the rewritten shape/coverage tests.

## Self-review checklist

- Spec §2–§6 all covered (ExtractAt, engine types, solve path, removals, test rewrites, validation).
- Engine oob threshold `SANITY_BITS` == pathid classifier `SANITY_BITS` (consistency).
- `model_packet` MSB-first from true BV size (minimized-slice correctness).
- No `=NB` segment remains anywhere (engine, pathid, cov/testgen expected ids).

# The `lookahead` primitive

**Status: SHIPPED 2026-08-01**, same-day with the bit-uniform IR it
was specified on (E-Peek is alignment-condition-free on that base).
Consolidates the decisions from the 2026-08-01 design review
(`docs/plans/2026-08-01-edsl-ir-review-followups.md`, Idea 1).

Shipped shape: spec §4.4 (E-Peek) + W9; `Extract.lookahead` flag;
interpreter (consumes nothing even on a mid-peek reject — forensics
still name the failing read); symex (see below — the predicted "long
pole" collapsed); C/eBPF (scoped local cursor), Lua (overlapping tree
items), `gen p4` (native `pkt.lookahead<T>()` — the refusal direction
reversed); eDSL `lookahead(H)` / `.lookahead(H)`.

**The exhibit landed:** `p4lang_switch_parser` re-transcribed — the
three invented `*Rest` types deleted (50→47 header types, 56→53
instances), `parse_mpls_inner_ipv4/6`/`parse_eompls` restored to the
pure pass-throughs they are in the source, and the regenerated suite
is **observationally identical**: exactly 93,727 vectors with the
same 13,003/162/80,562 accept/reject/truncation split as the
emulation — same behavior, honest structure.

**Symex, as-built (the interesting part):** the field-variable
encoding keys variables on the *(offset, len)* read term, so a peek
and a re-extract of the same bits are literally the same variable —
exact overlap aliases for free. What remained: (a) slice-equality
constraints for *partial* overlaps (peek 8 bits, re-extract as two
nibbles), emitted at placement time from statically-comparable offset
terms (normalize Add-chains; bail loudly on a var-length layout
between a peek and a possibly-overlapping read — v1 cap); (b) a
concrete **peek-overhang** bound: non-truncation witnesses extend
their solved length by it so peeked reads stay inside the packet, a
fixed read of `n <= overhang` bits skips its (infeasible) truncation
fork, and var-body truncation forks floor their length at
`overhang + 1`. Adversarial peek-then-branch-then-extract-different-
types is a committed test; suites replay green and pathid mirrors.

## What and why

An extract-like operation that instantiates a header — binding its
fields in the environment, driving selects, participating in def-use —
but **does not advance the cursor**. This is P4-16's `lookahead<T>()`
/ P4_14's `current(o, w)`, the one core P4 parser construct the IR
could previously only emulate.

The demand signal: `p4lang_switch_parser`'s two lookahead sites cost
the nibble-split emulation 4 invented header types, a 4/44-bit split
of `dst_addr`, and rerouted continuations — distortion that reaches
observable output (dissector, docs), not just authoring. The gibb
"pseudo-field lookahead" pattern was previously handled zero-IR; the
flagship benchmark needing invented types is what changed that call.

**Naming: `lookahead`** (P4's own term; `gen p4` emits it verbatim).
The original `assume` was rejected: in verification vocabulary
`assume` means constraint-injection-without-checking, and this op is
a checked, rejecting read — a collision aimed exactly at the
symex-literate audience.

## IR shape

`bool lookahead = 3` on the existing `Extract` message — reuses
instance naming, environment binding, and W7 def-use machinery
wholesale. A lookahead extract:

- reads the type's fields in declared order starting at the current
  cursor, with the same joint region/input bound and the same
  two-class reject taxonomy (past region end = structural `out of
  region bounds`; past input = truncation `out of bounds` — matches
  P4's lookahead-errors-on-short);
- binds every field in ρ exactly like an extract (W7 counts it as a
  definition; later same-state extracts/pushes/keys may use it);
- leaves the cursor where it was for whatever follows (same-state
  sequencing: extracts run in declared order; a peek simply doesn't
  advance the cursor for its successors — extract-then-peek in one
  state is `parse_lisp` verbatim);
- appears in the header list as an instance whose fields carry their
  true offsets (observables tell the truth about where the bits are).

## Semantics: E-Peek

One new rule family, E-Peek = E-Fixed minus the cursor update, plus a
no-op on the cursor at the header level. Termination untouched: a
peek-only cycle still burns depth budget (R-Depth counts states
entered, not bits consumed); `max_depth` stays the sole termination
authority. Regions untouched: the cursor doesn't move, so `c ≤
top(R)` is preserved trivially.

## v1 restriction

Peeked header types must be **all-fixed-width** (no `bit_len` under a
lookahead; validator rule W9-L). Every known use case is a small fixed
peek; lift only on real demand. This also keeps the symex aliasing
finite and offset-computable per path.

## The cost center: symex aliasing

Field-variable encoding (the 2026-07-28 perf win) assumes distinct
field variables cover disjoint wire bits. A peeked field and the
subsequently extracted fields over the same bits are the same bits
under two variables — without per-path aliasing constraints, symex
would emit inconsistent witness packets and unsound agreement claims.

Within one enumerated path all offsets are known (fixed-width v1
restriction + symbolic-cursor terms), so the fix is an equality set:
whenever a peeked field's bit range overlaps a later-placed field's
bit range on the same path, assert the overlapping slices equal.
Implementation shape: at placement time, check the new field's
`(off, len)` against previously placed ranges (both directions —
peek-then-extract and extract-then-peek); emit `Eq(slice(a), slice(b))`
constraints into the path. Adversarial test:
peek-then-branch-then-extract-different-types (the two branches
overlay different field layouts on the peeked bits).

Fallback if the aliasing lands badly: ship the eDSL surface as
desugaring to nibble-split, flip the desugar target to the IR op when
symex is ready; refusal markers per backend until then.

## Cheap everywhere else

- interpreter: read fields, don't advance the cursor;
- C/eBPF: same bounds check, no `off +=`;
- Lua: overlapping tree items are normal in dissectors;
- `gen p4`: native `lookahead<T>()` — a refusal-marker direction
  reversed (bit<N>-tuple types for multi-field peeks).

## Staged plan

1. E-Peek spec rules + W-rule in `ir-semantics.md` (the "semantics
   framework absorbs a new primitive in ~10 lines" exhibit).
2. proto + validator + interpreter + testvec coverage.
3. symex aliasing (the long pole) + the adversarial test.
4. C/eBPF, Lua, then `gen p4`.
5. Re-transcribe the two switch.p4 lookahead sites — the diff
   (3 deleted invented types, restored 1:1) is the motivating
   exhibit.

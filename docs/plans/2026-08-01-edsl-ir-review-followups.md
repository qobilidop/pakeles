# eDSL/IR design-review follow-ups — idea capture

**Status: notes, not a charter.** Captured 2026-08-01 from the
state-of-the-art design review (whose phases 1–5 shipped the same day:
`40f9e56`…`199a839` — semantics spec, inline targets, exhaustive
defaults, `header()` families, source locations) and the
`p4lang_switch_parser` pressure test that followed. Execution of
everything below is future work; nothing here is committed-to beyond
what its section says.

## The pressure-test verdict (context for everything below)

`p4lang_switch_parser.py` was compared line-by-line against the P4_14
original (`p4lang/switch` @ 7874f565, `p4src/includes/parser.p4`) and
the 2017 P4_16 translation (jafingerhut/p4lang-tests
`v1.0.3/switch-2017-03-07/out1/switch-translated-to-p4-16.p4`, the
form ParserHawk benchmarks against).

Where pakeles already wins (language-controlled dimensions, all of
them): dispatch-table abstraction (`_ethertype_arms()` vs the
`PARSE_ETHERTYPE` CPP macro — which the P4_16 translation *loses*,
expanding into 4 copy-pasted bare-literal arm lists), labeled values
feeding both dispatch and display, decomposed multi-key selects (which
*surfaced* the source's ihl=0 routing-protocol quirk that the packed
`0x506`-style literals hide), explicit reject reasons where P4_14 has
implicit parse exceptions, docstrings that flow to IR/docs/dissector,
and `pakeles lint` mechanically finding the 16 dead states that took
p4v/bf4-class research tooling to report.

Where P4 still wins — three construct gaps, each visible as a
transcription scar:

1. **Header stacks** (`vlan_tag_[2]`, `mpls[3]`, `int_val[24]`):
   slot identity lost (shared instance), MPLS hand-unrolled with
   invented names, int_val's exact-24 cap weakened to a max_depth
   budget.
2. **Lookahead** (`current(0,4)` / `lookahead<bit<4>>()`): the
   nibble-split emulation costs 4 invented header types, a
   4/44-bit split of `dst_addr`, and rerouted continuations —
   distortion that reaches *observable output* (dissector/docs), not
   just authoring.
3. **>64-bit fields** (`bit<128>`, `bit<320>`): IPv6 addresses as
   anonymous `var_bytes(16)` (no display name, no IPV6 format — the
   `DisplayFormat` exists but `var_bytes()` can't carry it); RoCE
   GRH chopped into 64-bit words.

Raw size: ~a wash vs P4_14 (pakeles carries display + docs neither P4
has). Verdict: ahead on everything the *language* controls; behind on
those three *constructs*.

## Idea 1 — `lookahead` IR primitive (the big one)

**Proposal (user, this session): an extract-like op that binds fields
and drives selects exactly like `extract`, but does not advance the
cursor.** Agreed direction: IR-level, not eDSL desugaring — the
nibble-split desugar manufactures `Rest` types whose distortion is
observable (split fields in dissector output, invented types in docs,
rerouted graphs), while the primitive restores 1:1 source
correspondence and lets continuations extract the *real* full types.
Also closes a named P4-16 parity box (`lookahead` is core P4 the IR
can only emulate today), and generalizes the gibb "pseudo-field
lookahead" pattern that was previously handled zero-IR — the flagship
benchmark needing 4 invented types is the demand signal that changed
that call.

Design points settled in discussion:

- **Semantics**: one new spec rule, E-Peek = E-Fixed minus the cursor
  update. Reads bounded by `min(top(R), |π|)` with the same two-class
  reject taxonomy (past region end = structural `out of region
  bounds`; past input = truncation `out of bounds` — matches P4's
  lookahead-errors-on-short). Termination untouched: a peek-only
  cycle still burns depth budget; max_depth stays the sole authority.
  Regions untouched (cursor doesn't move, `c ≤ top(R)` preserved).
  W7 def-use counts a peeked instance as a definition, unchanged
  machinery. Same-state sequencing: extracts run in declared order; a
  peek simply doesn't advance the cursor for its successors
  (extract-then-peek in one state = `parse_lisp` verbatim).
- **IR shape**: `bool peek = 3` (name TBD, below) on the existing
  `Extract` message — reuses instance/env/def-use wholesale.
- **v1 restriction**: peeked header types must be all-fixed-width (no
  `var_bytes` under a peek; validator rule). Every known use case is
  a small fixed peek; lift only on real demand.
- **Naming — DECIDED 2026-08-01: `lookahead`.** The original proposal
  was `assume`; review pushback stood: in verification vocabulary
  `assume` means constraint-injection-without-checking (assume/assert
  duality), and this op is a checked, rejecting read — a collision
  that hurts exactly the symex-literate audience. `lookahead` is
  P4's own term (`gen p4` emits it verbatim); the eDSL builder
  spelling (`lookahead(...)` vs `peek(...)`) can be settled at
  implementation time.
- **The cost center is symex.** Field-variable encoding (the
  2026-07-28 perf win) assumes distinct field variables cover
  disjoint wire bits. A peeked nibble and the first 4 bits of the
  subsequently extracted header are the *same bits* as two variables
  — without per-path aliasing constraints (offsets are known within a
  path, so "peeked field ≡ slice of overlapping downstream fields" is
  an equality set), symex would emit inconsistent witness packets and
  unsound agreement claims. Doable, but touches the perf-critical
  engine; scope it FIRST. Adversarial test case:
  peek-then-branch-then-extract-different-types.
- **Cheap everywhere else**: interpreter (read, don't advance), C/eBPF
  (same bounds check, no offset bump), Lua (overlapping tree items
  are normal), P4 backend (native `lookahead` — a refusal-marker
  direction reversed).
- **Staged plan**: (1) design note + E-Peek spec rule + W-rule (the
  "semantics framework absorbs a new primitive" exhibit, paper
  material); (2) proto + validator + interpreter + testvec; (3) symex
  aliasing — the long pole, with fallback: ship eDSL surface
  desugaring to nibble-split, flip the desugar target to the IR op
  when symex is ready; refusal markers per backend until then;
  (4) C/eBPF, then `gen p4`; (5) re-transcribe the two switch.p4
  lookahead sites — the diff (3 deleted invented types, restored 1:1)
  is the motivating exhibit.

## Idea 2 — `fixed_bytes()` + display metadata on byte runs (small, do early)

`var_bytes()` takes no display arguments, so `src_addr =
var_bytes(16)` renders anonymous — the most common wide field in
networking (IPv6 addresses) loses its name and its `IPV6` display
format, which already exists in the proto unreachable. Add display
name/format/doc parameters, plus a `fixed_bytes(n, ...)` alias for
constant lengths (`var_bytes(16)` reading as "variable" is itself a
wart). eDSL + docgen only; trivial; independent of everything else.

## Idea 3 — header stacks: WITHDRAWN as a feature (documentation item only)

**Revised 2026-08-01 after user challenge ("our output already shows
the header sequence — why do we need stacks?"), which was correct.**
An earlier draft of this section proposed `StackSpec` + `unroll`
machinery; decomposing what P4 stacks actually provide dissolved it:

- (a) *Repeated headers in output*: ALREADY FULLY HAVE — the header
  list records every extraction in order (QinQ yields both tags'
  values under the shared instance; int_val appears up to 24 times;
  testvec compares the whole sequence). The pressure-test claim
  "slot identity lost" overstated an addressability nit into an
  output gap.
- (b) *Bounded looping*: already have (cyclic states + max_depth) —
  the more honest encoding than P4's hidden `next` counter
  (counters-become-states; the W8/max_depth precedent).
- (c) *Exact-count caps* (mpls[3] rejects a 4th label): expressible
  by unrolling, which post-Phase-4 is a ~6-line plain-Python family
  loop with `.named()` — no new machinery warranted.
- (d) *Post-join `last`/earlier-slot access*: not directly
  expressible and W7 is RIGHT to forbid it (path-dependent at the
  join); the metadata-copy idiom in the loop body covers it visibly.
  No target has ever needed it.
- (e) *Deparser order / match-action slot addressing*: the reason
  stacks are IR objects in P4; no pakeles counterpart exists to
  serve.

**What survives**: a documentation item — record the three canonical
patterns (shared-instance repetition; exact-count via family-loop
unroll; last-via-metadata) so future transcriptions don't re-derive
them. Do NOT rename `vlan_tag_` to slot instances (IR/vector churn
for near-zero gain). Keep `int_val` cyclic regardless: exact-count
unrolling would take switch.p4 from 56 to 79 instances, past the
64-bit verdict-bitmap tier (a 128-bit tier is the recorded cost if
some future target demands exact-count on a big stack).

**Scorecard correction**: the P4-vs-pakeles construct gaps are TWO
(lookahead — primitive decided; wide values — boundary decided), plus
a stacks entry that reads "different encoding, same observables; P4
wins only on post-join last-access, which nothing uses."

## Idea 4 — the wide-value boundary: match vs compute, not width tiers

From the follow-on discussion (2026-08-01). Three options were weighed
for >64-bit fields:

- **Width-tiered IR versions (PakelesIR32/64/128): rejected.** Width
  is a per-field derived property here, not a machine-global
  parameter (the RV32/RV64 analogy fails); a declared tier can drift
  while a derived profile cannot; tiers fork the one-spec/one-
  mechanization story and walk the ONNX-opset road. The instinct's
  mature form: **formalize the derived capability report** —
  `pakeles lint` emits per-program demands (max computed-value width,
  max select-key width, sized regions, instance-count tier), backends
  declare envelopes, refusals become mechanical mismatches (the
  existing LUA-/P4-UNSUPPORTED culture, systematized).
- **"Smart" >64 compilation: half-realistic, and the half is the
  point.** Comparisons decompose cheaply everywhere (eBPF: u64-pair
  masked compares, exactly hand-written XDP's IPv6 idiom; Lua: byte-
  string compares work at ANY width even though numerics die at 2^32
  — byte matching is MORE portable than wide numerics; Z3: native
  BV128; testvec: bytes_hex exists). Arithmetic does not (carry
  chains, Lua-impossible, spec value-domain rewrite) and has zero
  demand in the whole corpus.
- **Adopted boundary: "wide bytes may be matched, never computed."**
  (a) Now: `fixed_bytes` + display (Idea 2) plus one committed spec
  sentence — the value domain is Z_2^64 by design; wider fields are
  opaque byte runs. (b) Parked with a ready shape: bytes-valued
  keyset entries (equality + masked) for selects only, per-backend
  lowering as above, expression grammar untouched — only if a target
  ever dispatches on a wide field (realistic candidate: parser-level
  IPv6 prefix routing). (c) Wide arithmetic: committed refusal.

## Non-goals decided in review

- **Do not structurally modernize `p4lang_switch_parser.py`.** The
  1:1 state-per-method ↔ P4-state correspondence is the audit asset
  of a transcription benchmark. Shared targets (`parse_set_prio_med`,
  ~20 inbound arms) must stay named methods regardless.
- **Keep its `default=accept()` on exhaustive `bos` selects** — the
  source writes `default: ingress`; Phase 3 omission would substitute
  a synthesized reject and be *less* faithful.
- **Imperative/AST-rewritten eDSL surface: rejected permanently**
  (re-affirmed; see the 2026-08-01 review session).

## Parked / optional

- **R5**: carry `intrinsic_metadata.priority` as declared metadata in
  the switch.p4 transcription (~20 arms become meaningful assigns).
  Deviates from the clean "all set_metadata is match-action interface
  state" rule; churns 93k vectors. Only if the paper wants the richer
  oracle claim.
- **Alignment-gap validator strengthening** (from the semantics spec,
  §2): a region-depth-style fixpoint over cursor mod 8 could turn the
  "specification fault" class into a static error.
- **Compat policy**: deferred until the stable-release push (still).
- **Lean 4 mechanization**: after the arXiv draft (still). Keep spec
  rules translation-friendly.
- **`annotations["src"]`**: only with a path-canonicalization story;
  diagnostics-only locations shipped in `199a839`.
- **Lua 200-local backend fix**: already recorded in the
  p4lang_switch_parser README; batch ProtoField declarations.

## Publication nuggets from the pressure test

- The P4_16 translation of switch.p4 is defective: `parse_int_header`
  carries two `default:` arms back-to-back (second silently dead),
  and it drifted from the shipped source (`parse_geneve` 3 arms +
  added default vs. the original's 1 arm + parse-exception;
  `parse_vxlan_gpe` matches flags). "ParserHawk benchmarks against a
  translation that is neither the shipped configuration nor
  semantically clean" — and the transcription pinned to P4_14 final
  is the defensible baseline.
- The macro story: P4_14's `PARSE_ETHERTYPE` CPP macro vs. its
  4×-copy-paste fate in P4_16 vs. typed arm-dict helpers — the
  cleanest single exhibit for "host-language leverage".
- Decomposed select keys surfacing the ihl=0 quirk the packed
  literals hide: notation as bug-finder.
- E-Peek (if adopted): the semantics doc absorbing a new primitive in
  ~10 lines — the "designed around a spec" claim made concrete.

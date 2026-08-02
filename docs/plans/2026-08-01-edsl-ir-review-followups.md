# eDSL/IR design-review follow-ups — idea capture

**Execution status (2026-08-01, same day):** the committed refinement
arc SHIPPED — Idea 6 (bit-uniform IR, 0.2.0) + Idea 2
(`fixed_bytes`/display) + the Idea-5 survivor (demoted alignment
analysis as codegen aid + derived demands in `pakeles lint`) landed
in one commit; Idea 1 (`lookahead`, E-Peek + W9 + all backends +
symex aliasing) and the switch.p4 re-transcription (observationally
identical suite: 93,727 vectors, 3 invented types deleted) landed
next. See docs/designs/2026-08-01-bit-uniform-ir.md and
docs/designs/2026-08-01-lookahead-primitive.md. Ideas 3b (caps) and
4b (bytes-valued keysets) remain trigger-gated as recorded below.

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

### Idea 3b — per-instance extraction caps (specified; build on trigger)

User proposal (2026-08-01): a declared cap on repeated extraction,
replacing unrolls for exact-count semantics. **Philosophically
admitted** where stacks were not — the sharpened principle is
"counters may BOUND, never BIND": P4's `next` binds (slots,
addressing — rejected); a cap only converts the (N+1)th extract into
a reject, exactly max_depth's shape (a budget nothing can extend;
termination authority untouched). Design points:

- **Per-INSTANCE, not per-type** (user's per-type framing has a
  switch.p4 counterexample: `Icmp` type is shared by `icmp` +
  `inner_icmp` — a type cap of 1 would wrongly reject the inner).
  Proto: parser-level `map<string, uint32> instance_caps`. Spec: one
  premise on E-Extract + a new normative reject reason + per-capped-
  instance counters in the configuration (~5 lines).
- **Cheap everywhere**: interp = counter map; C/eBPF/Lua = counter +
  compare; symex = path-space PRUNING (counts are path-prefix-
  determined — no solver work, unlike lookahead). Open question:
  `gen p4` fidelity = recognizing capped cyclic loops as `header[N]`
  stacks (or an initial refusal marker).
- **Use-case survey is thin**: TLV loops → sized regions (right
  tool); layered encaps → structural states; global bounds →
  max_depth. The only residents are P4-stack-style same-instance
  loops: `mpls[3]` + `int_val[24]`. Payoff there is real: int_val's
  documented cap deviation disappears, parse_mpls collapses to ONE
  cyclic source-named state, transcription = 62 states (source's 63
  minus folded start), no bitmap blowup.
- **DECISION: specified now, built only on a trigger** — (i) a
  real_world target with an incumbent oracle exhibiting per-count
  rejects (a proper MPLS/tunnel target), or (ii) the publication
  pass valuing full-fidelity switch.p4 as an exhibit.

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

## Sequencing decision (2026-08-01)

**Lookahead-first; publication pass after** the repo refinements.
Rationale: the paper case strengthened today (spec section exists,
design-principles trio, switch.p4 three-way comparison), and
lookahead's payoff includes paper exhibits (E-Peek + the
re-transcription diff) that should exist before the draft freezes.
Suggested early tasks inside that arc: the W9 alignment analysis
(below) — it touches the same validator/spec files and E-Peek's
fixed-width restriction composes with it.

## Idea 5 — SUPERSEDED by Idea 6: the alignment gap dissolves under bit-uniformity

(Original W9 plan, kept for the record: a W8-shaped static analysis
over cursor mod 8 — data-independent because fixed widths are
constants and `var_bytes` moves whole bytes — with a strict
one-alignment-per-state variant vs a demand-driven set variant,
decided empirically over the gallery.) **Superseded 2026-08-01 by the
user's bit-uniform IR proposal (Idea 6): closing the fault class by
GENERALIZATION (every op defined at every cursor) beats closing it by
RESTRICTION (rejecting programs that could misalign) — definitional
totality needs no analysis at all.** The alignment analysis survives
DEMOTED to where it belonged: a codegen optimization (provably-
aligned sites emit byte loads — the eBPF verifier's preference) and a
derived capability ("requires misaligned runs") for backend
envelopes. Soundness never depends on it.

## Idea 6 — bit-uniform IR (user proposal, ADOPTED; first item of the refinement arc)

**Decision (2026-08-01): re-denominate the three byte-typed
constructs — `byte_len` widths, region push lengths, `remaining()` —
to BITS.** Pakeles is already bit-addressed everywhere else (cursor,
fixed fields at any offset, BitString inputs, consumed_bits); this
removes the last byte-denominated island and with it the entire
alignment-fault class, the `8 | c` premises on three spec rules, and
the never-built W9. Precedent: this is the P4_14→P4_16 move (P4_14
header lengths were BYTES; P4_16 went bits for varbit/advance/
lookahead) — the direction the careful second system chose.

- **Frontend stays unit-explicit, NOT unit-uniform** (the one
  refinement to "all-in"): wire formats speak bytes, and P4-16's
  bit-uniform surface has a known forgot-the-×8 papercut class. Keep
  `var_bytes(n)` as sugar for `bit_len = n*8`, add `var_bits(n)`;
  `push_region(bytes=…)`/`(bits=…)`; `remaining_bytes()`
  (= `rem >> 3`, exact for byte-multiple regions) /
  `remaining_bits()`. Gallery .py files unchanged → goldens
  regenerate mechanically.
- **Costs, staged**: backends handle-or-refuse misaligned runs via
  the capability envelope (no existing program misaligns; aligned
  programs codegen identically, guarded by the demoted analysis);
  opaque values become bit strings (testvec's BitString is already
  the canonical form; FieldValue/ExpectedField gain bit lengths);
  proto `byte_len`→`bit_len` + ir_version bump + full regen
  (pre-1.0, no compat promise); symex cursor arithmetic ×1 —
  mechanical, field-variable encoding untouched (opaque runs bind no
  key values).
- **Demand**: BGP NLRI is the recorded bit-granular-lengths case
  (length-in-BITS then ceil(len/8)) — this pre-unblocks the standing
  second-pick target; also closes the denominational parity nit vs
  P4-16 and lets E-Peek be specified once, alignment-condition-free,
  on the new base.
- **Sequencing**: FIRST item of the lookahead-first arc (churn-heavy,
  design-light — land it before layering lookahead's rules on top).

## Follow-up opened 2026-08-01: convert the gibb nibble-splits to `lookahead`

The first-ever BMv2 run of `p4lang_switch_parser` (see its README)
showed that a 4-bit header type makes `gen p4` output uncompilable by
`p4c-bm2-ss`, whatever else is true of it. Four academic members still
carry the pre-`lookahead` nibble-split emulation and so emit
BMv2-uncompilable P4: **gibb_big_union, gibb_edge,
gibb_service_provider, kangaroo_parse_tree** (all `mpls_payload_nibble`,
4 bits; gibb_big_union also has `eompls_rest`, 28 bits). None has a
BMv2 conformance test, which is why it was never noticed.

`pakeles lint` now reports this as a derived demand rather than
refusing (a codegen refusal would break four members' committed
artifacts over what is really a transcription choice). Converting them
to the primitive — the same mechanical edit switch.p4 just had — would
delete their invented `*Rest` types AND make their P4 BMv2-compilable,
after which each should gain a BMv2 conformance test. Deferred because
re-transcribing published-benchmark members changes their README
comparison numbers and deserves its own audit pass.

**General rule this exposed:** a committed `gen/parser.p4` with no BMv2
conformance test is unverified — "generates" is not "compiles". The
cost of the test is small (13,599 vectors in ~14 s, one
`simple_switch` spawn).

## Parked / optional

- **Testvec design revisit** (user-flagged 2026-08-01, "not now"): a
  dedicated pass over the vector schema — at minimum compare
  `consumed_bits` (computed by the interpreter, present in C/eBPF
  output structs, currently uncompared — backends could agree on
  outcome while consuming differently, undetected); also weigh
  reject-time forensics (stop state/instance/field/offset) and
  whatever the lookahead work surfaces. Check the XDP verdict path's
  consumed reporting before committing.
- **Symex aliasing design for lookahead**: deliberately deferred to
  the lookahead execution session (argue it with the pathid code
  open, not speculatively).
- **Capability report formalization** (from Idea 4): derived
  per-program demands vs declared backend envelopes, tightening spec
  §6 and systematizing the refusal-marker culture. Low priority;
  nothing blocked on it.
- **R5**: carry `intrinsic_metadata.priority` as declared metadata in
  the switch.p4 transcription (~20 arms become meaningful assigns).
  Deviates from the clean "all set_metadata is match-action interface
  state" rule; churns 93k vectors. Only if the paper wants the richer
  oracle claim.
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

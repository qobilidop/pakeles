# Slice 2 design: the oracle factory

Date: 2026-07-19. Extends `2026-07-18-pakelesir-v0-design.md`. High-level
decisions settled in discussion with the project owner; low-level design
delegated. Deliverables: symbolic engine over the IR, `testgen`, `lint`,
`cov`, path-sensitive validation.

## Decisions from discussion (owner-approved)

1. **Path semantics: arm-level**, with truncation and reject paths
   first-class, category-tagged. "One path" = one sequence of arm
   choices (first-match-wins: arm *i*'s condition includes negations of
   arms 0..*i*−1; default = all negated). Value-partition/boundary
   enrichment is a future `testgen` option, not path semantics.
2. **Witnesses: raw z3 model with model completion.** No filler policy,
   no minimization, no post-processing. Minimal packet length (exactly
   the bits consumed; truncation vectors shorter by construction).
   Consequences accepted: unconstrained regions are effectively zeros
   (offset-bug blind spot until a counter-fill refinement); model drift
   across z3 versions handled by **committed-artifact discipline** —
   vectors regenerate only deliberately, diffs reviewed. Deferred
   refinements on record: counter-pattern filler, canonical witnesses.
3. **Vector format: proto-defined.** `pakeles.testvec.v1alpha1`,
   `TestSuite`/`TestVector` messages, protojson on disk, hex-string
   packet data (Wycheproof-style, for reviewable git diffs). Naming
   grounded in prior art: crypto test vectors (NIST/Wycheproof), EDA
   stimulus/response, ONNX conformance data.
4. **`BitString` input type**, defined *inside* the testvec package
   (proto is the wire boundary only; Rust-native types internally; lift
   to a shared package only when a second proto consumer appears —
   breaking moves are licensed by v1alpha1). Semantics: finite bit
   sequence, `{data_hex, bit_len}`, bit-granular length (matches the
   interpreter's bit-granular core; ASN.1 BIT STRING precedent).
   **Canonicalization**: canonical form is exactly ceil(bit_len/8)
   bytes, unused trailing low bits zero (MSB-first). Readers
   canonicalize (pad short / truncate long / zero pad bits) and never
   error; writers emit canonical only; lint warns on non-canonical.
5. **Solver: z3 crate first, behind a thin trait.** Long-term dream is
   solver-agnostic benchmarking; rsmt2 deferred (maturity); a
   pysmt-like Rust library is a noted dream, not scope.

## Low-level design (delegated decisions)

- **Layout concretization.** Variable-length fields make downstream
  offsets symbolic. The engine forks on the *length value*: enumerate
  feasible values of the length expression via all-SAT with blocking
  clauses (hard cap 1024 values; exceeding the cap is an engine *error*,
  never a silent truncation). Each fork pins `L == v`, making every
  field offset concrete per path. Completeness is preserved because
  length exprs depend only on fixed-width (≤64-bit) extracted fields.
  With concrete layouts, a path's symbolic state is just: packet as one
  bitvector, each field = Extract(packet, concrete range).
- **Truncation forks**: per extracted field per path prefix, a path with
  `bit_len = field_offset + field_len − 1` (fails reading exactly that
  field). Complete, not sampled; volume at current scale (~10² vectors
  for eth_ipv4_tcp) is fine. Infeasible-length branches (e.g. ihl ≤ 4
  wrapping the options length) surface naturally as REJECT-category
  `out of bounds` paths — semantically rejects, not truncations.
- **Path IDs** (stable across regeneration, diff-friendly):
  `state/armN` or `state/default` segments joined by `→`-less `/`;
  length forks append `state.field=Nb`; truncation vectors are the
  parent prefix + `!trunc@instance.field`.
- **Expected outputs** are produced by running the reference interpreter
  on each witness — the suite is self-checking against the normative
  semantics by construction, and CI verifies committed vectors by
  re-running the *interpreter* (stable), never by re-running the
  *solver* (drifts).
- **Solver trait** (deliberately minimal, not a pysmt): the engine
  compiles path conditions to a small internal constraint form
  (extract-of-packet compared to value/mask/range, plus the IR's
  arithmetic operators); the trait is `check(bit_len, &[Constraint]) →
  Unsat | Sat(bytes)` plus an all-values query for length enumeration.
  z3 is the only implementation in this slice.
- **`lint`** falls out of enumeration: states no feasible path reaches,
  arms whose condition (with first-match negations) is UNSAT
  (shadowed/unsatisfiable), plus the BitString canonical-form warning.
- **`cov`**: the interpreter gains an optional trace (sequence of
  (state, arm) decisions); `cov` maps each pcap packet to its path ID
  and reports exercised vs. total paths.
- **Path-sensitive validation** (retires slice-1 debt): solver-free
  dataflow — intersection-over-predecessors fixpoint computing instances
  definitely extracted on every path to each state; select keys and
  length exprs may only reference those.
- **Build**: `z3` crate as an optional dependency behind the `symex`
  cargo feature, **on by default** (feature exists for opt-out
  embedders); devcontainer gains `libz3-dev` + `libclang-dev` (bindgen).

## Non-goals (this slice)

Equivalence checking (the machinery lands here; the command comes with a
second implementation to compare), boundary-value enrichment, filler
policies, canonical witnesses, solver benchmarking, `gen`/`doc` commands.

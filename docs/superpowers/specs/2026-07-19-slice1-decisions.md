# Slice 1 design decisions

Date: 2026-07-19. Resolves two open questions from
`2026-07-18-pakelesir-v0-design.md` and records two semantics choices
made during implementation. All are encoded in `ir.proto` and the
reference interpreter; this note is the rationale.

## 1. Automaton encoding: explicit state graph (question closed)

Chosen over structured bounded loops. The parser is a flat list of named
states with guarded transitions; cycles are legal and bounded by a
mandatory parser-level `max_depth` (states entered). Rationale: 1:1
correspondence with P4's parser sublanguage (the ceiling principle, and
the future P4 frontend/backend map trivially); Leapfrog-style automata
tooling and the slice-2 symbolic engine both want the graph form;
the visualizer falls out naturally. A structured-loop *view* can be
derived later if composition wants it — it is not stored. Per-header-
stack bounds join the schema when header stacks land.

## 2. Slice-1 operator inventory (question opened-and-scoped)

Expressions: leaves `constant` (u64) and `field` (header-instance ref);
binops `ADD SUB MUL SHL SHR AND OR`, wrapping u64 semantics. Select
keysets: `value`, `masked` (match iff `key & mask == value & mask`),
`range` (inclusive). Comparison deliberately lives only in select
keysets, not general predicates — P4-shaped, and what slice-2 symbolic
execution wants. The inventory grows under protocol pressure; it never
shrinks (v1alpha1 lets us correct mistakes until promotion to v1).

## 3. Extraction semantics

Fixed-width fields: big-endian (network order), MSB-first at bit
granularity, ≤64 bits, valued as u64. Variable-length fields: opaque
byte runs, length in bytes computed by expression over previously
extracted fields, must start byte-aligned (interpreter enforces).
Reject reasons are part of the normative surface: `out of bounds`,
`max depth exceeded`, `no matching select arm` (only when a select has
no default), plus description-authored reasons.

## 4. tshark diff scope (slice-1 boundary, not a decision for all time)

Only fields annotated `tshark.key`, only numeric renderings (`0x…` hex
or decimal). Address-typed fields (`ip.src` renders dotted-quad) are
not comparable yet — typed rendering is annotation-layer work that
lands with the dissector backend in slice 3. Reject-outcome packets are
skipped in the diff: tshark best-effort-dissects malformed input, and
matching that behavior is precisely diagnose mode (slice 3).

## Deliberate simplifications carried as debt

- Validation checks field-ref *existence* (instance extracted somewhere,
  field exists on its type) but not path-sensitive extracted-before-use;
  slice 2's reachability analysis tightens this.
- `Extract.instance` exists in the schema but the builder always uses
  the default; header stacks (`instance` + next-index) are future work.
- One packet = one parse; no projections yet (slice 2+).

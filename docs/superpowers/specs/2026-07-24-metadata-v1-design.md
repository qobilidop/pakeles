# Metadata v1: read-write parse metadata

**Date:** 2026-07-24
**Status:** design approved; implementation pending
**Consumer:** flow-dissector rung 4a (`2026-07-24-flow-dissector-rung4a-design.md`) — but the capability is IR-wide, not flow-dissector-specific.

## Motivation

Two forces converged:

1. **The in-IR projection trigger fired.** The north-star design deferred an
   in-IR projection construct with an explicit trigger: "harness-projection
   drift — revisited if it bites." Rung 4 makes it bite: `is_encap` cannot be
   robustly *inferred* from trace shape (GRE sets it with no second IP layer;
   mixed-family tunnels defeat per-instance counting), so the harness would
   have to hand-mirror the kernel's tunnel rules with only the golden gate
   policing drift. Metadata assignment moves that one bit into the parser
   program, where the reference implementation (`bpf_flow.c` setting
   `keys->is_encap` in its case arms) literally puts it.
2. **P4-parity ambition.** The project bar is now: at least as expressive as
   the P4-16 parser, and more where it counts. P4-16 parsers permit
   assignments, read-write user metadata, and `select` on arbitrary
   expressions — but the spec guarantees nothing about termination (loop
   bounds are target-dependent folklore). Closing the metadata gap makes
   Pakeles "the P4 parser surface, decidable by construction": a TLV walk
   (extract option → `remaining -= len` → select on `remaining`) becomes a
   first-class bounded loop with `max_depth` in the schema and a symex
   witness per path.

Read-write (not write-only) was a deliberate call: termination never depended
on write-only-ness — `max_depth` alone bounds every run, and reads cannot mint
budget. Write-only bought only slightly simpler symex, while even write-only
metadata needs a symbolic store (witnesses must predict outputs). The marginal
cost of reads is letting `Select` keys resolve metadata references; crippling
the model would buy almost nothing.

## Invariants (schema-level law)

1. **`max_depth` is the sole termination authority.** Metadata may steer
   control flow (select keys, region sizes) but never extends the budget; the
   budget is spent by state entries only. Same shape as the kernel:
   `bpf_flow.c` mutates `keys->*` freely under an indifferent tail-call limit.
2. **Declared and typed only** — fixed-width unsigned scalars, 1..64 bits
   (same ceiling as fixed header fields). No byte-run metadata, no strings.
3. **Deterministic initialization** — every field starts at a declared init
   value (default 0); a parse result stays a pure function of (IR, packet).
4. **Assignment truncates to declared width** (mod 2^bits); reads
   zero-extend; arithmetic wraps exactly like existing `Expr` evaluation.
   One set of numeric rules IR-wide.

## Schema deltas (`proto/pakeles/ir/v1alpha1/ir.proto`)

```proto
message Parser {
  // ...existing fields 1-5, annotations 15...
  repeated MetadataField metadata = 6;      // NEW: declared, typed, ordered
}

message MetadataField {
  string name = 1;
  uint32 bits = 2;                          // 1..64
  uint64 init = 3;                          // default 0
  Display display = 4;                      // presentation only, as ever
  map<string, string> annotations = 15;
}

message State {
  string name = 1;
  repeated Extract extracts = 2;
  Transition transition = 3;                // unchanged number
  repeated Assign assigns = 4;              // NEW: ordered, run after extracts
  map<string, string> annotations = 15;
}

message Assign {
  string metadata = 1;                      // must name a declared MetadataField
  Expr value = 2;
}

message Expr {
  oneof kind {
    uint64 constant = 1;
    FieldRef field = 2;
    BinOp bin = 3;
    MetadataRef metadata = 4;               // NEW
  }
}

message MetadataRef { string name = 1; }
```

`State.transition` keeps its field number; `assigns` takes the next free slot
(serialization is name-based `ir.json`, but there is no reason to renumber).

Because `Select.keys` and `FieldWidth.byte_len` are already `Expr`, **branching
on metadata and sizing regions from metadata fall out with zero changes to
those messages**. That orthogonality is the point of the design.

**Assignment placement — the judgment call.** Assignments live in the state
body (P4-style), never on edges, even though `bpf_flow.c` sets `is_encap` in a
`case` arm. Kernel-shaped edge effects are expressed with **no-extract
pass-through states** (already schema-legal): `proto 4 → "ipip"
[assigns is_encap=1] → parse_ipv4`. This mirrors the C structure (each case
arm is a mini-state), keeps assignments in exactly one grammatical position
for validator/interp/backends/symex, and maps 1:1 onto P4 codegen. Cost: a
pass-through state spends one `max_depth` unit; consumers budget for it.

## eDSL surface

```python
class FlowMeta(Meta):
    is_encap = meta_bits(1)

parser(
    "linux_flow_dissector",
    metadata=FlowMeta,
    states={
        "ipip": assign(FlowMeta.is_encap, 1).goto("parse_ipv4"),
        # future TLV shape (not built in this slice):
        # "opt": extract(TcpOpt)
        #        .assign(FlowMeta.remaining, FlowMeta.remaining - TcpOpt.length)
        #        .select(FlowMeta.remaining, {0: "parse_done"}, default="opt"),
    },
)
```

Mirrors the `Header`/`bits` declaration idiom; `assign(...)` chains onto
`extract(...)` the way `.select(...)` does.

## Execution semantics

Within a state: **extracts → assigns (declared order; later assigns see
earlier writes) → transition.** Assignment RHS may reference any metadata and
fields extracted in this or earlier states. Assignments are total — width
truncation and wrapping arithmetic, no failure mode — so reject semantics are
untouched: rejects still come only from extraction (oob) and select-default,
preserving rung-3 oob reasoning.

**Result surface:** interp result gains `metadata: {name → u64}` (final
values). Testvec `Expected/Accepted` gains the same. On reject, metadata is
not compared (kernel analogy: no flow keys exported on drop).

## Backends

- **interp**: u64 store, truncate-on-write.
- **C / eBPF**: result struct gains the declared fields; assigns compile to
  statements.
- **P4**: user metadata, natively — the backend that validates the model's
  realism.
- **Lua/Wireshark**: computed as locals; final values rendered as a
  generated-info subtree so the conformance accept-branch comparison can see
  them.
- **symex**: symbolic store per path; assignments compose `Expr`s by
  substitution (no fixpoints — paths are finite by `max_depth`);
  select-on-metadata substitutes the store into the path condition; witnesses
  carry expected final metadata. Deepest touch; the symbolic-layout rework's
  one-witness-per-path structure is the intended substrate.

## Validation rules

- Assign target must name a declared `MetadataField`; `MetadataRef` likewise.
- `bits` in 1..64; `init` must fit in `bits`.
- Duplicate metadata names rejected.
- (Unchanged) `max_depth` mandatory; no metadata-dependent exemption exists.

## Testing this slice

A dedicated toy example — the metadata analog of `eth_ipvx_l4` — ships with
the slice and runs the full loop: eDSL → `ir.json` → validator error cases
(undeclared name, width range, init overflow) → interp → all four codegens →
symex witnesses → conformance. It exercises **both** paths: a constant write
on one arm (the rung-4a shape) and an accumulator loop with a select exit
(the TLV shape), so read-path semantics are tested before any gallery example
depends on them.

## Rejected alternatives

- **`encap()` as an IR construct** (domain marker on edges): bakes tunnel
  vocabulary into a domain-neutral schema; metadata subsumes it (`is_encap`
  becomes the program's vocabulary, not the IR's).
- **Explicit encap/subparser node** with scoped instances and per-level caps:
  full-toolchain change expressing control flow that back edges already
  express; invents scoping the reference implementation doesn't have; nothing
  in the kernel-agreement gate exercises what it uniquely provides.
- **Write-only metadata**: see Motivation — the invariant was doing no
  termination work and blocking the P4-parity/TLV ambition.
- **`var_bits` now**: bit-granular dynamic regions are the more principled
  unit (the IR is bit-addressed everywhere else; P4 `varbit` is bit-granular)
  but have zero drivers — the whole kernel ladder is byte-aligned. Deferred:
  `FieldWidth` is a proto3 oneof, so a `bit_len` arm is additive and
  non-breaking; trigger is the first bit-oriented example (codec bitstream /
  compressed headers), where bounded-loop guarantees would out-express real
  P4 targets. Budget center when it lands: codegen dynamic-shift paths, not
  the schema.

## Non-goals

- `lookahead` / `advance` (no driver; `Expr`-orthogonality keeps them cheap
  to add later).
- Per-header metadata; metadata in `Reject`; any mechanism by which metadata
  affects the `max_depth` budget.
- Full in-IR flow-keys projection (field-copy assignments replacing the Rust
  projection wholesale) — sanctioned direction, separate future slice.

## Risks

- **Symex store complexity** — first time path conditions relate values
  across loop iterations. Mitigation: substitution-only semantics (pure
  `Expr`s, finite paths), toy-example witnesses gate before rung 4a scales it.
- **Backend output-surface drift** — five artifacts now carry metadata.
  Mitigation: testvec `Expected.metadata` is the single cross-backend
  contract, exercised by the toy example's committed vectors.

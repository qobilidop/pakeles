# Sized Regions + TLV Loops — IR Slice Design

**Status:** design, binding for the TLS ClientHello run (charter:
`docs/plans/2026-07-29-tls-clienthello-charter.md`). This is the
rung-3 leftover (substream/TLV) slice, deferred there because no
kernel driver needed it; TLS ClientHello is the forcing target.

## Motivation

Length-prefixed formats (TLS, and beyond it 802.11 IEs, RADIUS,
BGP attrs) parse *inside a window bounded by a previously read length
field*, and iterate TLVs *until that window is exhausted*. Today the
IR has exactly one bound: the packet end. `var_bytes` can skip a
sized blob but nothing can parse *within* one. The missing construct
is the **sized region**; the TLV loop then falls out of existing
machinery (cyclic states bounded by `max_depth` — rung 4b precedent —
plus a new `remaining()` observable to select on).

This slice is the "more than P4 for TLV" claim from
[[p4-parity-ambition]]: a P4-16 parser can `extract` a varbit blob of
computed length but the blob is opaque — there is no parsing inside
it and no remaining-in-region observable, so TLV-within-sized-region
is inexpressible in a P4-16 parser (short of externs). Our `gen p4`
therefore *rejects* region-bearing IR with a clear error; that
documented boundary IS the parity-plus proof point.

## Constructs

Three additions, nothing else:

1. `RegionOp::Push(len_expr)` — open a region of `len_expr` BYTES
   starting at the current cursor.
2. `RegionOp::Pop` — close the innermost region; exact-mode only
   (cursor must sit exactly at the region end).
3. `Expr::Remaining` — bytes between the cursor and the innermost
   region end (packet end when no region is open).

Region ops are an ordered list on `State`, executed after `assigns`,
before the transition (so a push may reference a length field
extracted by the same state). `max_depth` remains the sole
termination authority — regions never affect the depth budget, they
only shrink the readable window.

## Normative semantics (interp)

State: a region stack of bit-granular ends, initially empty.
`top` = innermost end; `avail` = packet bit length.

- **Push(e):** cursor must be byte-aligned, else `Err` (IR malformed —
  the `var_bytes` precedent). `new_end = cursor + 8*eval(e)` with
  checked math. If a region is open and `new_end > top`: **reject
  "region out of bounds"** (structural: the inner length claims more
  than the outer window). `new_end` is NOT checked against `avail` —
  a region reaching past the buffer is a truncation discovered by
  reads, not a structural lie (this keeps rustls's
  incomplete-vs-InvalidMessage distinction projectable). Wrapped
  `eval(e)` (checked_mul/add overflow) → reject "region out of
  bounds".
- **Reads (both `bits` and `var_bytes`):** bounded by
  `min(top, avail)`. Crossing `top` first → **reject "out of region
  bounds"**; crossing `avail` first → the existing **"out of
  bounds"** (truncation class). When `top > avail` and the read
  crosses both, `avail` wins (it is the smaller bound) — truncation
  class, matching rustls (a truncated buffer inside a declared-long
  record is `incomplete`, not malformed).
- **Pop:** empty stack → `Err` (IR malformed). `cursor < end` →
  **reject "region not exhausted"** (rustls `TrailingData` analog).
  `cursor == end` → pop and continue. (`cursor > end` is impossible:
  reads are bounded by `top`.) Skip-to-end pop mode is deliberately
  NOT in this slice — no current target needs it; add when one does.
- **Remaining:** `(min(top, avail) - cursor) / 8`, at byte-aligned
  cursor (else `Err`). Buffer-clamped so a select on `remaining()`
  can steer truncated packets down a reject arm rather than
  fabricating structural bytes that don't exist.
- Reject reasons introduced: `region out of bounds` (push),
  `out of region bounds` (read), `region not exhausted` (pop) — all
  Error severity, all distinct from buffer `out of bounds`.

## IR schema (proto)

```proto
message State {
  // ... existing fields 1-4 ...
  // Ordered region ops, executed after assigns, before the transition.
  repeated RegionOp region_ops = 5;
}
message RegionOp {
  oneof kind {
    Expr push = 1;  // region byte length
    Pop pop = 2;
  }
}
message Pop {}
message Expr {
  oneof kind {
    // ... existing 1-4 ...
    Remaining remaining = 5;
  }
}
message Remaining {}
```

## Validator

- **Static stack-depth consistency:** dataflow fixpoint assigning each
  state a single on-entry region depth; a state reachable at two
  different depths, a pop at depth 0, or unbounded growth along a
  cycle (net-positive cycle) is a validation error. This yields a
  static max nesting depth K per parser — the backends' array size.
- `Remaining` is legal everywhere (depth 0 = buffer remaining).
- Byte-alignment is a runtime `Err`, as with `var_bytes` today.

## Symex

`Frame` gains `regions: Vec<Term>` (end-bit terms). No solver
vocabulary changes: `Term::Bin` already covers the arithmetic
(`SUB`/`MUL`/`SHR`), and term-vs-term comparison uses the existing
wrap-window `InRange` idiom (both sides bounded by `8*SANITY_BYTES`,
so `sub(a,b) ∈ [1, 2^32]` decides `a > b` exactly — same trick as the
wrapped-`var_bytes` oob split).

- **Push:** fork {structural-overrun reject (only when a region is
  open; constraint `new_end > top` via wrap-window), continue}. The
  continue branch pushes `new_end` and asserts its negation.
- **Reads:** existing buffer-truncation fork unchanged; one NEW fork
  when a region is open: `cursor' > top` → reject "out of region
  bounds". z3 prunes it wherever the enclosing constraints make it
  infeasible (the common case for fixed fields after a checked push),
  so path growth concentrates where real TLV ambiguity lives.
- **Remaining as select key:** term
  `SHR(SUB(min_end, cursor), 3)`; arms constrain it exactly like any
  key. (`min_end`: when both a region end and the packet width can
  bind, emit does the same clamped bookkeeping the interp does; the
  packet-width side is already modeled by cursor_max/witness ladder.)
- **Pop:** fork {`cursor == end` continue, `cursor < end` reject
  "region not exhausted"} — both via the same wrap-window idiom;
  pruned when the state graph makes exhaustion structurally certain.
- **Path budget (TLS shape):** a TLV loop of N iterations with a
  once-only descend arm (SNI) enumerates O(N²) accepts + O(N) rejects
  per family — a few thousand paths at N≈17, well under the 27k/57k
  precedents. Bench with `symex_bench` when the micro-example lands
  (budget: micro-example < 5s release; flagship < 120s release enum —
  else STOP per charter).

## Backends

- **C / eBPF:** `uint64_t region_end[K]; unsigned sp;` with K from
  the validator. Push/pop/remaining compile to compares and
  adds; after state unrolling the verifier sees bounded, constant-
  indexed accesses (katran precedent says this shape passes).
- **Lua dissector:** a Lua table stack, direct transliteration.
- **P4:** `gen p4` fails fast with "sized regions exceed P4-16 parser
  expressiveness" — the documented boundary (see Motivation).
- **docgen/viz:** regions render as nested byte-window annotations on
  states; no semantic weight.

## eDSL surface

```python
from pakeles import remaining, parser, extract, ...

"exts_hdr": extract(ExtLen).push_region(ExtLen.len).goto("tlv"),
"tlv": select(remaining(), {
    0: pop_region().then(...),        # region exhausted -> continue after
    (1, 3): reject("partial TLV header"),
}, default="ext_hdr"),
```

`push_region`/`pop_region` are state modifiers (ordered, post-assign);
`remaining()` is an expression usable as a select key. Exact builder
spelling may adjust to the existing StateBuilder idiom during build.

## Micro-example (regression anchor)

`tlv_items` (gallery peer of `counted_items`): `total_len:u8`,
push region, loop {`remaining()==0` → pop+accept; extract `t:u8`,
`l:u8`, `v:var_bytes(l)`; loop}. Exercises push, pop-exact, remaining
select, per-item region-oob reject, and the O(N²) loop enumeration —
committed with vectors + all backends BEFORE the flagship example.

## Build-time refinements (binding; supersede the sections above where
they conflict)

Discovered wiring symex: the engine deliberately keeps the packet
length OUT of the constraint system (per-path witness lengths come
from the emit-time ladder; constraints only range over field
variables). A buffer-clamped `remaining()` would force `avail` into
the constraints — a whole new solver dimension. Instead:

1. **`remaining()` is STRUCTURAL**: `(top − cursor)/8`, no buffer
   clamp, and it REQUIRES an open region — the validator's depth
   fixpoint rejects `remaining()` at region depth 0 (assigns check the
   state's entry depth; select keys the post-ops depth; push length
   exprs the depth before that op). Buffer-remaining never existed in
   any target's need; a truncated buffer inside a region now surfaces
   at the next read as ordinary truncation, which is exactly rustls's
   `incomplete`.
2. **Avail-free read-failure reasons**: a failing read (or a
   wrapped/oversized var_bytes length) is "out of region bounds" iff a
   region is open and the read's end crosses the innermost region end
   (wrapped lengths cross everything); otherwise it is the
   truncation-class "out of bounds". No comparison with the buffer
   length is involved in choosing the reason.
3. **Pop simplifies**: `cursor < end` → "region not exhausted",
   unconditionally (the end-past-buffer case is unreachable once
   `remaining()` is structural — a short buffer dies at a read first).
4. **Symex read trichotomy inside a region**: {crosses region end →
   reject "out of region bounds", fits region but buffer ends mid-read
   → Truncation (asserts it does NOT cross the region end), fits →
   continue}. Push forks {wrap/oversize → "region out of bounds",
   structural lie vs enclosing (wrap-window compare) → same reason,
   continue}; pop forks {exhausted (Eq diff 0) → continue, shortfall →
   "region not exhausted"}.

## Out of scope (named)

- **Peek/lookahead:** TLS ClientHello does not need it (every branch
  point extracts, none inspects-without-consuming). Finding recorded;
  construct deferred until a target forces it.
- **Skip-mode pop** (pad-to-end formats), **bit-granular regions**,
  **backward pointers** (DNS compression — permanently out, per
  roadmap).

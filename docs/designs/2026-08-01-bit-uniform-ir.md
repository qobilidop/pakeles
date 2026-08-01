# Bit-uniform IR (ir_version 0.2.0)

**Status: shipped 2026-08-01.** Decision record for re-denominating
the IR's three byte-typed constructs to bits, per the adopted proposal
in `docs/plans/2026-08-01-edsl-ir-review-followups.md` (Idea 6, which
superseded the W9 alignment-analysis plan, Idea 5).

## Decision

The IR is now bit-uniform: `FieldWidth.bit_len` (was `byte_len`),
`RegionOp.push`, and `Remaining` are all denominated in BITS, joining
the already-bit-addressed cursor, fixed widths, `BitString` inputs,
and `consumed_bits`. No IR operation carries an alignment
precondition; the spec's "specification fault" run class (a
well-formed program reaching a byte-denominated op misaligned) is
deleted by construction rather than excluded by analysis.

Precedent: the P4_14→P4_16 move (P4_14 header lengths were bytes;
P4_16 went to bits for varbit/advance/lookahead).

## Frontends stay unit-explicit, not unit-uniform

Wire formats speak bytes, and a bit-only surface has a known
forgot-the-×8 papercut class. Both authoring surfaces keep byte-
denominated constructors as ×8 sugar and add explicit bit forms:

- Python eDSL: `var_bytes(n)` ≙ `bit_len = n*8` (a literal
  `mul(expr, const 8)` tree), `var_bits(n)` raw; `fixed_bytes(n, …)`
  for constant runs (with display name/format/doc — the
  `fixed_bytes(16, "Source Address", IPV6)` case); `push_region(n)`
  bytes / `push_region(bits=…)`; `remaining()` ≡ `remaining_bytes()`
  (emits `remaining >> 3`) / `remaining_bits()`.
- Rust builder: `var_bytes`/`var_bits(_full)`, `push_region`/
  `push_region_bits`, `remaining()` raw bits.

The two frontends emit **identical trees** for the sugar (same
`mul(expr, c(8))` shape) so single-source examples stay
cross-language byte-identical. No gallery `.py` changed; all 18
descriptions regenerated mechanically.

## Version gating

`ir_version` bumped 0.1.0 → 0.2.0 and is now **checked first** by
`validate()` (exact match; pre-1.0, no compat promise): a stale
byte-denominated IR fails loudly instead of being re-read with its
lengths ×8 off. Belt to that suspender: `byte_len` field number 2 is
`reserved` and `bit_len` takes number 3, so stale binary/JSON IRs
also fail structurally ("no width" / unknown field).

## Test vectors

`ExpectedField.bytes_hex` (reserved) → `BitString bits = 4`: opaque
run values now carry explicit bit lengths in canonical BitString
form. The interpreter's `FieldValue::Bytes` became
`FieldValue::Bits` (canonical padded bytes; `ParsedField.bit_len`
authoritative).

## The demoted alignment analysis

The never-built W9 static alignment *check* is dead; alignment
survives as a derived, advisory property in `codegen`:

- `expr_mod8` — static residue of a length expression mod 8. Sound
  under wrapping (8 | 2^64 preserves residues through +, −, ×;
  bitwise ops are bitwise; shifts ≥ 3 zero the residue). The
  load-bearing case: `expr * 8` ≡ 0 regardless of `expr`, so every
  sugar-built program is provably aligned end-to-end.
- `entry_alignments` / `field_alignment` — the existing byte-load
  fixpoint, generalized: a var field advances by its length's static
  residue; an unknown residue poisons later offsets to `None`
  (degrading the fast path, never misfiring).
- `misaligned_var_runs` — var-run sites whose start alignment or
  whole-byte length is unprovable: the derived **"requires
  misaligned runs"** capability. Byte-surface backends refuse these
  loudly (Lua tvb ranges, the C harness's byte-hex printing — the
  existing LUA-/C-UNSUPPORTED culture); the generated parse cores
  themselves are bit-exact at any alignment (pure bit arithmetic for
  bounds and cursors — the ×8-free subtraction forms are simpler
  than the old division forms). `pakeles lint` prints the demands as
  information (never findings; exit code unaffected).

Soundness never depends on the analysis — this is the design point
that beat W9: closing the fault class by generalization (every op
defined at every cursor) instead of restriction.

## Costs paid

- Full regen: proto vendored code (Rust + Python), all 18 committed
  IRs, `testdata/parsers` fixtures, `gen/` artifacts, all vector
  suites.
- Symex: `SANITY_BYTES` → `SANITY_BITS` classifier (engine + pathid
  mirror), `remaining()` term loses its `>>3`, region/body terms lose
  their `×8` — mechanical; field-variable encoding untouched.
- Backends: C/eBPF bounds go to subtraction form in bits (overflow
  arguments simplify — no multiplication to wrap); Lua tvb ranges
  and the P4 varbit extract drop their ×8 (bits is P4's native
  varbit unit — the emitted lengths are value-identical).

## Unblocked

- BGP NLRI's bit-granular prefix lengths (the recorded
  second-pick-target case: length in bits, `ceil(len/8)` bytes on
  the wire) is now expressible as a native `var_bits` run.
- E-Peek (the lookahead primitive) can be specified once on the
  bit-uniform base, alignment-condition-free.
- The denominational parity nit vs P4-16 is closed.

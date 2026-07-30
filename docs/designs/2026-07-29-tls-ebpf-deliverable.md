# The eBPF SNI Deliverable — a generated TLV parser vs the real kernel verifier

**Headline:** Pakeles's GENERATED `tls_clienthello` parser — five
nested sized regions and a `remaining()`-driven TLV loop, the shape
that makes hand-written eBPF SNI parsers notoriously painful — **loads
verifier-clean into the real Linux kernel and agrees with the
interpreter on 28/28 corpus packets under `BPF_PROG_TEST_RUN`** — but
only up to a **measured `max_depth` ceiling of 22**. At the committed
`max_depth` of 96 the kernel rejects it for exceeding the 1M
instruction budget. Both halves of that sentence are the deliverable:
the machinery works in-kernel, and the unrolled-TLV approach has a
hard, quantified ceiling well below real browser traffic.

Harness: `oracle/tls_clienthello/spike/` (katran-spike lineage). An XDP
wrapper copies a bounded 512-byte prefix into a per-CPU scratch map and
calls the committed `gen/parser.bpf.c` core (`#include`d, so the spike
always tracks the artifact). `run.sh` loads it — the load IS the
verifier run — TEST_RUNs every corpus line ≥ 14 bytes, and diffs
outcomes line-by-line against the same generated core compiled as
userspace C99 (gate-proven field-equal to the interpreter).

```
./dev-priv.sh env PK_DEPTH=22 oracle/tls_clienthello/spike/run.sh
  using max_depth=22
  VERIFIER ACCEPTED the generated parser
  28 corpus lines TEST_RUN vs userspace core: 28 agree, 0 mismatch
```

## The measured ceiling

`depth-sweep.sh` varies ONLY `max_depth` — same parser graph, same
region machinery, same codegen — and attempts a load at each:

| `max_depth` | verifier |
|---|---|
| 12, 16, 17, 18, 19, 20, 22 | **accepted** |
| 23, 24, 32, 48, 64, 96 | rejected — `processed 1000001 insns (limit 1000000)` |

The cliff is sharp because the budget is spent on a fully unrolled
state machine: the emitted core is `for (depth) { switch (state) }`,
so the verifier explores ~`max_depth × states` blocks, each carrying
its reads and region checks.

**What depth 22 buys, in protocol terms.** The fixed ClientHello
prefix costs 12 states (record → handshake → version/random →
session_id → cipher_suites (+parity) → compressions → extensions
length). Each skipped extension costs 3 more (`s_tlv`, `s_ext`,
`s_skip`); descending into SNI costs 6. So depth 22 walks roughly
**three extensions** — enough for a minimal or SNI-early
ClientHello, and short of a real browser's 10–17. The committed
example keeps `max_depth = 96` because the rustls agreement corpus
includes a 17-extension browser-shaped ClientHello; correctness with
the incumbent outranks fitting the verifier.

This is a genuine, quantified statement of the community pain point:
it is not that TLV loops *cannot* be expressed for eBPF — the
generated one verifies and runs correctly — it is that full unrolling
does not scale to real extension counts. The named follow-up is a
codegen mode that emits a bounded verifier-loop (a `bpf_loop()` helper
callback or a `#pragma unroll`-free back edge) for cyclic states, so
per-iteration cost is paid once rather than `max_depth` times.

## Findings en route (three verifier rejections, three real fixes)

**1. Bounds refinement does not back-propagate across derived
scalars.** The first load failed with `invalid access to map value,
value_size=512 off=767 size=1`. The generated guard compared `off + n`
against the bound while the load indexed through `off`; the verifier
refines the register it tests, not its inputs, so `off` kept an
unrefined maximum. katran's parser passed the same verifier only
because its unrefined maxima happened to fit its scratch — the deeper
TLS state machine exposed the latent gap.

**2. Bit-by-bit reads blow the instruction budget.** `pk_read_bits`
loops once per BIT, so a 16-bit field cost 16 iterations of guarded
shifting, `max_depth` times over. Fix: a **byte-load fast path** —
when a field is statically byte-aligned and a whole number of bytes,
emit `n/8` direct byte loads. This reuses the alignment fixpoint the
Lua backend already had (`entry_alignments` / `field_alignment`, moved
to `codegen/mod.rs` so one analysis serves both backends). For
`tls_clienthello` 15 of 16 reads take the fast path. This is a general
codegen improvement, not a TLS-specific hack — the same bit-loop cost
is the plausible driver of the ~19x throughput gap the DPDK spike
measured against `rte_net_get_ptype`.

**3. Extra guards can cost more than they buy.** An intermediate fix
guarded every byte load individually; that added a branch per load,
range-split `bit_len`, and defeated verifier state pruning (28,538
states → 1M insns). The landed answer is **masking, not branching**:
the eBPF variant emits `#ifndef PK_BUF_MASK / #define PK_BUF_MASK
4095u` and indexes `buf[((off >> 3) + i) & PK_BUF_MASK]`. The mask is
dead for in-contract packets (the length guards already bound each
access) but bounds the index register directly, which is what the
verifier tracks. The default covers every committed conformance vector
(largest: 4096 bytes); a caller with a smaller scratch overrides it
(`-DPK_BUF_MASK=511u` in the spike) for a tighter bound. Portable C is
unmasked — the contract applies to the eBPF artifact only. Same device
already used for the sized-region stack index.

All three fixes are semantics-neutral and gate-verified: the compiled
C and rbpf conformance suites re-prove field-for-field interpreter
equality across the whole gallery after each.

## Boundary notes

- The wrapper still copies into scratch (contiguity + verifier-friendly
  bounds). Direct-packet-access codegen remains the follow-up named by
  the katran deliverable; the TLV loop does not change its difficulty.
- Corpus lines under 14 bytes are below the XDP `TEST_RUN` floor and
  are covered by the rbpf lane and the interpreter gate instead.

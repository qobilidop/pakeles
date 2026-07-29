# Spike: pakeles-generated C99 inside DPDK (ptype classification)

**Date:** 2026-07-29 (dpdk-ptype autonomous run, charter phase 6)
**Artifacts:** `oracle/dpdk_ptype/spike/{spike.c,run.sh}` — build+run with
`./dev.sh oracle/dpdk_ptype/spike/run.sh`.
**Question:** can the generated `examples/dpdk_ptype/gen/parser.c` serve
as (or alongside) DPDK's software classifier `rte_net_get_ptype()`?
Framing bar: EverParse's reported ≤2% overhead on adopted validators.

## What was built

An adapter (`adapt()` in spike.c) that replays rte_net.c's walk over the
generated parser's result struct and emits `(RTE_PTYPE_* mask,
rte_net_hdr_lens)`, plus a correctness harness (adapter vs the real
`rte_net_get_ptype`, packet for packet) and a ns/packet benchmark.
Single-segment mbufs throughout (charter boundary).

## Results (DPDK 23.11.4, arm64 container on Apple Silicon — indicative only)

**Correctness — clean.** Every packet the adapter projects matches DPDK
exactly: 43/78 golden-corpus lines and 217/3642 symex witnesses
projected, **0 mismatches**.

**Coverage — the structural finding.** The generated result is a flat
last-instance-wins struct (one slot per header instance). Anything that
extracts an instance twice — every tunnel with matching inner/outer
families, TEB's inner Ethernet, multi-link ext chains — overwrites the
slot, and the classification is NOT reconstructible post-hoc (~94% of
witnesses, ~45% of the corpus). Reject paths lose the failing-state
trace the laxness rule needs, too. The Rust oracle projection avoids
all of this only because the interpreter exposes the full extraction
trace. **A real integration should compute the classification inside
the parser** — ptype/hdr_lens as IR metadata built up by per-state
assigns — rather than project after the fact. That needs one IR
capability: arm-level (or pass-through-state) assigns so
select-dependent writes (frag bits, blind L4 lengths) are expressible;
the pass-through-state encoding works today but costs ~25 extra states.

**Performance — a large, explainable miss.**

| ns/packet (300k iters, corpus round-robin) | |
|---|---|
| `rte_net_get_ptype` | 7.6 |
| generated parser | 142.9 (+1777%) |
| generated parser + adapter | 154.3 (+1926%) |

The generated parser is ~19x slower — nowhere near the ≤2% bar. This is
not mysterious, and mostly not fixable by flag-tweaking:

- **It extracts everything.** rte_net.c reads 3–4 fields per header and
  skips the rest arithmetically; the generated parser materializes every
  declared field (48-bit MACs, seq/ack/window/checksums, VLAN pcp/dei/
  vid splits) through generic bit-offset extraction into a ~200-byte
  result struct.
- **It is eager.** Options/ext bodies/GRE optionals are bounds-checked
  and recorded; DPDK never touches them.
- **Generic loop-switch shape** (depth-counted state loop) vs DPDK's
  straight-line fall-through with a fast-path IPv4 goto.

The EverParse precedent got its ≤2% from validation-only code with
zero materialization — the fair analog here would be a
**projection-aware backend**: dead-field elimination against a declared
consumer (only proto/length fields feed ptype), native metadata
classification (above), and byte-aligned word reads instead of per-field
bit arithmetic. Those are codegen workstreams, not integration blockers
found in DPDK itself: the harness side (mbuf in, mask out, no EAL) was
trivial.

## Takeaways for the roadmap

1. The **oracle** integration (this run's gate) is solid: pure-function
   harness, no EAL, byte-stable goldens.
2. **Adoption-grade codegen needs**: (a) metadata-computed
   classification with arm-level assigns, (b) dead-field elimination /
   demand-driven extraction, (c) word-granular loads. Filed as the
   concrete follow-ups this spike exists to surface; without them the
   generated C is an oracle-quality artifact, not a datapath-quality
   one.
3. Numbers are container-on-Apple-Silicon; absolute values are
   indicative, the ~19x ratio is robust enough to stand as the finding.

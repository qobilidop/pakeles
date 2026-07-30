# Spike: Pakeles-generated eBPF under the real kernel verifier (katran_flow)

**Date:** 2026-07-29 (katran autonomous run, plan T6)
**Artifacts:** `oracle/katran/spike/{xdp_parser.bpf.c,run.c,run.sh}` —
`./dev-priv.sh oracle/katran/spike/run.sh` (privileged: real-kernel
BPF_PROG_TEST_RUN).
**Question:** does Pakeles's *generated* eBPF parser
(`examples/real_world/katran_flow/gen/parser.bpf.c`) pass the **real Linux kernel
verifier** and produce correct results in-kernel? This is the
audience-facing claim for the eBPF-community pitch — the everyday gate
already runs the generated program in rbpf (a userspace eBPF VM whose
verifier is weaker than the kernel's).

## What was built

A thin XDP wrapper (`xdp_parser.bpf.c`) that `#include`s the committed
generated parser (so it can never drift), copies a bounded packet prefix
into a per-CPU array-map scratch buffer, calls the generated
`pk_katran_flow_parse_core`, and stashes `{outcome, reason,
consumed_bits}` in a map. A userspace harness (`run.c`) loads the object
— **the load is where the kernel verifier runs** — and TEST_RUNs each
corpus packet.

## Result — verifier-clean and correct

**The kernel verifier ACCEPTS the generated parser** (kernel 6.8.0,
arm64 dev container). Over the 30-packet corpus the in-kernel parse
outcome partitions **23 accept / 7 reject**, matching both the Pakeles
interpreter and katran's own drop set exactly — **0 mismatches** (the 7
rejects are precisely katran's 7 `XDP_DROP` packets: IPv4 options, the
three fragment shapes, the two truncations, and the inner-ihl≠5 drop).

This is a materially stronger deliverable outcome than the DPDK spike
(which found a ~19x throughput gap projecting a flat C result). Here the
generated program is:

- **Verifiable as-is** — the generated loop-switch shape (bounded state
  loop, no recursion, no unbounded backward jumps) is already what the
  verifier wants; only a bounded packet-copy wrapper was needed, and
  that is boilerplate any XDP consumer writes.
- **Correct in-kernel** — the same accept/reject the interpreter and the
  incumbent produce, run through the real bpf() machinery.

## What the wrapper contributes (and what a real integration would add)

The generated core reads a contiguous `bit_len`-bounded buffer; XDP
packets are neither contiguous nor length-bounded to the verifier, so
the wrapper does a constant-bounded copy into map scratch (the 512-byte
BPF stack cannot hold the result struct + a packet buffer — the
generated file's own header notes "large parsers will need a redesign").
A production integration would either:

1. teach the C/eBPF backend to emit **direct-packet-access** reads
   (`data`/`data_end` bounds threaded through `pk_read_bits`), removing
   the copy; or
2. keep the copy but size the scratch to the example's provable maximum
   parse depth.

Neither is a blocker — the copy wrapper already ships a verifier-clean,
correct parser today. The finding for the roadmap: **Pakeles's eBPF
backend produces kernel-loadable parsers, verified on real hardware**,
which is the concrete evidence the eBPF-community pitch needs; the
direct-packet-access codegen is the efficiency follow-up (parallel to
DPDK's dead-field-elimination follow-up).

## Caveats

- One kernel (6.8.0), one arch (arm64 container on Apple Silicon);
  verifier behavior is version-dependent, so the claim is "accepted by
  the 6.8 verifier," not "accepted by every verifier."
- The wrapper caps the copied prefix at 256 bytes (SCRATCH_BYTES) — the
  corpus's deepest packet (ICMP + inner IP + inner L4) is well under
  that; a larger example would raise the bound.
- Correctness here is accept/reject + consumed_bits vs the interpreter;
  the full field-level projection agreement is the everyday gate's job
  (`diff katran`), already green over the same corpus.

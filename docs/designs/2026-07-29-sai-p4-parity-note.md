# Note: SAI P4 parity — a P4-vs-P4 parse differential on `simple_switch`

**Date:** 2026-07-29 (sai_parser autonomous run, plan T6)
**Artifacts:** `oracle/sai_p4/` (vendored incumbent + verdict-patch
factory), `examples/real_world/sai_parser/`, `src/oracle/sai.rs`.

## The claim

Pakeles's `sai_parser` model agrees, packet-for-packet, with the real
**SONiC PINS `sai_p4` parser** (sonic-pins @ e77250b8) over the committed
corpus (23 packets) and the full byte-aligned symbolic-execution witness
set (20 packets) — **0 divergences** in either. This is the roadmap's
"parity with a NOTABLE program" target: sai_p4 is the parser of a
production switch pipeline, not a toy.

## Why this is a genuine P4-vs-P4 differential

The incumbent is a P4 program on BMv2 `simple_switch` — the same engine
Pakeles's own P4 backend targets and the everyday `bmv2.rs` gate already
drives. So two independent P4 programs are compared on one switch:

- **Ours:** `examples/real_world/sai_parser/gen/parser.p4`, generated from the IR,
  checked against the Pakeles interpreter by `bmv2.rs` (the existing
  in-gate BMv2 differential).
- **Theirs:** the vendored sonic-pins parser, instrumented to emit the
  identical verdict wire-format (validity bitmap + error) and run over
  the corpus by `oracle/sai_p4/factory/capture.sh`.

`src/oracle/sai.rs` projects our interpreter's result into that same
(bitmap, err) format and diffs it against the incumbent's golden. The
bitmap bit order is a pinned contract shared by both programs (design
§4). Because both run on the same `simple_switch`, this is as close to a
true behavioral parity check between the two P4 parsers as the toolchain
allows — not a static comparison.

## What it exercises — and the honest coverage caveat

The sai_p4 parser is a clean, bounded v1model parser (Ethernet, VLAN,
IPv4/IPv6, ARP, ICMP, TCP, UDP; no IP-in-IP, no ext-header walk in this
snapshot). It uses **only exact/wildcard select entries** — no
value_sets, lookahead, varbit, header stacks, or masked/range keys. So
while the parity claim is strong for what the program *does*, it does
**not** exercise Pakeles's more advanced IR machinery (lookahead,
value_sets, mask/range selects). A complete P4-parity story needs a
**P4-feature side-corpus** — small hand-written P4 parsers that each use
one advanced feature — run through the same BMv2 differential. That is a
named, deferred roadmap item, not part of this run.

## Toolchain finding

The prebuilt `simple_switch` in the dev image has **logging compiled
out**: `--log-console -L trace` yields only startup lines. SONiC's own
DVaaS reads per-state parser traces from that log; here it is
unavailable, which is why the oracle uses a P4 instrumentation patch (a
verdict header) instead. Anyone reproducing SONiC's log-based parse
tracing on this image would need a logging-enabled BMv2 build.

## Deliverable takeaway

Pakeles can state agreement with a **production switch parser**, verified
by running both the incumbent and Pakeles's own generated P4 on the same
reference switch. The follow-up for a full P4-parity claim is the
feature side-corpus (advanced select constructs), parallel to the
efficiency follow-ups named for the DPDK (dead-field elimination) and
katran (direct-packet-access) backends.

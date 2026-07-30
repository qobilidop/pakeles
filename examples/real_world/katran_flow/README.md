# Example: `katran_flow`

The third **incumbent-agreement** example (after
[`linux_flow_dissector`](../linux_flow_dissector) and
[`dpdk_ptype`](../dpdk_ptype)): a field-for-field model of the packet
**parse path** of Meta's [Katran](https://github.com/facebookincubator/katran)
XDP load balancer (`katran/lib/bpf/balancer.bpf.c` `process_packet`),
whose parsed flow keys + XDP verdict agree packet-for-packet with katran
itself over the committed corpus.

**The agreement claim:** agrees with **katran @ commit `dd915fd2`
(default build, empty maps)** over
[`conformance/katran.dd915fd2e21a.golden.json`](conformance/katran.dd915fd2e21a.golden.json)
— for every packet the XDP verdict, the export `stage`, and the parsed
flow tuple (src/dst, ports, proto, flags, tos) match. Design doc:
[`docs/superpowers/specs/2026-07-29-katran-design.md`](../../docs/superpowers/specs/2026-07-29-katran-design.md).

## The two-oracle gate

Unlike DPDK's `rte_net_get_ptype` (a pure userspace function), katran's
parse writes into an internal `packet_description` and then makes load
-balancing decisions we do not model. Two problems, both solved in the
factory ([`oracle/katran_flow/factory/`](../../oracle/katran_flow/factory/)):

1. **Compile + run** the GPL sources (fetched at capture time, never
   committed) with plain `clang -target bpf` plus a 7-line pakeles shim
   for the one Meta-internal header the OSS tree references but does not
   ship (`common/bpf/bpf_net_helpers.h` — two big-endian EtherType
   constants). The program loads and runs under `BPF_PROG_TEST_RUN`.
2. **Observe the parsed keys** with an anchored, sha-verified,
   idempotent instrumentation patch (`fetch.sh`, capture-time only,
   never committed/upstreamed): a 1-entry array map `pk_export_map` that
   exports the parsed `packet_description` at two points *before* any
   vip/LB stage. The verdict is the raw `BPF_PROG_TEST_RUN` return.

The everyday unprivileged gate (`committed_goldens_agree`, `cargo run --
diff katran`) diffs our projection ([`src/oracle/katran_flow.rs`](../../src/oracle/katran_flow.rs))
against the committed golden. Re-minting is privileged (in-kernel
TEST_RUN):

```sh
./dev-priv.sh oracle/katran_flow/factory/capture.sh
```

## Scope: the default-build bounded core

Katran is XDP at the NIC, so the parse is flat and small: Ethernet →
{IPv4, IPv6} → {ICMP-inner, TCP, UDP}. **No VLAN, no MPLS, no IPv6
extension-header walk.** Beyond the committed corpus, the full
byte-aligned symbolic-execution witness set (18 packets ≥ 14 B) was
replayed through the real balancer — **0 divergences** from our
projection.

**Boundary (documented, config-gated / non-default-build — the
"heuristic tail"):**

- **QUIC / UDP-stable-routing / TCP-TPR server-id routing.** QUIC
  parsing is fully expressible in the IR (fixed-offset, the header
  spelling is worked out in the design doc), but katran gates it on a
  vip-map flag (`F_QUIC_VIP`) — **map config, not packet content.** A
  packet-pure parser cannot condition on that without modeling map
  state, which is exactly the load-balancer logic we exclude. So QUIC
  is a boundary on principle, not difficulty; stable-routing and the
  TPR option walk are additionally behind non-default `#ifdef` flavors.
- **IPIP / GUE decap** (`#ifdef INLINE_DECAP_*`): not in the default
  build, so proto 4/41 and GUE-port UDP fall through to XDP_PASS here.
- **< 14-byte packets:** XDP `BPF_PROG_TEST_RUN` rejects them at the
  syscall level — out of oracle reach (no corpus lines).
- **The XDP_TX echo-reply mutation bytes:** we assert the verdict, not
  the rewritten output packet.

## Quirk catalog (harness-verified against katran @ dd915fd2)

Faithfully modeled, never "corrected" — and a striking contrast with
the two prior incumbents on the very same packets:

- **IPv4 options are a hard `XDP_DROP`.** `ihl != 5` drops immediately
  ("we dont support em"). The Linux flow dissector *parses* options and
  DPDK *blind-skips* them — three incumbents, three behaviors, one
  packet.
- **No IPv6 extension-header walk.** Only the fixed 40-byte header is
  read; `next_header == Fragment (44)` is a hard drop, and any other
  non-{ICMPv6,TCP,UDP} next_header (HopByHop, Routing, …) is taken as
  the L4 proto directly and `XDP_PASS`ed as "unknown L4" — no walking,
  the opposite of the kernel's ext-header chain.
- **Fragments drop.** Any IPv4 `MF`/offset or IPv6 Fragment header →
  `XDP_DROP` (katran refuses to guess a flow from a fragment).
- **ICMP error flow inversion.** An ICMP/ICMPv6 `DEST_UNREACH` /
  `PKT_TOOBIG` carries the *original* packet; katran parses that inner
  packet and takes the flow keys with **src/dst AND ports SWAPPED**
  (plus the `F_ICMP` flag) so the error routes to the same real as the
  flow that triggered it. `tos`, however, still comes from the OUTER IP
  (katran reads it before the ICMP branch). The corpus proves all of
  this: an inner `0a000005:12345 → 0a000006:443` surfaces as
  `0a000006:443 → 0a000005:12345`.
- **ICMP echo is answered in-parser.** An echo request returns
  `XDP_TX` (a mutated echo reply), never reaching the flow-key stage —
  a verdict class of its own, distinct from the `XDP_PASS` of every
  other non-error ICMP type.
- **IPIP is not decap in the default build.** proto 4/41 with no
  `INLINE_DECAP_IPIP` flavor is just an unknown L4 → `XDP_PASS` with
  the outer flow keys; the corpus carries an IPIP packet to prove the
  boundary (vs the kernel and DPDK, which both re-enter the inner IP).
- **TCP SYN/RST are lifted** into `F_SYN_SET`/`F_RST_SET`; every other
  flag is ignored. `total_len`/`payload_len` are recorded verbatim,
  never validated against the buffer.

## Files

| File | What it is |
|---|---|
| [`katran_flow.py`](katran_flow.py) | The description in the Python eDSL |
| [`katran_flow.ir.json`](katran_flow.ir.json) | The normative Pakeles IR |
| [`gen/`](gen/) | Wireshark dissector, C99 + eBPF parsers, P4-16, docs, parse graph |
| [`conformance/`](conformance/) | Symbolic-execution vectors + the katran-minted golden |

## Try it

```sh
./dev.sh cargo run -- diff katran   # our keys+verdict vs the committed golden
```

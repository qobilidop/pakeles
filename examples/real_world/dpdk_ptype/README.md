# Example: `dpdk_ptype`

The second **incumbent-agreement** example (after
[`linux_flow_dissector`](../linux_flow_dissector)): a field-for-field
model of DPDK's software packet classifier `rte_net_get_ptype()`
(`lib/net/rte_net.c`), whose projected output — the `RTE_PTYPE_*`
classification mask plus `struct rte_net_hdr_lens` — agrees
packet-for-packet with DPDK itself over the committed corpus.

**The agreement claim:** agrees with **DPDK 23.11 (Ubuntu noble
23.11.4) on little-endian hosts**, over
[`conformance/ptype.dpdk-23.11.4.golden.json`](conformance/ptype.dpdk-23.11.4.golden.json)
— accepts compared exactly (mask + all seven hdr_lens fields),
truncation lines via the laxness rule below. Design doc:
[`docs/superpowers/specs/2026-07-29-dpdk-ptype-design.md`](../../../docs/superpowers/specs/2026-07-29-dpdk-ptype-design.md).

## The two-oracle gate

1. **Committed golden** (reproducible, environment-free):
   [`factory/capture.c`](factory/capture.c)
   feeds each corpus packet to the real `rte_net_get_ptype()` through a
   hand-built single-segment stack mbuf — the function is pure over
   mbuf data, so **no EAL, no hugepages, no privilege** — and the
   version-tagged JSON it emits is committed here. The everyday gate
   test `committed_goldens_agree` diffs our projection
   ([`src/lib.rs`](src/lib.rs),
   `cargo run -p pakeles-example-dpdk-ptype`) against it.
2. **Live differential** (no staleness): where the dev container's
   DPDK + gcc are present, `live_dpdk_capture_matches_committed_golden`
   rebuilds the harness, re-runs the corpus, and requires the fresh
   capture to byte-match the committed golden.

Re-minting (unprivileged, in the normal container):

```sh
./dev.sh examples/real_world/dpdk_ptype/factory/capture.sh
```

## No drop verdict: the laxness rule

`rte_net_get_ptype` classifies **every** packet — truncation just stops
classification early with a partial mask. Our parser trunc-rejects at
the same read boundaries; the projection maps each *mappable* reject
class onto DPDK's partial answer (checked like any entry, never
skipped): a truncated fixed header yields the mask-so-far, a truncated
VLAN/QinQ tag still claims its bit (set before the read), a truncated
outer TCP strips the L4 bit, and a truncated *inner* TCP wipes
everything but the inner L2/L3 bits.

**Excluded (unmappable) classes** — our eager `var_bytes` demands bytes
DPDK arithmetic-skips, so DPDK's answer depends on values we never
extracted. These are documented boundaries with **no corpus lines** (the
projection hard-errors, so accidental inclusion is a red gate):

- IPv4 options region truncated (DPDK advances `ihl*4` without reading).
- IPv6 extension-header *body* truncated (DPDK reads only the 2-byte
  prefix).
- GRE C/K/S optional region truncated (pure offset arithmetic in DPDK).
- Fragment header truncated mid-way (2..7 bytes present).
- `ihl < 5`: DPDK rewinds its cursor into the IP header (computes
  `l3_len < 20` and reads L4 *inside* the IP bytes); our cursor is
  monotonic — inexpressible, and modeled as a wrapped-length reject.
- Multi-segment mbufs (the harness builds single-segment ones) and
  UDP-port-configured tunnels (VXLAN/Geneve — not in
  `rte_net_get_ptype` at all).

## Quirk catalog (all harness-verified against DPDK 23.11.4)

Beyond the committed corpus, the **full byte-aligned symex witness set
(3,642 packets) was replayed through the real `rte_net_get_ptype`**:
3,461 agree with our projection exactly, and every one of the 181
disagreements is an expected excluded-class reject (178 IPv4
options-region truncations, 3 outer equivalents) — zero unexplained
divergences.

Faithfully modeled, never "corrected":

- **MPLS classification is dead code in 23.11.4.** The label loop has
  no bottom-of-stack break, so `i == MAX_MPLS_HDR` always holds and the
  function returns *before* setting `L2_ETHER_MPLS`: an MPLS packet
  classifies as plain `L2_ETHER`, l2_len 14 — label stack present,
  absent, or truncated.
- **Byte-swap tunnels (little-endian hosts).** `ptype_tunnel` switches
  the big-endian leftover proto against host `IPPROTO_*` values, so
  EtherTypes `0x0400`/`0x2900`/`0x2F00` classify as IPIP/IPv6-in-IP/GRE
  tunnels (e.g. `eth[0x0400]/IPv4/TCP` → `TUNNEL_IP INNER_L3_IPV4
  INNER_L4_TCP`). Conversely the inner section compares host u8 IP
  protos against big-endian EtherType constants: protocol **8** (EGP)
  parses an inner IPv4 and protocol **129** an inner VLAN, both with no
  tunnel bit.
- **The inner section needs no tunnel.** Any leftover post-L2 proto
  falls through: double-VLAN classifies as `...INNER_L2_ETHER_VLAN
  INNER_L3_* INNER_L4_*`, Q-then-AD as `INNER_L2_ETHER_QINQ`, and a
  top-level TEB EtherType parses an inner Ethernet — all with
  tunnel_len 0.
- **QinQ reads only the second tag.** The first tag (including its
  TPID) is a blind 4-byte skip: bare `0x88A8` + IPv4 misreads IPv4
  bytes as the second tag and still reports `L2_ETHER_QINQ`, l2_len 22.
- **GRE ignores version; R means "not a tunnel".** The opt_len table is
  indexed by the C/R/K/S nibble only — a version=1 packet with C+K+S
  parses as a full GRE tunnel (the kernel accept-stops on version≠0: a
  documented kernel-vs-DPDK divergence), while any R=1 combination
  yields no tunnel bit at all. TEB inside GRE is reported as
  `TUNNEL_NVGRE` without checking the key flag.
- **Blind lengths.** UDP/SCTP are never read: `l4_len` 8/12 are
  reported even with zero L4 bytes present. TCP's `l4_len = doff*4` is
  unvalidated (doff=0 → 0, doff=8 with no options bytes → 32).
- **Fragment quirks.** An IPv6 fragment whose `next_header` is 0
  (HopByHop) hits the walk's `proto == 0` early return and **loses the
  `L4_FRAG` bit**. An IPv4 packet with any nonzero MF|offset stops as
  `L4_FRAG` regardless of protocol.
- **The 5-link ext bail snaps l3_len back.** Five consumed option links
  exhaust `MAX_EXT_HDRS` and return -1: the mask keeps `L3_IPV6_EXT`
  but `l3_len` reverts to 40 (the walk's l3_len update is
  success-path-only), and no L4 is ever classified — whatever the 5th
  link's next_header promises.
- **Unknown `version_ihl` keeps walking.** Only `0x45..0x4F` map to an
  L3 bit; anything else (e.g. `0x55`) gets *no* L3 bit but the walk
  continues and can still classify L4 (`L2_ETHER | L4_TCP`).
- **Truncated inner TCP wipes the outer classification** — the
  early-return masks with `INNER_L2|INNER_L3` only, so
  `IPv4/IPv4/TCP(truncated)` classifies as bare `INNER_L3_IPV4`
  (0x00100000): outer L2/L3/tunnel bits all gone.
- **Exactly one inner level.** A second stacked tunnel is never
  dispatched (`ptype_inner_l4` knows only TCP/UDP/SCTP): double-IPIP
  stops at `INNER_L3_IPV4`.

## Files

| File | What it is |
|---|---|
| [`dpdk_ptype.py`](dpdk_ptype.py) | The description, authored in the Python eDSL — mirrors rte_net.c's walk state-for-state |
| [`dpdk_ptype.ir.json`](dpdk_ptype.ir.json) | The normative Pakeles IR (protojson) |
| [`gen/`](gen/) | Every generated artifact: Wireshark dissector, C99 parser, eBPF program, P4-16 program, docs, parse graph |
| [`conformance/vectors.json`](conformance/) / `vectors.pcap` | Control-shape-complete symbolic-execution suite |
| [`conformance/ptype.dpdk-23.11.4.golden.json`](conformance/ptype.dpdk-23.11.4.golden.json) | DPDK-minted golden `(ptype, hdr_lens)`, version-tagged — the agreement artifact |

## Try it

```sh
./dev.sh cargo run -p pakeles-example-dpdk-ptype   # our (ptype, hdr_lens) vs the committed goldens
tshark -X lua_script:gen/dissector.lua -r conformance/vectors.pcap -V
```

# `katran` design-lite — DRAFT (phase 1 study notes; phase 2 completes this)

**Date:** 2026-07-29
**Status:** phase-1 incumbent study, in progress. Becomes binding when
the projection + gate shape sections are decided.
**Incumbent pin:** facebookincubator/katran @
**dd915fd2e21ab333eda302d753c92c8806defc8a** (main, 2026-07-28) —
`katran/lib/bpf/{balancer.bpf.c, pckt_parsing.h, handle_icmp.h,
balancer_consts.h, balancer_structs.h}`. GPL-2.0: fetch-at-capture-time
only, never vendored (bpf_flow.c precedent).

## 1. The parse/decide boundary (from source)

`process_packet(xdp, nh_off, is_ipv6)` in balancer.bpf.c:715, called
from the XDP entry after an EtherType demux (0x0800/0x86DD; anything
else XDP_PASS). The PARSE portion, in order:

1. `parse_l3_headers` (pckt_parsing.h:455):
   - IPv6: fixed 40-byte header, `proto = nexthdr`; `tos` from
     priority/flow_lbl bits; **IPPROTO_FRAGMENT (44) → XDP_DROP** (no
     ext-header walk at all — any other nexthdr falls through);
     ICMPV6 → the ICMP path; else record src/dst (16B each).
   - IPv4: **`ihl != 5` → XDP_DROP** (options unsupported — hard drop,
     the opposite of both prior incumbents); `frag_off &
     PCKT_FRAGMENTED → XDP_DROP`; ICMP → ICMP path; else record
     src/dst. `tot_len`/`payload_len` recorded as `pkt_bytes` (not
     validated against data_end).
2. `handle_if_icmp` (handle_icmp.h, read line-by-line): ICMP/ICMPv6
   echo request → **XDP_TX of an in-place mutated echo reply** (MAC/IP
   swap, type flip, checksum adjust) — the program answers pings; a
   parse-relevant verdict class of its own. v4 type == DEST_UNREACH
   (any code; FRAG_NEEDED only bumps stats) and v6 type ∈ {PKT_TOOBIG,
   DEST_UNREACH} → parse the EMBEDDED inner IP header at the fixed
   icmp+inner offset, set F_ICMP, take src/dst from the inner packet
   SWAPPED (inner daddr→flow.src, saddr→flow.dst; inner v4 ihl != 5 →
   DROP), then L4 ports read from the inner transport header with the
   same swap. Every other ICMP type/code → XDP_PASS.
3. L4 by `flow.proto`: TCP (`parse_tcp`: fixed 20B struct read; SYN →
   F_SYN_SET, RST → F_RST_SET; ports, SWAPPED under F_ICMP), UDP
   (`parse_udp`: 8B; ports, swapped under F_ICMP), anything else →
   **XDP_PASS** (not drop).
4. Config-gated parse arms (each behind an #ifdef flavor AND/OR a
   vip_map flag — the map-dependence problem):
   - `INLINE_DECAP_IPIP`/`INLINE_DECAP_GUE`: proto 4/41 (or UDP
     dport == GUE_DPORT 6080) → decap + RECURSIVE re-process of the
     inner packet (bpf_xdp_adjust_head + tail-ish re-entry).
   - QUIC (`parse_quic`, run for F_QUIC_VIP vips): UDP payload byte 0:
     long-header bit (0x80) → 1B flags + 4B version + 1B dcid-len +
     16B (QUIC_MIN_CONNID_LEN) dcid prefix, with packet-type <
     HANDSHAKE → "initial, fall back to hash" and dcid-len <
     QUIC_MIN_CONNID_LEN → no server-id; short header → 1B flags +
     16B cid. cid[0]>>6 = cid version (V1/V2/V3), server-id =
     fixed bit-slices of cid bytes (projection-side arithmetic, not
     parse). All FIXED offsets/lengths — expressible in today's IR
     (bit fields + selects); no var-bits needed.
   - UDP stable routing (`parse_udp_stable_rt_hdr`, F_UDP_STABLE_RT):
     UDP payload byte 0 == STABLE_ROUTING_HEADER → fixed 16B cid,
     server-id = cid bytes 1..3.
   - TCP TPR option walk (`tcp_hdr_opt_lookup`, TCP_SERVER_ID_ROUTING
     flavor): doff-sized option area, kind/len TLV walk bounded by
     TCP_HDR_OPT_MAX_OPT_CHECKS, looking for kind 0xB7 len 6 →
     4B server-id. A bounded TLV cycle — flow-dissector ext-opt
     precedent.

Everything after (vip_map/LPM lookups, hash-flag port zeroing, LRU,
consistent hashing, encap toward reals, stats) is LB DECISION — out of
scope; the projection must stop at parsed keys + parse-relevant
verdict.

## 2. The two hard problems (phase-1/2 to resolve)

- **Map-dependence:** which hint-parse arm runs depends on vip_map
  content (F_QUIC_VIP, F_UDP_STABLE_RT flags) and build flavors
  (#ifdefs). Direction: pin ONE factory configuration (documented in
  the capture harness: a fixed vip set with one TCP vip, one UDP+QUIC
  vip, one stable-rt vip; default build flavor with
  TCP_SERVER_ID_ROUTING on) so classification is deterministic
  per-packet. The claim becomes "katran @ pin, flavor X, config C" —
  version-tagged like everything else.
- **Observation:** packet_description/flow keys are internal.
  Candidates, in preference order: (a) katran's own flow_debug maps
  (flow_debug.h — LRU maps recording parsed flows when built with
  flow debug on) read back after BPF_PROG_TEST_RUN; (b) return value +
  output packet (encap headers encode the chosen real — too far
  downstream); (c) a pinned instrumentation patch exporting
  packet_description via a map before the LB stage (capture.c-style,
  committed as a diff, applied at fetch time). Decide empirically in
  the dev-priv container.

## 3. Immediately visible quirk candidates (to verify + corpus)

- IPv4 options = hard DROP (vs kernel dissector parsing them, vs DPDK
  blind-skipping them) — a three-incumbent divergence showcase.
- Any IPv6 ext header other than Fragment: NOT walked — nexthdr is
  treated as the L4 proto directly (e.g. HopByHop → XDP_PASS as
  "unknown L4"), while Fragment specifically DROPs.
- ICMP flow-key inversion (src/dst and ports swapped) — deliberate
  (flow affinity for errors), a projection rule.
- QUIC "initial packets fall back to hash" (packet-type gate) and the
  0xFF cid-version sentinel.
- `pkt_bytes` recorded from tot_len/payload_len without validation.

## 4. Next (phase 1 remainder)

Read handle_icmp.h line-by-line; enumerate build flavors actually used
by katran's own tests; get their program loaded + TEST_RUN-executed in
the dev-priv container (their BUCK/CMake fetch may be avoidable —
clang -target bpf on balancer.bpf.c with pinned includes); solve
observation via flow_debug vs patch; smoke-test; then finish this doc
(coverage map §, projection + laxness §, example scope §, gate shape §,
out-of-scope §) and mark it binding.

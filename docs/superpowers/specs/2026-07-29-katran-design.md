# `katran` design-lite

**Date:** 2026-07-29
**Status:** BINDING (phase 2 complete). Sections 1-3 are the incumbent
study; 6-10 are the binding decisions.
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

## 4. Phase-1 harness status (2026-07-29)

DONE — `oracle/katran/factory/{fetch.sh,capture.c,capture.sh}`:

- The pinned balancer compiles with plain `clang -target bpf` against
  the fetched tree plus a 7-line pakeles shim for the Meta-internal
  `common/bpf/bpf_net_helpers.h` (OSS tree includes it but does not
  ship it; only `BE_ETH_P_IP`/`BE_ETH_P_IPV6` are needed). Default
  flavor (no #ifdefs).
- Loads + runs under BPF_PROG_TEST_RUN in dev-priv (kernel 6.8.0,
  BTF-defined maps fine). With ALL MAPS EMPTY the whole parse path is
  exercisable: smoke run confirmed no-vip v4/v6 TCP → XDP_PASS, IPv4
  options (ihl=6) → XDP_DROP, v4 MF frag → XDP_DROP, v6 Fragment
  nexthdr → XDP_DROP, ARP → XDP_PASS, ICMP echo → XDP_TX with the
  correctly mutated in-place reply (MAC/IP swap, type flip, checksum
  adjust) — echo replies are observable through data_out.
- Harness constraint: XDP TEST_RUN rejects data_in < 14 bytes at the
  syscall level (EINVAL, not a verdict) — sub-Ethernet truncation lines
  are untestable against this incumbent; corpus + laxness rule must
  treat < 14B as out of oracle reach (document, don't fabricate).

## 5. Observation: SOLVED (phase 1, 2026-07-29)

An anchored, sha-verified, idempotent pakeles patch (applied by
`fetch.sh`, capture-time only, never committed/upstreamed — the sai_p4
"instrumentation gadget" arriving early) adds a 1-entry array map
`pk_export_map` and exports the parsed `packet_description` at two
points BEFORE any vip/LB stage (post-L3/ICMP `stage|1`, post-L4
`stage|2`) plus the QUIC parse result (`stage|4`). `capture.c` resets +
reads it per TEST_RUN. flow_debug was rejected: it only records GUE
routes (encap decisions), not the base parse. Smoke-confirmed the full
core parse is now observable (v4/v6 flow tuples, ports, proto, flags,
tos). QUIC parsing (stage|4) is exportable too, but is a boundary —
see §6 (config-gated, not packet-pure).

## 6. Binding scope: the default-build bounded core

Modeled — the DEFAULT build's parse path (no build #ifdefs), which is
already remarkably bounded because katran is XDP at the NIC:

- **L2:** Ethernet only. **No VLAN, no MPLS, no QinQ** — the entry
  demuxes `h_proto` straight to v4/v6; any other EtherType (ARP
  included) is `XDP_PASS` without entering the parser.
- **L3:** IPv4 (`ihl != 5` → DROP, `frag_off & 0x3FFF` → DROP, ICMP →
  inner path, else record src/dst/proto/tos) and IPv6 (fixed 40B,
  nexthdr == Fragment → DROP, ICMPv6 → inner path, **no extension-header
  walk** — any other nexthdr is taken as the L4 proto directly).
- **ICMP inner:** ICMP/ICMPv6 echo request → `XDP_TX` mutated reply
  (verdict-class, no keys); DEST_UNREACH (v4) / {PKT_TOOBIG,
  DEST_UNREACH} (v6) → parse the embedded inner IP at the fixed offset
  (inner v4 `ihl != 5` → DROP), set F_ICMP, take flow src/dst from the
  inner packet SWAPPED, then read inner L4 ports SWAPPED; any other
  ICMP type → `XDP_PASS`.
- **L4:** TCP (fixed 20B; SYN→F_SYN_SET, RST→F_RST_SET; ports) and UDP
  (8B; ports); any other proto → `XDP_PASS` ("to the stack").

**Boundary (documented, NOT modeled — the "heuristic/config tail," per
the flow-dissector precedent):**

- **QUIC** (`parse_quic`): a design refinement made during the build.
  QUIC parsing IS fully expressible in today's IR — fixed offsets, a
  long/short-header select, bit-field cid slices, no var-bits (the
  header spelling is worked out in §7b below, kept for the future
  rung). But it is gated by `vip_info->flags & F_QUIC_VIP` — **map
  config, not packet content.** A packet-pure parser (Pakeles's whole
  premise) cannot condition on it without baking specific vip addresses
  into the model, i.e. modeling map state — which is exactly what the
  LB-logic exclusion forbids. So QUIC joins the config-gated tail as a
  boundary, on the same principled ground as stable-rt/TPR, NOT because
  it is hard. This keeps `katran_flow` a pure packet→result function.

- **IPIP/IPv6-in-IP decap** (`#ifdef INLINE_DECAP_IPIP`) and **GUE
  decap** (`#ifdef INLINE_DECAP_GUE`): not in the default build; proto
  4/41 and GUE-port UDP fall through to `XDP_PASS` here. Recursive
  decap re-entry is a future rung.
- **UDP stable-routing** (`#ifdef UDP_STABLE_ROUTING`) and **TCP TPR
  option walk** (`#ifdef TCP_SERVER_ID_ROUTING`): non-default flavors;
  the TPR walk is a bounded doff-sized TLV loop (a separate rung, the
  flow-dissector ext-opt analog).
- **< 14-byte packets:** XDP TEST_RUN rejects them at the syscall level
  — out of oracle reach (documented, no corpus lines).

## 7. Projection: `ParseResult` → katran keys + verdict

Harness-side (`src/oracle/katran.rs`), from OUR parse trace only. The
compared tuple, matching the golden's schema:

- `verdict` ∈ {XDP_PASS, XDP_DROP, XDP_TX} and `stage` (bits 1/2):
  - our reject on a modeled DROP cause (ihl≠5, v4/v6 frag, inner ihl≠5,
    truncated header at/after L3) → **XDP_DROP, stage 0**;
  - our accept terminating at an L4 (tcp/udp) → **XDP_PASS, stage 3**
    with the flow tuple;
  - our accept stopping at L3 for a non-TCP/UDP proto → **XDP_PASS,
    stage 1** (the "to the stack" arm), flow src/dst/proto set, ports 0;
  - our accept at Ethernet with a non-IP EtherType → **XDP_PASS,
    stage 0**, no keys (katran never enters the parser);
  - ICMP echo → **XDP_TX, stage 0** (a declared verdict, keys not read).
- `flow`: src/dst (v4 = 4 bytes then zero-filled to the 16-byte union,
  v6 = 16; our parse's family decides), sport/dport (0 unless L4
  reached), proto, `flags` (F_ICMP|F_SYN_SET|F_RST_SET replayed from
  the ICMP arm + TCP flag bits), tos (v4 tos byte / v6 priority+flow_lbl
  top nibble). Under F_ICMP the addresses AND ports are the INNER,
  SWAPPED values — the projection mirrors the inversion.
### 7b. QUIC header spelling (deferred rung — recorded, not built)

For when a future rung models config as packet predicates: long header
= `flags:8 / version:32 / dcid_len:8 / dcid[0:16]` read at UDP payload
byte 0 when `flags & 0x80`; short header = `flags:8 / cid[0:16]`
otherwise; `cid_version = cid[0] >> 6` (select {1,2,3}, else 0xFF
sentinel); server_id V1 = `((cid[0]&0x3F)<<10)|(cid[1]<<2)|(cid[2]>>6)`,
V2 = `(cid[1]<<16)|(cid[2]<<8)|cid[3]`, V3 = `(cid[1]<<24)|…|cid[4]`;
long packet-type `< HANDSHAKE(0x20)` after masking 0x30 ⇒ is_initial
(fall back to hash, no id). All fixed-offset bit arithmetic.

**Laxness rule:** every packet gets a katran verdict; there is no
"further processing" escape at the wire. Our reject maps to XDP_DROP
only for the modeled DROP causes above; any reject we cannot map to a
katran DROP (e.g. an L4 truncation where katran would still XDP_PASS
the L3 keys) is either modeled to match or excluded with a boundary
note — checked, never skipped, exactly as dpdk_ptype.

## 8. Example scope + name

New example **`katran_flow`** (content-named). A field-for-field model
of the default-build parse path §6. Headers: Ethernet, IPv4 (with the
ihl≠5 and fragment gates as selects/rejects), IPv6, ICMP + ICMPv6
(type/code demux), an embedded inner IPv4/IPv6 for the ICMP path, TCP
(SYN/RST flag bits), and UDP. `max_depth`
small (the deepest path — eth/ICMP/inner-ip/inner-L4 — is ~5 states;
no cycles in the default build). Metadata: `is_icmp` (drives the
address/port inversion, the second metadata-v1 consumer after
flow-dissector's is_encap).

## 9. Gate shape

- **Committed golden** (privileged mint, flow-dissector factory
  pattern): `examples/katran_flow/conformance/katran.<pin>.golden.json`
  minted ONLY by `oracle/katran/factory/capture.sh` at pin dd915fd2
  with ALL MAPS EMPTY (config C collapses to "empty" now that QUIC is a
  boundary — the core parse needs no vip/real config). Everyday unprivileged gate test diffs our projection against
  it (`committed_goldens_agree` analog, floors, pin guard on the
  commit hash).
- **`diff katran`** CLI mirroring `diff dpdk-ptype`/`diff
  flow-dissector`.
- The version tag is the katran COMMIT HASH (not a kernel
  version — the incumbent is the userspace-visible XDP behavior, though
  the mint runs in-kernel).

## 10. Out of scope

Decap flavors (IPIP/GUE), stable-routing + TPR walk (non-default
flavors / future rungs), < 14B packets, all LB decision logic
(vip/LPM/LRU/consistent-hash/encap/stats — the projection stops at
parsed keys + parse-relevant verdict), and the echo-reply packet
MUTATION bytes (we assert the XDP_TX verdict, not the rewritten
output).

# `dpdk_ptype` design-lite: modeling DPDK's `rte_net_get_ptype()`

**Date:** 2026-07-29
**Status:** binding for the dpdk-ptype run (charter:
`docs/plans/2026-07-29-dpdk-ptype-charter.md`)
**Incumbent pin:** DPDK **23.11.4** (Ubuntu noble `libdpdk-dev`
23.11.4-0ubuntu0.24.04.2; behavior verified against upstream
`v23.11.4:lib/net/rte_net.c` — 509 lines — and empirically via the
in-container harness `oracle/dpdk_ptype/factory/capture.c`).

The function classifies **every** packet — there is no drop verdict. It
returns a `RTE_PTYPE_*` bit-mask plus `struct rte_net_hdr_lens` (l2/l3/
l4/tunnel/inner_l2/inner_l3/inner_l4 lengths), reading headers via
`rte_pktmbuf_read` (all-or-nothing per header struct) and stopping early
with a partial mask when a read fails. The `layers` argument is pinned to
`RTE_PTYPE_ALL_MASK` (what the harness passes); hdr_lens fields off the
taken path are left unwritten, so the harness zero-initializes.

## 1. Coverage map (from the pinned source; line numbers = v23.11.4)

The walk is a **straight pipeline** — no loops except the two bounded
ext-header walks. Each section falls through to the next; unmatched
dispatch values are never an error, they just stop adding bits:

- **L2** (:236-290): 14-byte Ethernet, no EtherType >= 0x0600 check.
  Then exactly one of:
  - `0x8100`: one 4-byte VLAN tag (bit claimed *before* the read), l2 18.
  - `0x88A8`: QinQ — reads ONLY the second tag at off+4 (the first tag's
    4 bytes, including its TPID, are skipped blind), l2 22.
  - `0x8847`/`0x8848`: **dead code in 23.11.4** — the MPLS loop has no
    bottom-of-stack break, so `i == MAX_MPLS_HDR` is always true and the
    function returns *before* `pkt_type = RTE_PTYPE_L2_ETHER_MPLS`
    (:279-289). Result: plain `L2_ETHER`, l2_len 14, identical whether
    the label stack is present, absent, or truncated. Verified
    empirically (harness: MPLS packet → ptype 0x1).
  There is no VLAN loop: a second tag falls through to the *inner*
  sections (see the double-VLAN quirk below).
- **L3** (:296-351): IPv4 iff `version_ihl` ∈ 0x45..0x4F via a lookup
  map (0x45 → `L3_IPV4`, 0x46-0x4F → `L3_IPV4_EXT`, anything else → no
  L3 bit **but the walk continues**); l3_len = ihl*4; options are
  arithmetic-skipped, never read. Fragment check `frag_off & 0x3FFF`
  (offset|MF, Res/DF ignored) → `L4_FRAG`, l4_len 0, stop. IPv6: fixed
  40 bytes; `proto` ∈ {0,43,44,50,51,60} → `L3_IPV6_EXT` else
  `L3_IPV6`; EXT triggers `rte_net_skip_ip6_ext` (:176-219):
  - HOPOPTS/ROUTING/DSTOPTS: read 2-byte prefix, advance (len+1)*8
    (body never read), loop.
  - FRAGMENT: read prefix, advance 8, `frag=1`, **always terminal**.
  - NONE (59): return 0 → stop with the EXT mask (l3_len includes
    consumed links).
  - anything else (incl. ESP/AH, despite being in the EXT *map*):
    returned as the final proto, no skip.
  - Bound: `MAX_EXT_HDRS` 5 — the 5th consumed option link exhausts the
    loop and returns -1 → EXT mask, **l3_len snaps back to 40** (:334
    returns before the :337 update), no L4, regardless of what follows.
  - Post-walk `proto == 0` check (:339) fires for a Fragment whose
    next_header is 0 (HOPOPTS): returns **without** the `L4_FRAG` bit.
- **L4** (:353-379): TCP — reads the fixed 20-byte header only, l4_len
  = doff*4 (doff unvalidated: 0..60 possible, options never read);
  truncated TCP strips the L4 bit (`return pkt_type & (L2|L3)`). UDP —
  never read at all, l4_len 8 blind. SCTP — never read, l4_len 12
  blind. Other protos: fall through to tunnel.
- **Tunnel** (:127-173): only three arms. GRE (47): opt_len table
  indexed by the C/R/K/S flag nibble — **version bits are never
  examined** (contrast: the kernel accept-stops on version != 0), and
  any R=1 combination yields opt_len 0 = "not a tunnel" (no bit, no
  advance, proto stays 47 → walk ends). Otherwise advance 4+C*4+K*4+S*4
  (optionals arithmetic-skipped, never read), proto := GRE proto field;
  TEB (0x6558) → `TUNNEL_NVGRE`, else `TUNNEL_GRE`. IPIP (4) →
  `TUNNEL_IP`, proto := 0x0800, zero-length. IPV6 (41) → `TUNNEL_IP`,
  proto := 0x86DD. **No UDP-based tunnels** (VXLAN/Geneve/GTP need port
  config; `rte_net_get_ptype` never looks behind UDP — those live in
  `rte_ethdev`/PMD land).
- **Inner** (:384-508): runs UNCONDITIONALLY after the tunnel section —
  reached with tunnel_len 0 whenever the leftover proto missed every
  earlier section. One TEB-gated inner Ethernet, then one inner
  VLAN-or-QinQ (same blind-second-tag QinQ read; inner VLAN *replaces*
  `INNER_L2_ETHER` rather than adding), then inner IPv4/IPv6 + ext walk
  + inner L4, all mirroring the outer rules with `INNER_*` bits. Inner
  TCP truncation returns `pkt_type & (INNER_L2|INNER_L3)` — **wiping
  the outer L2/L3/tunnel bits** (:498). Exactly one inner level: a
  second stacked tunnel is never dispatched (`ptype_inner_l4` knows
  only TCP/UDP/SCTP).

Consequences verified empirically (harness over the flow-dissector
corpus): double-VLAN classifies as `L2_ETHER_VLAN INNER_L2_ETHER_VLAN
INNER_L3_* INNER_L4_*` with no tunnel; Q-then-AD yields
`INNER_L2_ETHER_QINQ`; bare `0x88A8` + IPv4 misreads IPv4 bytes as the
second tag and still claims `L2_ETHER_QINQ`; eth/0x6558 directly enters
the inner-Ethernet path with no tunnel bit.

## 2. Validation behavior

`rte_net_get_ptype` validates **nothing but read bounds**. Modeled
faithfully, never corrected:

- Truncation over-claims: the VLAN/QinQ bits are set before the tag
  read; UDP/SCTP l4_len are reported without reading a byte (a
  zero-payload proto-17 IPv4 packet gets `L4_UDP`, l4_len 8).
- Truncation under-claims: TCP truncation strips the L4 bit; inner-TCP
  truncation wipes every outer bit.
- Arithmetic skips trust length fields: IPv4 options, IPv6 ext bodies,
  GRE optionals are advanced by claimed length without existence
  checks, so l3_len/tunnel_len can point past the packet end (observed:
  ext claiming 16 bytes with 8 present → `L3_IPV6_EXT` l3_len 56 on a
  62-byte packet).
- `version_ihl` outside 0x45..0x4F loses the L3 bit but keeps walking
  (an ihl=4 "IPv4" packet can still earn `L4_TCP` with no L3 bit, the
  L4 read overlapping IP header bytes).
- GRE version ignored; R bit = silently not-a-tunnel; NVGRE claimed for
  TEB without checking the key flag.

## 3. Projection: `ParseResult` → `(ptype, hdr_lens)`

Harness-side (Rust, `src/oracle/dpdk_ptype.rs`), a deterministic map
from OUR parse trace — instances extracted (in order), their fields, and
on reject the failing state + bit offset. Never reads raw packet bytes
beyond what our parser extracted (else the agreement claim is circular).

**Accept ⇒ exact.** Mask bits from the instance sequence + dispatch
values (e.g. `L3_IPV4` vs `L3_IPV4_EXT` from `version_ihl`; `L4_UDP`
from a terminal accept whose last next-proto value is 17 — UDP/SCTP are
*not extracted*, mirroring DPDK's blind l4_len). hdr_lens from fields:
l2 = 14 + 4·vlan + 8·qinq; l3 = ihl*4 | 40 + Σ(1+hel)·8 (+8 frag;
snap-back to 40 on the 5-link bail); l4 = doff*4 | 8 | 12 | 0;
tunnel = 4 + (c+k+s)*4 | 0; inner mirrors. The `proto==0`
fragment quirk: FRAG bit granted only when the fragment's next_header
!= 0.

**Reject ⇒ the laxness rule.** Our parser trunc-rejects where DPDK
early-returns; the projection maps *mappable* reject classes onto
DPDK's partial answer and the gate checks them like any entry — never
skipped. A reject class is mappable iff DPDK's answer needs neither the
failing header's field values nor bytes we didn't extract:

| failing state (avail bytes at state start) | DPDK's answer |
|---|---|
| ethernet < 14 | ptype 0, all lens 0 (eh read fails first) |
| vlan < 4 | prior mask + VLAN bit, l2 14 |
| qinq < 8 | prior mask + QINQ bit, l2 14 (DPDK's off+4 read fails iff ours does) |
| ipv4 < 20, ipv6 < 40 (outer or inner) | mask so far, l3/inner_l3 unwritten |
| ext_opt_k < 2 | mask so far (EXT already set), l3 stays 40 |
| ext_frag < 2 | mask so far, no FRAG bit, l3 stays 40 |
| gre < 4 | mask so far, no tunnel bit, tunnel_len 0 |
| tcp < 20 (outer) | mask & (L2\|L3), l4 0 |
| inner_tcp < 20 | mask & (INNER_L2\|INNER_L3) — outer bits wiped |
| inner_ethernet < 14 | mask so far, inner_l2 0 |

**Unmappable classes = documented boundary, excluded from the corpus**
(fragmented-IPv4 precedent from the flow-dissector README): rejects
where our eager `var_bytes` demands bytes DPDK arithmetic-skips —
IPv4 options region truncated (avail ≥ 20 at the ipv4 state), IPv6 ext
*body* truncated (avail ≥ 2 at an opt state), GRE optionals truncated,
fragment header truncated mid-way (avail 2..7), and the wrapped-length
reject for ihl < 5 (DPDK rewinds the cursor into the IP header; our
cursor is monotonic — inexpressible, boundary). The projection returns
a hard error for these, so a corpus line in an excluded class fails the
gate rather than passing silently. Phase 5 still *catalogs* DPDK's
behavior on these packets via the harness (observed, not gate-checked).

### 2b. Addendum (2026-07-29, during build): the byte-swap quirks

rte_net.c mixes endianness in two comparisons, discovered while writing
the projection and verified with six harness probes (all matched):

- `ptype_tunnel` (:132) switches the **big-endian** leftover proto
  against **host** `IPPROTO_*` case values. On little-endian hosts,
  EtherTypes **0x0400 / 0x2900 / 0x2F00** (BE bytes 04-00 / 29-00 /
  2F-00 read as host 4 / 41 / 47) classify as IPIP / IPv6-in-IP / GRE
  tunnels — e.g. `eth[0x0400]/IPv4/TCP` yields `TUNNEL_IP
  INNER_L3_IPV4 INNER_L4_TCP`.
- The inner-L2/L3 section compares the **host** u8 IP proto against
  **big-endian** EtherType constants: protocol **8** (EGP) == 
  `be16(0x0800)` parses an inner IPv4, protocol **129** ==
  `be16(0x8100)` parses an inner VLAN — both with NO tunnel bit
  (`ptype_tunnel` missed them).

Modeled with extra select arms on the L2 states (0x0400/0x2900/0x2F00)
and the outer IP/ext states (8/129). The agreement claim is therefore
**little-endian-host DPDK** (arm64/x86-64 — every mainstream DPDK
deployment); a big-endian build would classify these differently.

## 4. Example scope + name

New example **`dpdk_ptype`** — a field-for-field model of rte_net.c's
walk, NOT a reuse of `linux_flow_dissector` (kernel semantics: version
gate on GRE, VLAN depth rules, drop verdicts — all absent here).
Distinct header definitions where DPDK's masks demand it: IPv4 splits
the fragment word as `flags_res_df: bits(2)` + `mf_frag_off: bits(14)`
(so DPDK's 0x3FFF mask is an exact field); TCP is the fixed 20 bytes
with NO options region (DPDK never reads them); QinQ is an 8-byte
header `first_tag: bits(32)` (blind) + `tci` + `proto`; GRE splits
c/r/k/s/reserved9/version3/proto16 with **no select on version**.

State graph: a DAG, ~27 states, no cycles (the inner section never
loops back — one tunnel level by construction):

- `parse_ethernet` → {0x0800 ipv4, 0x86DD ipv6, 0x8100 vlan, 0x88A8
  qinq, 0x8847/0x8848 accept (MPLS dead code), 0x6558 inner_ethernet,
  default accept}
- `parse_vlan`/`parse_qinq` → {0x0800 ipv4, 0x86DD ipv6, 0x6558
  inner_ethernet, 0x8100 inner_vlan, 0x88A8 inner_qinq, default accept}
- `parse_ipv4`: single **multi-key select** on `(mf_frag_off,
  protocol)`: {(0,6) tcp, (0,4) inner_ipv4, (0,41) inner_ipv6, (0,47)
  gre, default accept} — frag≠0 hits default (accept; projection reads
  the field), UDP/SCTP/unknown hit default (never extracted).
- `parse_ipv6` → {0/43/60 ext_opt1, 44 ext_frag, 6 tcp, 4/41/47
  tunnel arms, default accept}; `ext_opt1..4` same arms (self-chain
  unrolled — DPDK's bound is 5 *reads*); `ext_opt5` extract + accept
  (the bail); `ext_frag` extract + accept (always terminal).
- `parse_gre`: select on `r` {0: gre_opt, default accept (R present =
  not a tunnel)}; `parse_gre_opt`: extract `var_bytes(c*4+k*4+s*4)`,
  select on `GRE.proto` {0x0800 inner_ipv4, 0x86DD inner_ipv6, 0x6558
  inner_ethernet, 0x8100 inner_vlan, 0x88A8 inner_qinq, default
  accept}.
- Inner mirror: `inner_ethernet` (→ inner_vlan/inner_qinq/inner IP),
  `inner_vlan`, `inner_qinq`, `inner_ipv4` (multi-key select → {(0,6)
  inner_tcp, default accept}), `inner_ipv6` + `inner_ext_opt1..5` +
  `inner_ext_frag`, `inner_tcp` — inner tunnels are default-accepts.
- `max_depth` 20 (longest path ≤ 18 states; DAG, so this is headroom,
  not a semantic bound).

No metadata fields (no `is_encap` analog — the mask carries
everything). Instance names disambiguate outer vs inner (`ipv4` vs
`inner_ipv4` etc.), which is what the projection keys on.

Symex expectation: DAG with two 5-unrolled chains — path count orders
of magnitude below the flow dissector's 57k; no cycle machinery.

## 5. Gate shape (both live + committed golden)

1. **Committed golden** (the reproducible claim):
   `examples/real_world/dpdk_ptype/conformance/ptype.dpdk-23.11.4.golden.json`,
   minted ONLY by `oracle/dpdk_ptype/factory/capture.sh` (build
   `capture.c` against the container's libdpdk, run over
   `oracle/dpdk_ptype/factory/corpus.txt`). Schema:
   `{dpdk_version, entries: [{packet_hex, ptype, ptype_name,
   hdr_lens{7 fields}}]}`. Always-on gate test
   (`committed_goldens_agree` analog) with count floors; every entry
   compared — accepts exactly, mappable rejects via the laxness rule.
2. **Live differential** (no staleness): a tool-gated cargo test (BMv2
   precedent) that, when `pkg-config libdpdk` resolves in-container,
   rebuilds the harness, re-runs the corpus, and (a) byte-compares the
   fresh capture against the committed golden (drift detector), (b)
   diffs our projection against it.
3. CLI: `diff dpdk-ptype` mirroring `diff flow-dissector`.

## 6. Out of scope (charter + findings)

- Multi-segment mbufs (`rte_pktmbuf_read`'s seg-walk path) — the
  harness builds single-segment mbufs; the generated-C spike inherits
  the same boundary.
- Runtime-configured tunnel ports (VXLAN/Geneve/GTP) — not in
  `rte_net_get_ptype` at all.
- Linux three-way diff; rte_flow.
- The unmappable reject classes of §3 (lazy-skip laxness + ihl<5
  rewind) — README boundary notes, phase-5 catalog entries, no corpus
  lines.
- `layers` masks other than ALL: the early-outs are pure gating, no
  reachable extra behavior worth modeling.

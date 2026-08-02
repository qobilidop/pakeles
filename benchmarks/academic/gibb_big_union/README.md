# `gibb_big_union` — Gibb et al.'s "big-union" parse graph

The union of the suite's scenario graphs, and its stress member:
802.1Q/802.1ad VLANs sharing a two-tag budget, 802.1ah/PBB, MPLS(≤5)
with EoMPLS, IPv4/IPv6 with the full L4 fan-out (ICMP/ICMPv6, TCP,
UDP, GRE(≤3) with NVGRE, IPsec ESP/AH, SCTP), VXLAN, ARP/RARP, and an
inner Ethernet under every tunnel. The paper counts **28 nodes and
677 paths** on the unrolled graph.

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24,
  Fig. 3e "big-union."
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013.
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-big_union.txt`. Reference only — the repo grants
  no license (empty LICENSE file); this transcription is original
  expression over the published facts (see the group README's
  licensing rule).

**Alias note:** the RMT paper's cost comparison (Fig. 6) and the
thesis charts label this graph "Composite."

## Comparison numbers

The paper's 28 nodes are the unrolled graph — directly comparable to
our state map. This transcription has **29 states**: the source's 28
nodes plus 1 mechanical state — the `MplsPayloadNibble` peek, which
dispatches the pseudo-field the source folds into its MPLS map (see
below). It was 31 until 2026-08-01: without a lookahead construct the
nibble had to be *consumed*, which forced `Ipv4Rest` / `Ipv6Rest`
duplicate-continuation states alongside the full IP headers. The
`lookahead` primitive deleted both. Our
path enumeration reports 1,306 accepting parse paths (the committed
symex suite carries 9,545 vectors once truncation/reject probes are
added); the paper's 677 uses a counting convention it does not spell
out, so the numbers sit side by side rather than being an identity.

## Transcription notes

- **Unmatched dispatch = accept.** No map in the source has a reject
  arm; every select here defaults to `accept()` — the graph
  classifies, it does not validate.
- **Shared VLAN budget.** `ieee802-1q` and `ieee802-1ad` share one
  counter (`max_var = vlan`, `max = 2`): a combined total of two
  tags. Unrolled as `parse_vlan_q1` (802.1Q entry) and
  `parse_vlan_ad` (802.1ad entry), both continuing at a shared
  `parse_vlan_q2` for the second tag, whose map has no further VLAN
  arms — a third tag falls to the default. Per the source, 802.1ad is
  followed only by 802.1Q or 802.1ah/PBB, and PBB runs
  unconditionally into the inner Ethernet.
- **MPLS ≤5, with the pseudo-field lookahead** transcribed as in
  `gibb_service_provider` (bos select per label state; on bos=1 a
  `lookahead(MplsPayloadNibble)` dispatches without consuming, so
  continuations extract their real full headers). This graph has the
  EoMPLS arm: nibble 0 → `Eompls` (the source's full control word,
  its leading `zero` nibble included — the peek consumed nothing) →
  inner Ethernet.
- **`map(fragOffset, protocol)` concatenates its keys** (per the
  artifact's format documentation): every IPv4 L4 arm is `(0, proto)`
  — only first fragments dispatch. The map is built once in
  `_ipv4_arms()` and shared by every entry into `Ipv4` (same for IPv6
  in `_ipv6_arms()`); before the `lookahead` conversion it also had
  to be shared with a duplicate `Ipv4Rest` state.
- **GRE ≤3, keyed on `(K, proto)` concatenated** (the source's
  `0x16558`/`0x16559` values = K=1 ++ proto): K=1 + 0x6558 → NVGRE →
  inner Ethernet; K=1 + 0x6559 → nested GRE. At the third GRE the
  bound is exhausted and the nested arm falls to the default.
- **VXLAN on UDP dstPort 65535 [sic].** The source's own comment:
  "Made up value for port — not yet assigned" (the paper predates
  the 4789 assignment). It stays 65535.
- **The AH map is transcribed as-is**, including its ICMPv6 arm —
  reachable even when AH was entered from the IPv4 path. The source
  is the source.
- **Options fields.** IPv4/TCP variable tails become
  `var_bytes(len*4 - 20)`; sub-5 length values wrap to a huge byte
  count and reject out of bounds. The artifact's `max_length` caps
  (256/192 bits) are hardware buffer bounds, not grammar, and are not
  modeled.
- **IPv6 addresses.** The source extracts srcAddr/dstAddr as 128-bit
  fields; 128 exceeds the eDSL's fixed-`bits` ceiling (64), so they
  are carried as constant-length opaque 16-byte runs (`var_bytes(16)`
  — same bits consumed, value-opaque), the house idiom from
  `linux_flow_dissector`.
- **GRE flag naming.** The source's case-distinct `S`/`s` pair
  becomes fields `s`/`strict` (display names keep the source's
  letters).
- **`max_depth = 17`**: the deepest unrolled path is 16 headers —
  Ethernet, 802.1ad, second VLAN tag, five MPLS labels, the peeked
  payload nibble, `Ipv4`, IPsec AH, three GREs, NVGRE, inner Ethernet
  (AH's GRE arm is what makes this the deepest) — plus one.

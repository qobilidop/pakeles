# `gibb_enterprise` — Gibb et al.'s "Enterprise" parse graph

Ethernet → {VLAN(≤2), IPv4, IPv6, ARP/RARP}: the campus-network
member of the parse-graph suite from *Design Principles for Packet
Parsers*. The IP pair dispatches to ICMP/ICMPv6/TCP/UDP; ARP/RARP
carries an IPv4 address body.

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24 —
  Fig. 3a "Enterprise."
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013 (the same suite, Fig. 4.4).
- Second consumer: Doenges et al., *Leapfrog: Certified Equivalence
  for Protocol Parsers* (PLDI 2022) uses this graph in its §7.2
  "Applicability" benchmarks.
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-enterprise.txt`. Reference only — the repo grants
  no license (empty LICENSE file); this transcription is original
  expression over the published facts (see the group README's
  licensing rule).

## Transcription notes

- **Unmatched dispatch = accept.** The source's `next_header` maps
  have no reject arm; a value outside the map simply ends the
  recognized header sequence. Every select here therefore defaults
  to `accept()` — the graph classifies, it does not validate.
- **VLAN bound unrolled.** The source bounds the `ieee802-1q` node
  with `max = 2`; the paper's figures draw the bound as two nodes.
  Transcribed as two states (`parse_vlan1`, `parse_vlan2`) over one
  header type; a third tag falls to the default (accept). The VLAN
  tag dispatches exactly as Ethernet does (same map in the source).
- **`map(fragOffset, protocol)` concatenates its keys** (per the
  artifact's format documentation), so L4 dispatch requires
  `fragOffset == 0` AND the protocol match — transcribed as a
  multi-key select with `(0, proto)` arms.
- **One ARP/RARP node.** The source maps both 0x0806 (ARP) and
  0x8035 (RARP) to a single `arp_rarp` node; one `ArpRarp` header
  here, with the IPv4 address body (`ArpRarpIpv4`) reached only via
  `protoType == 0x0800`.
- **ICMP and ICMPv6 are distinct nodes** in the source despite
  identical layouts; kept distinct (`Icmp`, `Icmpv6`).
- **128-bit IPv6 addresses.** The source extracts `srcAddr`/`dstAddr`
  as 128-bit fields; `bits()` tops out at 64 bits, so they are
  carried as constant-length opaque 16-byte runs (`var_bytes(16)`) —
  same bits consumed, value-opaque.
- **Options fields.** `length = ihl * 4 * 8` with a trailing `*`
  field becomes `options = var_bytes(ihl * 4 - 20)` (same for TCP's
  `dataOffset`). Sub-5 length values wrap to a huge byte count and
  reject out of bounds — the same idiom `linux_flow_dissector` uses
  for `doff < 5`. The artifact's `max_length` caps (256/192 bits)
  are hardware buffer bounds, not grammar, and are not modeled.
- **`max_depth = 6`**: the deepest unrolled path (ethernet, vlan,
  vlan, ipv4, l4 = 5 headers) + 1.
- Field names are ours (snake_case renderings of the source's).

## Cross-checked against Leapfrog

Cross-checked against Leapfrog (PLDI 2022), `lib/Benchmarks/Enterprise.v`
(Apache-2.0), which independently encodes this graph as a P4A automaton
for a self-equivalence proof. The state graphs are isomorphic (11 states
each, matching Table 2's 22 for the pair) with identical TPID, ARP/RARP,
and VLAN×2 structure. Leapfrog's copy deviates from parser-gen where
equivalence-to-itself doesn't care: header widths are truncated
(IPv4/IPv6 to 64 bits, options dropped), the L4 key omits `fragOffset`,
ICMPv6 is keyed at 1 rather than 58, unmatched ethertypes reject rather
than end recognition, and the IPv4 protocol select slices bits 72–79 of
a 64-bit header — a zero-width key under P4A's clamping slice, making
every IPv4 packet take the ICMP arm. We follow parser-gen on all of
these.

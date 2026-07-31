# `gibb_datacenter` — Gibb et al.'s "Data center" parse graph

Ethernet → {VLAN(≤2), IPv4, ARP/RARP} with the tunnel stack of its
era: GRE nested up to three deep, NVGRE, and VXLAN, each tunnel
ending in an inner Ethernet header. No IPv6 and no MPLS in this
graph.

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24 —
  Fig. 3b "Data center."
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013 (the same suite, Fig. 4.4).
- Second consumer: Doenges et al., *Leapfrog: Certified Equivalence
  for Protocol Parsers* (PLDI 2022) uses this graph in its §7.2
  "Applicability" benchmarks.
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-datacenter.txt`. Reference only — the repo grants
  no license (empty LICENSE file); this transcription is original
  expression over the published facts (see the group README's
  licensing rule).

## Transcription notes

- **Unmatched dispatch = accept.** The source's `next_header` maps
  have no reject arm; a value outside the map simply ends the
  recognized header sequence. Every select here therefore defaults
  to `accept()` — the graph classifies, it does not validate.
- **VXLAN port 65535 [sic].** The source dispatches UDP `dstPort ==
  65535` to VXLAN, with its own comment "Made up value for port --
  not yet assigned" — the graph predates the IANA 4789 assignment.
  Transcribed faithfully as 65535; no silent fix.
- **`map(K, proto)` concatenates its keys** (per the artifact's
  format documentation): the GRE map values 0x16558 and 0x16559 are
  the 1-bit `K` field (= 1) concatenated with the 16-bit protocol
  (0x6558 NVGRE inner / 0x6559 nested GRE) — transcribed as a
  multi-key select with `(1, proto)` arms. Same rule gives IPv4's
  `(0, proto)` L4 arms (`fragOffset == 0` AND the protocol match).
- **GRE bound unrolled.** The source bounds `gre` with `max = 3`;
  transcribed as three states (`parse_gre1..3`) over one header
  type. The third state drops the nested-GRE arm (a fourth nesting
  falls to the default, accept) but keeps the NVGRE arm at every
  depth.
- **VLAN bound unrolled** the same way (`max = 2`, `parse_vlan1`/
  `parse_vlan2`); a third tag falls to the default.
- **Inner Ethernet.** The source's `ethernet2` (terminal, after
  NVGRE and VXLAN) reuses the `Ethernet` header type as a second
  instance named `ethernet2`.
- **GRE flag names.** The source's single-bit flags `S` and `s`
  collide once snake-cased; they are `s` (sequence present) and
  `strict` (strict source route) here, with the source's spellings
  preserved in the display labels.
- **One ARP/RARP node** (0x0806 and 0x8035 both map to `arp_rarp`),
  with the IPv4 address body reached via `protoType == 0x0800`.
- **Options fields.** `options = var_bytes(ihl * 4 - 20)` for IPv4
  and `var_bytes(data_offset * 4 - 20)` for TCP; sub-5 length values
  wrap to a huge byte count and reject out of bounds. The artifact's
  `max_length` caps (256/192 bits) are hardware buffer bounds, not
  grammar, and are not modeled.
- **`max_depth = 10`**: the deepest unrolled path (ethernet, vlan,
  vlan, ipv4, gre, gre, gre, nv_gre_inner, ethernet2 = 9 headers)
  + 1.
- Field names are ours (snake_case renderings of the source's).

## Cross-checked against Leapfrog

Cross-checked against Leapfrog's `lib/Benchmarks/DataCenter.v`: 15
states each (Table 2: 30 for the pair), same VLAN×2 and GRE×3
unrolling, same NVGRE/VXLAN bodies and inner Ethernet, and the same
faithfully-carried pre-assignment VXLAN port 65535. Leapfrog's first
GRE state splits parser-gen's `map(K, proto)` value `0x16558` into
(K=1, 0x6558) exactly as we do; its deeper GRE states, however, key on
`proto` alone (the 17-bit literal truncates), it omits the `1 : icmp`
arm (leaving its ParseICMP state unreachable), drops `fragOffset` from
the L4 key, and rejects a fourth GRE where parser-gen simply stops
recognizing. We follow parser-gen on each point.

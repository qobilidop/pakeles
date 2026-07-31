# `gibb_service_provider` — Gibb et al.'s "Service provider" parse graph

Ethernet → MPLS(≤5) → {IPv4, IPv6}, with direct IPv4/IPv6 from
Ethernet: Fig. 3d of *Design Principles for Packet Parsers*. The MPLS
bound of five is the suite's deepest label stack, and the graph is
where the source's MPLS pseudo-field lookahead does real work.

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24,
  Fig. 3d "Service provider."
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013.
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-service_provider-fixed.txt` ("Designed for use in
  fixed parsers"). Reference only — the repo grants no license (empty
  LICENSE file); this transcription is original expression over the
  published facts (see the group README's licensing rule).
- Consumer: Leapfrog (Doenges et al., PLDI 2022) uses this graph in
  its §7.2 "Applicability" benchmarks.

**Variant note:** the artifact carries a second
`headers-service_provider-prog.txt` twin ("programmable" — its MPLS
tags are handled slightly differently). The fixed variant is what is
transcribed here; the twin is recorded, not a member.

## Transcription notes

- **Unmatched dispatch = accept.** The source's maps have no reject
  arm; a value outside the map ends the recognized header sequence.
  Every select defaults to `accept()` — the graph classifies, it does
  not validate.
- **MPLS bound unrolled.** `max = 5` becomes five states
  (`parse_mpls1`..`parse_mpls5`); a sixth label (bos=0 at the fifth)
  falls to the default — beyond the bound is not a recognized
  sequence.
- **The MPLS pseudo-field lookahead.** The source dispatches on
  `map(bos, next-header)` where `next-header` is a 4-bit
  *pseudo-field*: the next header's first nibble, used in decision
  only, never consumed. Transcribed by splitting the decision — each
  MPLS state selects on `bos` alone, and on bos=1 the nibble is
  extracted as its own 4-bit header (`MplsPayloadNibble`), with the
  IP continuations defined minus their leading 4 bits (`Ipv4Rest`,
  `Ipv6Rest`). Bit-for-bit the same language, no lookahead construct.
- **No EoMPLS in this graph.** The source's nibble map has only
  `b10100` (IPv4) and `b10110` (IPv6) — unlike big-union there is no
  EoMPLS arm; any other nibble falls to the default. The source's
  `next_header_def = b10001` is a test-bench input default, not
  grammar, and is not modeled.
- **IPv4/IPv6 are terminal.** This graph has no L4 dispatch — the
  source gives neither IP node a `next_header` map.
- **Options field.** `length = ihl * 4 * 8` with a trailing `*` field
  becomes `options = var_bytes(ihl * 4 - 20)`; sub-5 IHL values wrap
  to a huge byte count and reject out of bounds. The artifact's
  `max_length = 256` cap is a hardware buffer bound, not grammar, and
  is not modeled.
- **IPv6 addresses.** The source extracts srcAddr/dstAddr as 128-bit
  fields; 128 exceeds the eDSL's fixed-`bits` ceiling (64), so they
  are carried as constant-length opaque 16-byte runs (`var_bytes(16)`
  — same bits consumed, value-opaque), the house idiom from
  `linux_flow_dissector`.
- **`max_depth = 9`**: the deepest unrolled path is 8 headers
  (Ethernet, five MPLS labels, the payload nibble, `Ipv4Rest`), plus
  one.

## Cross-checked against Leapfrog

Cross-checked against Leapfrog's `lib/Benchmarks/ServiceProvider.v`
(Plain module, 11 states; Table 2: 22 for the pair). Both encodings use
the same extract-then-branch treatment of the MPLS payload nibble and
identical ethertype arms; the equal state counts are coincidental,
since the compositions differ: Leapfrog encodes the MPLS stack as one
self-looping state (unbounded, where parser-gen bounds it at `max = 5`;
we unroll five states), branches on bit 24 of the MPLS header for
bottom-of-stack (bit 23 in the MPLS format and in Leapfrog's own Edge
encoding), and unrolls IPv4 options into per-IHL states 5–8 — a
fixed-width-formalism necessity that also reads parser-gen's
`max_length = 256` as a grammar cap, where we treat it as a hardware
buffer bound and keep the full IHL range.

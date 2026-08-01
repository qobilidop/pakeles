# `gibb_simple` — Gibb et al.'s "simple" parse graph

Ethernet → VLAN(≤2) → IPv4 → {TCP, UDP}: the smallest member of the
parse-graph suite from *Design Principles for Packet Parsers*. It is
the baseline bar in the hardware cost comparisons (RMT Fig. 6 and
thesis Fig. 3.11 label it "Simple").

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24.
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013 (Fig. 3.11 "Simple").
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-simple.txt` ("Simple parse graph example:
  Ethernet, VLAN, IPv4, TCP, and UDP only"). Reference only — the
  repo grants no license (empty LICENSE file); this transcription is
  original expression over the published facts (see the group
  README's licensing rule).

**Provenance note:** this graph is NOT in the paper's Figure 3 (the
five figure members are Enterprise, Data center, Edge, Service
provider, and big-union); it exists in the artifact and in the
RMT/thesis cost charts. It is kept in the suite here so the
comparison set for those charts is complete.

## Transcription notes

- **Unmatched dispatch = accept.** The source's `next_header` maps
  have no reject arm; a value outside the map simply ends the
  recognized header sequence. Every select here therefore defaults
  to `accept()` — the graph classifies, it does not validate.
- **VLAN bound unrolled.** The source bounds the `ieee802-1q` node
  with `max = 2`; the paper's figures draw the bound as two nodes.
  Transcribed as two states (`parse_vlan1`, `parse_vlan2`) over one
  header type; a third tag falls to the default (accept).
- **`map(fragOffset, protocol)` concatenates its keys** (per the
  artifact's format documentation), so L4 dispatch requires
  `fragOffset == 0` AND the protocol match — transcribed as a
  multi-key select with `(0, proto)` arms.
- **Options fields.** `length = ihl * 4 * 8` with a trailing `*`
  field becomes `options = var_bytes(ihl * 4 - 20)` (same for TCP's
  `dataOffset`). Sub-5 length values wrap to a huge byte count and
  reject out of bounds — the same idiom `linux_flow_dissector` uses
  for `doff < 5`. The artifact's `max_length` caps (256/192 bits)
  are hardware buffer bounds, not grammar, and are not modeled.
- The artifact file spells one IPv4 field `identificaiton` [sic];
  field names here are ours (`identification`).
- The four VLAN TPIDs (0x8100, 0x9100, 0x9200, 0x9300) are the
  source's, including the three pre-standard legacy values.

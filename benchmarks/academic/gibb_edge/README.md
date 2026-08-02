# `gibb_edge` — Gibb et al.'s "Edge" parse graph

Ethernet → {MPLS(≤2), IPv4, IPv6}, with the MPLS pseudo-wire
first-nibble lookahead deciding between EoMPLS (→ inner Ethernet),
IPv4, and IPv6. No VLAN, and no L4 dispatch anywhere — IPv4 and IPv6
are terminal in this graph.

**Aliases in the corpus:** this is "Edge" in the paper's primary
figure (Fig. 3c, the name used here per the group naming rule), but
"Enterprise Edge" in the paper's Fig. 15, and "Core router" in the
RMT paper and the thesis. The artifact file's own banner reads
"Enterprise edge parse graph".

## Source

- Glen Gibb, George Varghese, Mark Horowitz, Nick McKeown. *Design
  Principles for Packet Parsers.* ACM/IEEE ANCS 2013, pp. 13–24 —
  Fig. 3c "Edge."
- Glen Gibb. *Reconfigurable Hardware for Software-Defined Networks.*
  PhD thesis, Stanford University, 2013 (the same suite, Fig. 4.4).
- Second consumer: Doenges et al., *Leapfrog: Certified Equivalence
  for Protocol Parsers* (PLDI 2022) uses this graph in its §7.2
  "Applicability" benchmarks.
- Artifact reference: `github.com/grg/parser-gen`,
  `examples/headers-edge.txt`. Reference only — the repo grants no
  license (empty LICENSE file); this transcription is original
  expression over the published facts (see the group README's
  licensing rule).

## Transcription notes

- **Unmatched dispatch = accept.** The source's `next_header` maps
  have no reject arm; a value outside the map simply ends the
  recognized header sequence. Every select here therefore defaults
  to `accept()` — the graph classifies, it does not validate.
- **The MPLS pseudo-field lookahead → nibble-split pattern.** The
  source dispatches on `map(bos, next-header)` where `next-header`
  is a 4-bit *pseudo-field*: decision-only lookahead read from the
  NEXT header, never consumed (values `b0xxxx` → MPLS, `b10000` →
  EoMPLS, `b10100` → IPv4, `b10110` → IPv6). Each MPLS state
  dispatches on `bos` alone (bos=0 → next label, nothing else
  consumed); on bos=1 a dedicated state **peeks** the nibble with
  `lookahead(MplsPayloadNibble)` and dispatches on it, and because a
  peek consumes nothing the continuations extract their real full
  headers (`Ipv4`, `Ipv6`, and `Eompls` with its leading `zero`
  nibble intact). *Before 2026-08-01 the IR had no lookahead, so the
  nibble was consumed and each continuation needed an invented
  `*Rest` twin defined minus its leading 4 bits.*
- **One shared nibble state** serves both MPLS depths (bos=1 from
  `parse_mpls1` and `parse_mpls2` both target it).
- **MPLS bound unrolled.** The source bounds `mpls` with `max = 2`;
  transcribed as two states over one header type. From the second
  label, bos=0 falls to the default (accept) — beyond the bound is
  not a recognized sequence.
- **One IP header type per protocol.** Direct entries from Ethernet
  and post-MPLS entries now share the same full `Ipv4`/`Ipv6` types;
  the split twins the nibble-consuming encoding required are gone.
- **`next_header_def = b10001` is not modeled** — per the artifact's
  format documentation it is a test-bench input default, not
  grammar.
- **128-bit IPv6 addresses.** The source extracts `srcAddr`/`dstAddr`
  as 128-bit fields; `bits()` tops out at 64 bits, so they are
  carried as constant-length opaque 16-byte runs (`var_bytes(16)`) —
  same bits consumed, value-opaque.
- **Options fields.** `options = var_bytes(ihl * 4 - 20)` for both
  IPv4 variants; sub-5 length values wrap to a huge byte count and
  reject out of bounds. The artifact's `max_length` cap (256 bits)
  is a hardware buffer bound, not grammar, and is not modeled.
- **Inner Ethernet.** The source's `ethernet2` (terminal, after the
  EoMPLS control word) reuses the `Ethernet` header type as a second
  instance named `ethernet2`.
- **`max_depth = 7`**: the deepest unrolled path (ethernet, mpls,
  mpls, the peeked nibble, eompls, ethernet2 = 6 headers) + 1. The
  peek costs a state but consumes no bits.
- Field names are ours (snake_case renderings of the source's).

## Cross-checked against Leapfrog

Cross-checked against Leapfrog's `lib/Benchmarks/Edge.v` (Plain module,
14 states; Table 2: 28 for the pair). Leapfrog independently arrived at
the same *emulation* of parser-gen's `pseudo-fields` lookahead this
transcription used until 2026-08-01: a consumed 4-bit version-nibble
header followed by remainder headers (their 28-bit EoMPLS and 316-bit
IPv6 matched our then-`EomplsRest`/`Ipv6Rest` bit-for-bit). Two tools
independently reaching for the same workaround is the clearest
evidence a lookahead primitive earns its place; with `lookahead()` the
peek consumes nothing and the continuations are the full 32-bit EoMPLS
and 320-bit IPv6 headers. The 0/4/6 nibble map, MPLS×2 unrolling, and
accept-on-unmatched Ethernet are unchanged. The 14-vs-8 state-count
difference decomposes exactly, and every term is an encoding artifact
rather than a language difference: P4A cannot express variable-length
IPv4 options, so Leapfrog unrolls IHL into four fixed-width states
plus a dispatch state (+3) and adds two shim states so the direct
Ethernet→IP path also consumes the version nibble (+2), while sharing
one post-nibble IPv6 state (−1); and it keeps the two remainder-header
states (+2) that the lookahead encoding no longer needs. 8+3+2−1+2 =
14. Before 2026-08-01 that last term was absent and ours was 10.

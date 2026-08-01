# Standing notes: the publication/positioning pass (next arc)

Short notes from the 2026-07-31 end-of-session review, so nothing is
lost between sessions. Not a charter — the seed for one.

## The next arc is the publication pass, and its inputs are ready

- **Corpus:** 18 members in paper vocabulary — `benchmarks/industry/`
  (7 incumbent-agreement claims, each pinned + golden-gated),
  `benchmarks/academic/` (8 transcriptions cited to source),
  `examples/` (3 tutorials). All green on main.
- **Oracle diversity:** six shapes — a kernel (flow dissector via
  BPF_PROG_TEST_RUN), a C library (DPDK), a patched eBPF program
  (katran), BMv2 P4-vs-P4 (sai, dash), a TLS library (rustls), a dual
  QUIC-stack lane (quiche + quinn with pinned divergences).
- **Headline artifacts:** two kernel-verifier-clean generated eBPF
  parsers (tls @ depth 22, quic at committed depth); four committed
  parity-boundary artifacts (P4-UNSUPPORTED: regions ×2 flavors,
  varint varbit bounds; LUA-UNSUPPORTED: 62-bit values); the QUIC
  varint verdict (self-sizing fields reduce to existing IR); the
  Gibb pseudo-field finding (the only lookahead driver ever found
  reduces to the split-header pattern).
- **The Leapfrog cross-check is publishable on its own:** certified
  A≡A′ never checks A≡source; independent transcription + arbitration
  against parser-gen found five slips in Leapfrog's encodings
  (ICMPv6=1, missing ICMP arm, zero-width IPv4 select, bos off-by-one,
  truncated 17-bit GRE literal) — all invisible to their theorems.
  Details in the four `benchmarks/academic/gibb_*` READMEs.
- **Citation hooks:** the gallery holds all three ParserHawk
  (SIGCOMM'25) benchmark sources (switch.p4, sai, dash); Gibb's
  graphs double as Leapfrog's benchmarks; classic switch.p4 carries
  the p4v/Vera/bf4/SafeP4/Gauntlet record.

## The P4-16 parser coverage claim (2026-07-31 analysis)

Measured over all committed IRs: every construct the IR has is
exercised by ≥1 member. Against the P4-16 parser chapter:

- **Covered:** fixed + variable extraction, multi-key select, masked
  arms, bounded stacks (unrolled/cyclic), lookahead (as split-header
  pattern), verify/errors (dash), subparser use cases (state
  composition), sized regions + remaining() (beyond P4).
- **Out of scope by thesis:** parser value sets (runtime-mutable
  dispatch vs decidability-by-construction) — none of the seven
  industry incumbents uses one; cheap, evidenced boundary.
- **Engine-supported, zero drivers, unauthorable from Python:**
  IR-native RANGE keyset entries (range() sugar expands to exacts);
  expression select keys (BinOp keys — IR-legal, eDSL fixed-field
  only). Each is a small eDSL exposure whenever a driver appears
  (masked() was in this exact state until switch.p4 drove it).
- Half-exercised: packet-level remaining() (no-region form) as a
  select key.

## Deferred targets (all recorded, none urgent)

- `everparse_bitcoin` — cheap academic add; CompactSize varint =
  the QUIC two-field split; nested counted structures.
- X.509/DER — the realism heavyweight if another industry claim is
  ever wanted (oracles: `der`/`x509-parser`).
- BGP path attrs — demoted: post-QUIC analysis says it likely forces
  no new IR (extended-length flag = the two-field split; NLRI
  ceil-bits = existing exprs).
- Leapfrog Utility pair-gate — demoted (too specialized; design
  recorded in the academic-gallery memory if ever revisited).

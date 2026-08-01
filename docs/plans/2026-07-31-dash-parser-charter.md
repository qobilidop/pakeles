# Autonomous run: dash_parser — Azure's DASH BMv2 parser vs simple_switch

**Date:** 2026-07-31
**Status:** charter (user-approved this session; follows the landed
p4lang_switch_parser arc). Seventh real_world incumbent-agreement
target, the sai_parser pattern end to end.
**Done =** full gate green on main with
`real_world/dash_parser`: our transcription of DASH's BMv2 parser
agreeing with the ACTUAL instrumented parser running on
simple_switch over a committed corpus (version-tagged golden), plus
README (scope/laxness/quirks), registration, memory.

## Source & oracle

- **Incumbent:** sonic-net/DASH (Microsoft's Disaggregated APIs for
  SONiC Hosts — the Azure SmartNIC data-plane lineage), pinned @
  `d5c003dd7774` (HEAD at charter time; activity has decelerated —
  22 commits in 2025 — so the pin matters and is README-noted).
  Apache-2.0.
- **Modeled artifact:** `dash-pipeline/bmv2/dash_parser.p4` (+
  `dash_headers.p4`) — the parser's own file name gives the example
  name, per the katran/sai rule. 14 states, 13 header types, two
  layers (u0 underlay + customer overlay after VXLAN).
- **Oracle = the sai_parser factory pattern, verbatim:** vendor the
  pinned parser + headers into `third_party/dash/` (Apache-2.0,
  copied verbatim + PROVENANCE.md, per the third_party rule);
  `factory/instrument.py` wraps the UNMODIFIED parser in a minimal
  v1model harness that emits header-validity + key fields;
  p4c-bm2-ss compiles it; `capture.py` replays the corpus through
  simple_switch; golden `dash.<pin12>.golden.json` (pin in the
  filename). The 20 pipeline-stage includes of dash_pipeline.p4 are
  NOT needed — the parser is self-contained with its headers file.
- **Academic footnote for the README:** dash_pipeline.p4 is itself a
  published benchmark (P4Testgen SIGCOMM'23; ParserHawk SIGCOMM'25
  uses dash_parser.p4 directly) — with sai_parser and
  p4lang_switch_parser this completes ParserHawk's three benchmark
  sources in the gallery.

## Scope & expected shape

Transcribe `dash_parser.p4` exactly: start → u0_ethernet →
{dash-metadata header path, u0_ipv4 (IHL select → options state —
`var_bytes` on ihl), u0_ipv6} → u0 L4; u0_udp dst_port → VXLAN →
customer_ethernet → customer IPv4/IPv6 → customer TCP/UDP. Every
select value from the source (including the DASH packet-metadata
ether-type sentinel and the VXLAN port). P4-16 `transition accept` /
implicit reject semantics mapped per source (their parser DOES use
explicit rejects — mirror them, unlike the classify-only academic
graphs). Projection: header-validity set + the fields the
instrumented oracle emits; laxness matrix per divergence found (the
sai precedent). Quirk grounds: IHL ladder (options), sentinel
ether-type collisions, VXLAN port on TCP, truncations at every
boundary, customer-layer confusion.

## Phases

0. Preflight: branch `dash-parser` (done); charter commit.
1. Vendor `third_party/dash/` (pinned copy + PROVENANCE.md) +
   factory (instrument.py / capture.py / capture.sh / corpus ≥ 40,
   mk-corpus deterministic) + mint golden in-container. STOP gate:
   p4c-bm2-ss or simple_switch can't run the instrumented parser
   (their own CI does, so expected pre-passed).
2. Transcription `dash_parser.py` + example crate
   `pakeles-example-dash-parser` (sai lib.rs/main.rs template:
   projection, laxness, diff, gate tests incl. golden pin-prefix +
   corpus floor) + registration (workspace member, REAL_WORLD lists
   ×3, real_world README row, root README count 6→7 real-world).
3. Full gate; witness replay through the factory; README quirk
   catalog (honest none if none).
4. Closure: ff-merge + push on green; CI verified; memory updated.

## Ground rules

As every prior run. Factory adds NAMED files only; goldens minted
only by the factory; the vendored tree is verbatim-with-PROVENANCE
(no edits — instrumentation happens in factory/build at capture
time, the sai instrument.py way). If the DASH parser turns out to
need IR we don't have (nothing suggests so — it is small and
conventional), STOP and report.

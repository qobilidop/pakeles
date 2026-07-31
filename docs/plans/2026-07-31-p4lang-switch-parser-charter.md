# Autonomous run: p4lang_switch_parser — the scale stress test

**Date:** 2026-07-31
**Status:** charter (user-approved this session, with the naming and
source decisions below made explicitly by the user).
**Done =** full gate green on main with `academic/p4lang_switch_parser`
— the parser of classic switch.p4, the most-cited P4 program in the
literature — transcribed at full shipped-default size (63 states, 57
header types, 56 instances), the 64-bit verdict-bitmap tier landed,
stress findings documented (symex scale, eBPF unroll), READMEs +
memory updated.

## Source (binding, user decisions)

- **Repo:** `p4lang/switch` @ master `7874f565` (final commit,
  2020-10-29). P4_14. Apache-2.0 file headers (no root LICENSE —
  reference-only per group rules; transcription is original
  expression over facts).
- **Configuration:** the SHIPPED defaults — `p4features.h` untouched
  (FABRIC_ENABLE, INT_EP_ENABLE + INT_TRANSIT_ENABLE ⇒ INT_ENABLE,
  SFLOW_ENABLE all ON; no *_DISABLE; ADV_FEATURES off) plus
  `__TARGET_BMV2__`. Pin sentence: "switch.p4 @ 7874f565, as-shipped
  feature defaults, BMv2 target." Preprocessed inventory (verified):
  **63 parser states, 57 header_types, 56 header instances** incl.
  stacks `vlan_tag_[2]`, `mpls[3]`, `int_val[24]`.
- **Deliberately NOT the 2017 P4-16 translation** (user call: align
  with the original repo's latest state). The translation
  (jafingerhut/p4lang-tests, ParserHawk's ref) becomes a secondary
  cross-reference, README-noted.
- **Name:** `p4lang_switch_parser` (user call): org-qualified because
  "switch" is a generic word — new naming-rule nuance for the group
  README; component `parser` = the source's own file
  (includes/parser.p4), the katran/sai rule.
- Preprocessed reference files (facts source for transcription):
  scratchpad `switch-p4/{parser.pp.p4, headers.pp.p4}`.

## Why this target

User goal: realistic, complicated parsers stressing expressiveness.
switch.p4 is the citation champion — p4v (SIGCOMM'18, "58 parse
states" in its modified config, verified <3 min), Vera (SIGCOMM'18:
"the largest P4 program available today"), bf4 (SIGCOMM'20, 165
bugs), SafeP4 (ECOOP'19 bug study), Gauntlet (OSDI'20, translated),
ParserHawk (SIGCOMM'25, parser subsets via the P4-16 translation).
With sai_parser and (next arc) dash_parser, the gallery holds all
three of ParserHawk's benchmark sources. Our full-parser numbers —
states, symex paths, witness-suite size, backend artifact sizes —
land beside all of these.

## Expected stress findings (document, don't force)

- **Verdict bitmap:** 56 instances > 32 → 64-bit tier
  (`bitmap_bits`: 8/16/32/64, error >64). Mechanical, driven, own
  commit — the "different encoding" alternative is not needed at 56.
- **max_depth:** deepest path runs ≈ 40+ states (INT stack ×24 on the
  tunnel path). Compute from the transcribed graph; document.
- **eBPF unroll:** 63 states × depth ~40 will likely exceed the
  kernel's 1M-insn budget at committed depth (tls precedent: 96
  states clean only ≤ 22). The gate's rbpf conformance still runs;
  a real-kernel load attempt is OPTIONAL here (academic group has no
  eBPF deliverable bar) — if attempted, a rejection is a documented
  finding, not a failure.
- **Symex scale:** path count unknown; could exceed the 57k
  flow-dissector record. gen_vectors runs release-mode; if generation
  time is unacceptable for CI, that is a REAL finding — options
  (document, pick in-flight): arm coalescing (precedent), suite
  sampling with a floor, or a per-example testgen budget. Do NOT
  silently drop the example from the suite.
- **P4_14 semantic notes:** current-state parsing of the source is
  fixed-width-heavy (verify: does parse_ipv4 consume options?); the
  `int_val[24]` stack loop; ROCE/FCoE/TRILL/NSH arms; nested tunnel
  re-entry (inner ethernet → inner IP). Every transcription choice
  README-documented per group rules.

## Phases

0. Preflight (done): branch `p4lang-switch-parser`; charter commit.
1. Engine: 64-bit verdict-bitmap tier + tests (own commit, mirrors
   the 32-bit tier commit 761da6d).
2. Transcription: `examples/academic/p4lang_switch_parser/` — .py
   from the preprocessed facts (delegated build, reviewed); expect
   the .py to be the gallery's largest by far. Registration
   checklist (ACADEMIC ×4 lists + group README row + naming nuance).
   Pipeline per example: eDSL → fmt-ir → lint → gen_examples →
   academic battery.
3. Full gate; measure and record: state count, symex path count +
   generation time, suite size, backend artifact sizes; adjust CI
   posture only if measurements force it (documented).
4. Closure: commit/push/CI green; memory (academic-gallery roster,
   p4-parity notes if any new boundary appears); README counts.

## Ground rules

As all prior runs: single line of work; full gate per commit batch;
transcription-notes honesty (source quirks stay, e.g. whatever
oddities the P4_14 parser contains); facts-not-text from the source;
if a wall needs engine work beyond the bitmap tier, STOP and report.
The follow-on `dash_parser` arc (real_world, sai_parser pattern) is
SEPARATE — chartered after this lands.

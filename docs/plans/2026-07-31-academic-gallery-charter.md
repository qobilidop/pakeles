# Autonomous run: the academic/ gallery group — wave 1 (Gibb + Kangaroo)

**Date:** 2026-07-31
**Status:** charter (user-approved direction + roster this session).
**Done =** full gate green on main with a third gallery group
`examples/academic/` (group README with the naming/licensing rules
below, machinery extended in dev tools + pytest + scripts), seven
committed transcriptions — `gibb_simple`, `gibb_enterprise`,
`gibb_datacenter`, `gibb_edge`, `gibb_service_provider`,
`gibb_big_union`, `kangaroo_parse_tree` — each with regenerated
artifacts and a Source-cited README, plus memory updated.

## Why this group exists

The real_world collection is judged sufficient (user, this session);
the marginal value of new examples is comparability, not engine
growth. `academic/` holds **descriptions reproduced from published
evaluations, cited to source**: our full pipeline (state counts, symex
path counts + witness suites, five backends) runs over the same
artifacts the literature evaluated, so our numbers sit next to
published ones. Wave 1 = the parse graphs of Gibb et al. ANCS 2013
(the canonical parser-design paper; also the benchmark set Leapfrog
[PLDI 2022] certified equivalences over — one transcription, two
literatures of comparison) + Kangaroo's Cisco parse tree (INFOCOM
2010). Deliberately NOT agreement targets: there is no runnable
incumbent; the gate is the synthetic-class battery.

## Group rules (these go in the group README, normative)

Naming extends the real_world scheme (`<namespace>_<component>`):

1. **Namespace = the work's own brand name if it has one**
   (kangaroo, leapfrog, everparse), **else first-author surname**
   (gibb — "parser-gen" is generic, and the literature attributes the
   graphs to Gibb et al.; Leapfrog's own citation practice).
2. **Component = the item's name in the work's PRIMARY figure/table**,
   snake-cased ("big-union" → `big_union`); when the work itself
   spells a multi-word name both ways, prefer its compact artifact
   spelling (`datacenter` per headers-datacenter.txt + Leapfrog's
   "Datacenter", over Fig 3's "Data center" — user call, this
   session); in-corpus aliases (Fig 3 "Edge" = Fig 15 "Enterprise
   Edge" = RMT/thesis "Core router"; "big-union" = RMT "Composite")
   are recorded in the example README, not the name. **Where the work
   doesn't name its item, fall back to the work's own noun** —
   `kangaroo_parse_tree` — the exact rule that produced
   `katran_parser`.
3. **Derived items belong to their origin namespace.** Leapfrog's
   "Applicability" benchmarks ARE Gibb's graphs (its §7.2 says so);
   they land here once as `gibb_*`, with Leapfrog cited as a second
   consumer in those READMEs. A downstream work gets entries only for
   items it adds.
4. **Fixed published items only.** Parameterized generators
   (Whippersnapper) are bench tooling, not gallery members. Grammars
   requiring IR we deliberately declined (Nail's DNS compression /
   ZIP offsets — backward references) are citations, not members.
5. **Licensing: transcribe facts from the papers; never vendor or
   copy artifact files.** Graph structure, dispatch values, and
   bounds are facts; our eDSL text is original expression.
   Specifically: `grg/parser-gen`'s LICENSE file is EMPTY (no grant) —
   its files are reference-only. Leapfrog's repo is Apache-2.0.
   Every example README carries a **Source** section: citation,
   figure/table, artifact reference, and a **Transcription notes**
   list of every interpretive choice.

## Wave-1 items and their binding facts

From ANCS 2013 Fig 3 (+ thesis Fig 4.4; parser-gen `examples/` as
factual reference — the agent-verified header sets and bounds):

- `gibb_simple` — Eth, VLAN(×2), IPv4, TCP, UDP. Repo/thesis-only
  (NOT in Fig 3 — provenance nuance in README; kept for the
  RMT-Fig-6 / thesis-Fig-3.11 comparison set).
- `gibb_enterprise` — + IPv6, ICMP/ICMPv6, ARP/RARP (+ARP-IPv4 body).
- `gibb_datacenter` — VLAN, IPv4-only, GRE(×3 nested via
  K+proto=0x6559), NVGRE (K+proto=0x6558), VXLAN (via UDP dstPort
  65535 — the paper predates the 4789 assignment; transcribe 65535
  faithfully, README-note it), inner Ethernet terminal.
- `gibb_edge` — MPLS(×2), EoMPLS → inner Ethernet, IPv4/IPv6
  terminal (no L4 dispatch in this graph).
- `gibb_service_provider` — MPLS(×5) → IPv4/IPv6 (fixed variant;
  the repo's `-prog` twin is a README note, not a member).
- `gibb_big_union` — the 28-node/677-path union: adds 802.1ad
  (shared VLAN budget with 802.1Q, ≤2 combined), 802.1ah/PBB → inner
  Ethernet, SCTP, IPsec ESP (terminal) / AH (with nextHdr dispatch),
  MPLS(×5), GRE(×3). The paper's 28 nodes = the UNROLLED graph
  (21 header types + repetitions) — which is exactly our state map.
- `kangaroo_parse_tree` — from §VII prose (the only prose-sourced
  item): Ethernet → shims {802.1Q, nested 802.1Q, recirc tag,
  service tag, 802.1ah, 802.1ad} → up to 4 MPLS | ARP | RARP | IPv4
  | IPv6; MPLS → Eth/IPv4/IPv6; IPv4/IPv6 → TCP/UDP/GRE/ESP/ICMP/
  IPv4-in-IP; IPv6 → ext header → TCP/UDP/ESP/ICMPv6; GRE → IPv4/
  IPv6. README documents each interpretive choice: the Cisco-internal
  recirc/service-tag EtherTypes are unpublished (placeholder values,
  clearly marked), "resirc" is the paper's own spelling [sic], and
  the "3 IPv4 lengths / 8 GRE lengths" remark describes their TCAM
  entry counts, not distinct grammars — our IHL/GRE-flag handling
  covers those ranges natively.

## Transcription semantics (binding, from the format spec)

- **Dispatch maps concatenate their key fields** (`map(fragOffset,
  protocol) { 6 : tcp }` = fragOffset 0 AND protocol 6) → our
  multi-key select with tuple arms, natively.
- **Unmatched dispatch = end of recognized sequence** → every select
  `default=accept()`. These graphs classify; they do not validate.
- **MPLS `pseudo-fields` lookahead** (the 4-bit next-header nibble,
  decision-only, not consumed): modeled by dispatching on `bos`
  FIRST (bos=0 → next label, nothing consumed), and only on bos=1
  extracting the nibble as its own 4-bit header, with IPv4/IPv6/
  EoMPLS continuations defined minus their leading 4 bits. Bit-for-
  bit faithful; zero new IR. NOTE for [[p4-parity-ambition]]: this is
  the first real DRIVER for peek/lookahead ever seen in this project
  — and the split-header pattern covers it, so peek stays out of the
  IR with a better justification than "no driver".
- **Bounded repetition** (VLAN≤2, MPLS≤2/5, GRE≤3): unrolled states
  (the paper draws the unrolling in Fig 3), one instance per header
  type (repeated extracts append to the result; the multi-instance
  restriction is var-width-only). `max_depth` = deepest unrolled
  path + 1, documented per example.
- **IPv4/TCP options**: `var_bytes(ihl*4 - 20)` / `(dataOffset*4 -
  20)`; sub-5 values wrap to a huge length → oob reject (the
  linux_flow_dissector `doff<5` idiom). parser-gen's `max_length`
  caps (256/192 bits) are hardware buffer bounds, not grammar —
  README-noted, not modeled.

## Engine change (one, driven): 32-bit verdict bitmap tier

`gibb_big_union` has ~24 header instances; the P4 backend's verdict
bitmap caps at 16 (`bitmap_bits`) and hard-errors beyond. These
graphs are the ancestors of P4 — a refusal marker would be wrong.
Add a 32-bit tier (8/16/32, hard error >32). Wire format changes
only for parsers with >16 instances, so all committed artifacts are
stable. Own commit, latent-limitation protocol.

## Phases

0. Preflight: branch `academic-gallery`, commit charter.
1. Machinery: `examples/academic/` + group README (rules above);
   `pakeles-dev` ACADEMIC table + `gallery()`; `gen-examples.sh`
   group loop; `conftest.py` three-way group resolution;
   `rust/pakeles/tests/academic_gallery.rs` (the synthetic battery,
   loading committed ir.json from disk — validate + canonical +
   artifacts-current + C/eBPF conformance per example; Lua for all;
   BMv2 for `gibb_simple` + `gibb_enterprise` only, gate-cost bound);
   root README gallery prose. Bitmap tier change.
2. `gibb_simple` end-to-end as the pipeline prover (own commit).
3. Remaining five gibb graphs + kangaroo (small commits, full gate
   per commit batch).
4. Closure: full gate, ff-merge + push on green, CI verified, memory
   updated ([[p4-parity-ambition]] lookahead-driver note; new
   academic-gallery memory; roster status: wave 2 = Leapfrog pair-gate
   pattern + 3 pairs, deferred `everparse_bitcoin`).

## Ground rules

As every prior run: single line of work; full gate per commit;
never commit generated suites (gitignored); `git status` after each
commit; transcription-notes honesty (every deviation from the source
named in the README — silent "fixes" of the source are forbidden;
the source is the source, quirks included, e.g. VXLAN port 65535).
If a graph won't express without IR changes beyond the bitmap tier,
STOP and report rather than improvise.

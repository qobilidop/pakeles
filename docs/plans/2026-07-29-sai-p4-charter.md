# Autonomous run: SAI P4 (SONiC PINS) parser — P4-to-P4 parse agreement on BMv2

**Date:** 2026-07-29
**Status:** charter (self-authored per the roadmap standing instruction
after Katran closed). Fourth incumbent-agreement target.
**Done =** full gate green on main with a new `sai_parser`-class example
whose parse (headers extracted + verdict) agrees packet-for-packet with
the pinned SONiC PINS `sai_p4` parser run on `simple_switch`, over a
committed corpus (version-tagged claim), a documented divergence/quirk
catalog, and memory updated.

## Why this target is different (and easier to observe)

The incumbent is a **P4 program**, run on **BMv2 `simple_switch`** — the
exact toolchain Pakeles's own BMv2 oracle (`src/oracle/bmv2.rs`) already
drives, in-gate. So the observation problem is the lightest yet: no
source patch (contrast Katran). `simple_switch --log-console` prints a
per-packet parser trace (`Parser state 'parse_ipv4'`, `Extracting header
'ipv4'`), a direct readout of which states ran and which headers were
extracted from the UNMODIFIED program. This is what SONiC's own DVaaS
stores (`dvaas/packet_trace.proto bmv2_textual_log`).

Research (condensed in `scratchpad/saip4-research.md`, full report in
that session): pin **sonic-net/sonic-pins @
e77250b8dcab96e6f0e6ba1a9643f66771caa46c** (main HEAD, 2026-04-27).
**Apache-2.0 → vendorable** with attribution (unlike GPL katran — this
one CAN live in-repo with a license header). Parser =
`sai_p4/fixed/parser.p4` (243 lines, shared by middleblock/tor/fbr);
v1model; compiles with plain **p4c-bm2-ss** (`-DPLATFORM_BMV2` + C
preprocessing). A self-contained single-file snapshot exists at
`p4_symbolic/testdata/parser/sai_parser.p4` (318 lines) — a good minimal
target if the full include tree is unwieldy.

## Context

- Roadmap position: DPDK (done) → Katran (done) → **sai_p4** → TLS
  ClientHello. Backend/audience: P4 backend / parity claim with a
  NOTABLE program (user: "not those toy programs").
- Make-or-break (roadmap): the observation problem — SOLVED cheaply by
  `--log-console` (above); confirm empirically in phase 1.
- Coverage caveat (roadmap): sai_p4 uses NO value_sets / lookahead /
  varbit / header stacks / masked-or-range selects — all exact/wildcard.
  So it will NOT exercise our lookahead/value_set/mask-range machinery.
  Keep a small **P4-feature side-corpus** note for the parity claim's
  completeness (documented boundary, not this run's build).
- Parser scope (from research): Ethernet, ARP, IPv4, IPv6, one level
  IP-in-IP (all 4 combos), IPv6 hop-by-hop (only when
  header_extension_length==0, else accept — the no-lookahead quirk),
  ICMP/ICMPv6, TCP, UDP, a P4Runtime packet_out controller header
  (CPU-port-gated). NO VLAN (parser.p4 TODO — 0x8100 falls to accept),
  no GRE/ERSPAN at this pin.

## Binding references (read first)

- `examples/real_world/dpdk_ptype/` + `src/oracle/dpdk_ptype.rs` and
  `examples/real_world/katran_flow/` + `src/oracle/katran.rs` — the two freshest
  instantiations (projection + laxness + quirk-catalog + gate shape).
- `src/oracle/bmv2.rs` — the EXISTING simple_switch harness (p4c-bm2-ss
  compile + run + header-bitmap compare); the sai oracle extends this
  toolchain to a SECOND (incumbent) program.
- `scratchpad/saip4-research.md` — pin, file map, features, observation
  recipe, license, corpus notes.
- Memory: `parser-target-roadmap`, `observation-patch-oracle` (the
  lighter --log-console route + the git hazards), `symex-perf`.

## Phase 0 — preflight

Tree clean; main not diverged; full gate green; branch `sai-p4`.

## Phase 1 — incumbent harness (feasibility gate)

1. Fetch the pinned parser sources (Apache — MAY be vendored in-repo
   with a license header + provenance note; prefer the self-contained
   `sai_parser.p4` snapshot if the include tree fights the container's
   p4c). Record the pin (version tag).
2. Compile with the container's `p4c-bm2-ss` (`-DPLATFORM_BMV2`) → BMv2
   JSON. If it needs flags/preprocessing the container lacks: try the
   snapshot; if still blocked, STOP + report.
3. Run a handful of packets through `simple_switch --log-console` (or
   the existing bmv2.rs run path), confirm the parser-state / header
   -extraction lines are scrapeable into a per-packet extracted-header
   set + accept/verdict.
4. STOP gate: sai_p4 won't compile on the container p4c OR the parse
   trace isn't observable from simple_switch. Report what was tried.

## Phase 2 — design-lite (binding, committed before building)

`docs/superpowers/specs/<date>-sai-p4-design.md`: coverage map from the
pinned parser.p4; the projection (our ParseResult → the sai
extracted-header set + verdict) and laxness rule (their `verify`/accept
vs our reject; the header_extension_length!=0 accept quirk; the
packet_out CPU-gated arm — modeled or boundary); example scope + name
(`sai_parser`, a field-for-field model of parser.p4); gate shape (a
committed version-tagged golden of the sai parse trace + a live
tool-gated differential on simple_switch, like bmv2.rs); out-of-scope
(match-action tables, deparser rewrites, the feature side-corpus).

STOP gate: the parse can't be made deterministic per-packet.

## Phase 3 — plan doc

Tasks / corpus matrix / floors / commit messages, per the dpdk+katran
conventions. Corpus exercises each parser state incl. the four IP-in-IP
combos, the hop-by-hop==0 accept, ICMP, ARP, and the CPU packet_out arm.

## Phase 4 — build (small commits, gate green per commit — per-commit
this time, not tip-only; verify `git status` after each commit per the
[[observation-patch-oracle]] hazard note)

Vendor the sai parser (license header) → oracle harness scraping the
simple_switch trace → eDSL `sai_parser` example + regen → projection +
`diff sai` + gate tests → corpus + golden mint → README.

## Phase 5 — quirk hunt

Replay the symex witness set through simple_switch; catalog divergences
(the header_extension_length!=0 accept, VLAN-unparsed, the CPU-gated
arm, any select-miss → accept behavior). ≥1 real quirk or honest none.

## Phase 6 — P4-in-P4 note (the deliverable)

The audience artifact is the parity claim itself: our GENERATED P4 for
`sai_parser` vs the real sai parser.p4, both on simple_switch — do they
extract the same headers over the corpus? A short docs note with the
result (and the feature-coverage caveat: exact/wildcard only). If our
generated P4 can be diffed structurally against theirs, note that too.

## Phase 7 — closure

Full gate + regen clean; ff-merge + push (only if green; VERIFY no
stray/oversized blobs before merge — the katran lesson); memory
(roadmap sai status, feature side-corpus note); this is the last of the
four roadmap targets — note TLS ClientHello remains.

## Ground rules

As dpdk+katran: single line of work; dev.sh gotchas; full gate PER
commit; floors only ratchet; goldens minted only by the harness;
latent-bug protocol; every STOP = tree green + report. Apache license →
vendoring the parser IS allowed (with a header + provenance); still
never commit build outputs (gitignore the build dir first). Verify
`git status` after each commit.

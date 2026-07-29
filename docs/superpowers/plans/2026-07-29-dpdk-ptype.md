# `dpdk_ptype` Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [x]`) syntax for tracking.
> Execute task-by-task; every task ends with the repo green.

**Goal:** new gallery example `dpdk_ptype` agreeing packet-for-packet
with DPDK 23.11.4's `rte_net_get_ptype()` — `(ptype mask, hdr_lens)` —
over a committed corpus, via both a committed version-tagged golden and
a live in-container differential; then the generated-C-in-DPDK spike.

**Spec:** `docs/superpowers/specs/2026-07-29-dpdk-ptype-design.md`
(binding design-lite; all quirk expectations harness-verified).
**Charter:** `docs/plans/2026-07-29-dpdk-ptype-charter.md`.

## Global constraints

- Full gate green per commit; floors only ratchet up; goldens minted
  only by `oracle/dpdk_ptype/factory/capture.sh`.
- Byte-identity discipline on re-mints (all prior entries unchanged).
- Any disagreement during minting: investigate against rte_net.c; fix
  OUR side or document a boundary — never adjust the golden.
- Symex: DAG, no cycles — expect cost far below the flow dissector's;
  measure with `symex_bench` only if regen is unexpectedly slow.

## The corpus matrix (single source: design §1-§3; hexes authored once
in Task 3, byte-identical twins in Task 2's projection unit tests)

**Accepts — plain (12):** v4/TCP, v4/UDP, v6/TCP, v6/UDP, v4/SCTP
(zero L4 bytes — blind l4_len 12), VLAN+v4/TCP, QinQ+v6/UDP, v4
ihl=6+options/TCP (`L3_IPV4_EXT`), v6 hopopt/TCP, v6 destopt
hel=1/UDP, v6 routing/TCP, v4 proto=61 (L3 stop).

**Accepts — quirk lines (20):** MPLS single label (dead code → L2
only); MPLS truncated 2 bytes (same); bare 0x88A8+IPv4 (blind QinQ
tag misread); ARP (L2 stop); 802.3 length ethertype; double-VLAN
Q/Q+v4/TCP (inner path, no tunnel); Q-then-AD (INNER_QINQ); triple
tag AD/Q/Q+v4/TCP; TEB-at-top eth/0x6558/eth/v4/TCP (inner, no
tunnel); version_ihl=0x55 (no L3 bit, L4 continues); TCP doff=8 no
options bytes (blind l4_len 32); TCP doff=0 (l4_len 0); UDP zero L4
bytes; v4 MF frag (L4_FRAG); v4 offset-frag proto=6; v6 frag first;
v6 frag non-first; v6 frag next=0 (**no FRAG bit**); v6 ESP (EXT no
skip); v6 nh=59 (plain IPV6 stop).

**Accepts — ext-chain (5):** opt→NONE(59); 4 opts+TCP (l3 72); 5
opts+TCP (**bail: l3 snaps to 40, no L4**); 4 opts+frag (FRAG, l3
80); opt→proto 89 (default stop).

**Accepts — tunnels (15):** IPIP v4/v4/TCP; v4(41)/v6/UDP;
v6(4)/v4/TCP; IPIP behind QinQ; GRE v0 plain/v4/TCP (tunnel_len 4);
GRE+C (8); GRE+K+S (12); GRE+C+K+S (16); GRE **R=1** (no tunnel
bit); GRE **version=1** C+K+S+inner present (version ignored —
kernel-divergence twin); GRE proto=0x8100 → inner VLAN; GRE
proto=0x8847 (stop after tunnel); NVGRE (TEB)/eth/v4/TCP; NVGRE +
inner VLAN+v6/TCP; GRE behind ext chain (opt next=47).

**Accepts — inner depth (8):** double IPIP (second tunnel never
dispatched); inner v4 ihl=6 (INNER_L3_IPV4_EXT); inner v4 MF frag
(INNER_L4_FRAG); inner v6 hopopt/TCP; inner v6 frag (INNER_L4_FRAG);
inner v6 frag next=0 (no INNER_FRAG bit); inner 5-opt bail
(inner_l3 40); inner v4 SCTP (blind 12).

**Trunc lines — the laxness rule, all mappable classes (12):** eth 10
bytes (ptype 0); VLAN tag 2 bytes; QinQ 6 bytes; v4 header 10 bytes;
v6 header 20 bytes; outer TCP 10 bytes (strip L4); GRE base 2 bytes;
TEB + inner eth 8 bytes; GRE + inner v4 10 bytes; **inner TCP 10
bytes (outer bits wiped — ptype INNER_L3 only)**; v6 + 1-byte ext
prefix; IPIP + inner v6 20 bytes.

Total ≈ 72 lines. Excluded classes (design §3) get NO corpus lines;
the projection hard-errors on them, so accidental inclusion is a red
gate, not silence.

## Floors

After the mint: `entries >= 70`, and the golden's `dpdk_version` must
start with `"DPDK 23.11"` (pin guard). Ratchet in its own commit AFTER
the golden commit.

---

### Task 1: eDSL example + regen + registration

**Files:** `py/src/pakeles/examples/dpdk_ptype.py` (+ `__init__.py`),
`scripts/gen-examples.sh` (add to loop), `src/examples.rs` (embed +
canonical/mirror/validate tests), regenerated `examples/dpdk_ptype/*`.

- [ ] Headers + 27-state DAG per design §4 (multi-key frag selects;
  QinQ blind-tag header; TCP fixed-20; GRE no-version-select;
  ext_opt1..5 unrolled; max_depth 20).
- [ ] Full regen `./dev.sh scripts/gen-examples.sh`; inspect doc.md,
  graph.svg, vectors present; all four backends emit.
- [ ] Full gate.
- [ ] Commit: `feat(example): dpdk_ptype — field-for-field model of DPDK 23.11 rte_net_get_ptype`

### Task 2: projection + diff CLI + unit tests

**Files:** `src/oracle/dpdk_ptype.rs`, `src/oracle/mod.rs`,
`src/cli.rs` (`diff dpdk-ptype`).

- [ ] `RTE_PTYPE_*` constants (values from pinned rte_mbuf_ptype.h);
  `HdrLens`; `GoldenFile{dpdk_version, entries}` serde matching the
  capture schema.
- [ ] `project(ir, packet) -> Projected{ptype, hdr_lens}` per design
  §3: accept path + mappable-reject table; hard error (distinct
  variant) on unmappable classes.
- [ ] `diff_goldens` + `diff dpdk-ptype` CLI (default goldens
  discovery under `examples/dpdk_ptype/conformance/`).
- [ ] Projection unit tests: byte-identical twins of the corpus matrix
  (accepts + trunc + quirk lines), expected values hand-derived from
  the design (independently of the harness — the golden mint is the
  cross-check).
- [ ] Full gate.
- [ ] Commit: `feat(oracle): dpdk_ptype projection + diff — laxness-rule mapping of reject traces`

### Task 3: corpus + capture.sh + golden mint

**Files:** `oracle/dpdk_ptype/factory/corpus.txt`, `capture.sh`,
`examples/dpdk_ptype/conformance/ptype.dpdk-23.11.4.golden.json`.

- [ ] corpus.txt: the matrix above, commented sections, hexes identical
  to Task 2's test twins.
- [ ] `capture.sh`: build capture.c via pkg-config libdpdk, run over
  corpus, write the version-tagged golden (unprivileged, in dev.sh).
- [ ] Mint. Investigate ANY projection/golden mismatch against
  rte_net.c before committing (fix ours or boundary-doc; never the
  golden).
- [ ] Full gate (`diff dpdk-ptype` green against the fresh golden).
- [ ] Commit: `test(oracle): dpdk_ptype corpus + DPDK-23.11.4-minted goldens`

### Task 4: gate tests + floors + README

**Files:** `src/oracle/dpdk_ptype.rs` (gate tests), example README.

- [ ] `committed_goldens_agree` analog: always-on, floors (entries >=
  70, version pin guard), every entry compared.
- [ ] Live differential test, tool-gated on `pkg-config libdpdk` +
  gcc (BMv2-precedent gating): rebuild harness, fresh capture,
  byte-compare vs committed golden + full diff.
- [ ] `examples/dpdk_ptype/README.md`: what it is, the two-oracle
  shape, honest boundary section (excluded laxness classes, ihl<5,
  single-segment, no UDP tunnels), quirks section (from phase 5).
- [ ] Floors ratchet commit (separate, after golden).
- [ ] Full gate.
- [ ] Commit: `test(oracle): dpdk_ptype gate — committed-golden agreement + live DPDK differential`

### Task 5 (charter phase 5): quirk hunt

- [ ] Replay the full symex witness set (accepts + rejects + truncs)
  through the harness; diff DPDK's answer against our projection for
  every MAPPABLE witness — any disagreement is a bug (fix ours) or an
  undocumented quirk (catalog it).
- [ ] README quirks/divergence catalog finalized (>= 1 real quirk —
  already banked: MPLS dead code, frag-next-0, inner-TCP outer-wipe,
  blind lengths, QinQ blind tag, version-ignored GRE).
- [ ] Commit: `docs(example): dpdk_ptype divergence/quirk catalog from witness replay`

### Task 6 (charter phase 6): generated-C-in-DPDK spike

**Files:** `oracle/dpdk_ptype/spike/` (adapter + bench, not gate-wired),
`docs/designs/2026-07-29-dpdk-integration-spike.md`.

- [ ] Adapter: `examples/dpdk_ptype/gen/parser.c` output →
  `(RTE_PTYPE_* mask, rte_net_hdr_lens)` (single-segment; reuse the
  Rust projection's mapping rules, in C).
- [ ] Correctness harness: adapter ≡ `rte_net_get_ptype` over corpus +
  witness set (modulo documented laxness).
- [ ] Benchmark ns/packet, adapter vs incumbent, over the corpus
  vector set; arm64-container caveat stated; report vs EverParse ≤2%
  bar (a miss is a finding, not a blocker).
- [ ] Docs note; commit: `docs(design): generated-C-in-DPDK spike — correctness + benchmark findings`

### Task 7 (charter phase 7): closure

- [ ] Full gate + fresh vector regen leaves tree clean.
- [ ] ff-merge dpdk-ptype → main, push (only if all green).
- [ ] Memory updates: parser-target-roadmap (DPDK status), new memory
  if the oracle pattern diverged from the flow-dissector template.

## Definition of done

Full gate green on main; `dpdk_ptype` example present with all backends
+ conformance; committed DPDK-23.11.4 golden agreement over the whole
corpus incl. laxness-rule trunc lines; quirk catalog in README; spike
doc with benchmark numbers; memory updated.

# `linux_flow_dissector` rung 4b Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [x]`) syntax for tracking.
> Execute task-by-task; every task ends with the repo green.

**Goal:** GRE (proto 47) in `linux_flow_dissector`, agreeing with upstream
`bpf_flow.c`'s `IPPROTO_GRE` arm: version≠0 accept-stop *before* the
optional region or `is_encap` (the ordering crux), C/K/S-sized opaque
optionals, proto dispatch 0x0800/0x86DD/TEB with TEB re-entering
`parse_ethernet` itself. Completes the north-star ladder: proto-47 leaves
the README's excluded set.

**Spec:** `docs/superpowers/specs/2026-07-28-flow-dissector-rung4b-design.md`
(binding design-lite). Depends on rung 4a (landed 2026-07-28) and its
goldens mint (phase 1 of the 2026-07-29 ladder-completion run).

## Global Constraints

- Same gate/commit discipline as rung 4a: full gate green per commit;
  floors only ratchet up; goldens minted only by the factory.
- `max_depth` stays 10 (deepest golden chain:
  eth/IPv4/GRE/GREOpt/eth/vlan_q/IPv4/TCP = 8 entries).
- No new IR capability — confirmed: GRE is extract + select + assign +
  cross-header `byte_len`, all existing machinery.

## Decisions (fixed here)

- **No `parse_gre_teb` state** (design's open spelling question, resolved
  as it leaned): the TEB arm targets `"parse_ethernet"` directly. TEB
  re-entry IS `parse_ethernet` — the kernel reads the inner 14-byte
  Ethernet and runs its full `parse_eth_proto` dispatcher, which is
  exactly what `parse_ethernet` does. `is_encap` is already set by
  `parse_gre_opt`, so no pass-through work remains for a dedicated state.
  No validator/codegen blocker: the emitted IR validates and enumerates.
- **eDSL blocker found and fixed (prerequisite commit):** the design's
  "cross-header byte_len is legal" claim holds at the IR layer, but the
  eDSL's var_bytes instance-rebind (`_build.py`) blanket-rewrote *every*
  field ref in a byte_len expression to the enclosing instance
  (`gre_opt`), producing `unresolved field ref gre_opt.c` at enumeration.
  Fixed to rebind only sibling refs (those naming the owning header
  type); byte-identical IR for all existing examples.
- **Header spelling** (per design): `GRE` base = c/routing/key_flag/
  seq_flag/reserved(9)/version(3)/proto(16); `GREOpt["gre_opt"].body =
  var_bytes(GRE.c * 4 + GRE.key_flag * 4 + GRE.seq_flag * 4)`. The R bit
  is modeled but never checked (kernel masks only C/K/S/version) —
  fidelity boundary, not divergence.
- **State spelling**: `parse_gre` selects on `GRE.version`
  `{0: "parse_gre_opt"}, default=accept()` (kernel step 2: version≠0 →
  BPF_OK immediately, optionals never read, no is_encap);
  `parse_gre_opt` extracts the optional region, then
  `.assign(FlowMeta.is_encap, 1)`, then selects on `GRE.proto`
  (cross-state key) `{0x0800, 0x86DD, 0x6558}`, default
  `reject("unsupported gre proto", info=True)`.

## Symex gate (measured 2026-07-29, gate PASSED)

Enumerate-only via `symex_bench` on the 4b IR:

- Release: **72.1s wall**, 57,311 paths (3,517 accept / 12,847 reject /
  40,947 trunc); 26,371 feasibility checks in 7.4s; 57,311 inline witness
  solves in 32.4s.
- Debug (what `gen_examples` runs): **236.6s wall** for the same.
- Projected full regen (debug enum+witness + assembly/interp round-trips
  + artifact writes): **~6–8 min**, under the 15-min STOP threshold.
- Path growth vs 4a: 12,993 → 57,311 (~4.4×) — the TEB back edge makes
  `parse_ethernet`/`parse_vlan_*` cyclic, as the design's risk section
  predicted.

## The GRE corpus matrix (design §Oracle)

Accepts (10):

1. GRE-v4/TCP: eth/IPv4(p=47)/GRE(v0, proto=0x0800)/IPv4/TCP
2. GRE-v6/UDP: eth/IPv6(nh=47)/GRE(v0, proto=0x86DD)/IPv6/UDP
3. GRE+C: csum optional present (4 bytes)
4. GRE+K+S: key+seq optionals (8 bytes)
5. GRE all C/K/S flags (12 bytes)
6. version=1 accept-stop **with C/K/S set and truncated tail** — proves
   the step-2 ordering (optionals never read on version≠0)
7. TEB: GRE(proto=0x6558)/inner eth/IPv4/TCP
8. TEB + inner 802.1Q: `n_proto` = the inner tag's encapsulated proto
9. GRE behind IPIP: eth/IPv4(p=4)/IPv4(p=47)/GRE/... (mixed-arm double
   encap)
10. MPLS-over-TEB: inner eth ethertype 0x8847 → MPLS read-and-stop

Drops (4):

1. truncated GRE base (2 bytes)
2. version-0 C-flagged with optionals present but truncated inner header
   (kernel optionals are thoff arithmetic, not reads — the drop comes
   from the *inner* header read failing)
3. TEB with truncated inner Ethernet
4. ARP-over-GRE (proto 0x0806 → dispatcher default drop)

---

### Task 1: eDSL — GRE/GREOpt + states + arms, full regen

**Files:** `py/src/pakeles/examples/linux_flow_dissector.py`; regenerated
`examples/real_world/linux_flow_dissector/*` (ir.json, py copy, `gen/*`,
conformance vectors).

- [x] Example changes per Decisions (docstring gains the rung-4b
  paragraph; `47: "GRE"` labels on `IPv4.protocol`/`IPv6.next_header`;
  `47: "parse_gre"` arms on `parse_ipv4`/`parse_ipv6`/`parse_ipv6_opt`
  — NOT `parse_ipv6_frag`).
- [x] Full regen `./dev.sh scripts/gen-examples.sh`; inspect `gen/doc.md`
  (GRE states, metadata), `graph.svg`, vectors carry gre paths.
- [x] Full gate. `committed_goldens_agree` stays green (corpus has no GRE
  yet; existing projection untouched).
- [x] Commit: `feat(example): linux_flow_dissector rung 4b — GRE base/optionals split, version gate, TEB re-entry`

### Task 2: Projection — n_proto positional-last + GRE-stop accept

**Files:** `src/oracle/linux_flow_dissector.rs`.

- [x] `n_proto`: LAST `vlan_q` instance's encapsulated proto, else first
  `ethernet` — kernel PROG(VLAN) rewrites `n_proto` for inner tags
  behind TEB; identical results pre-4b (only one vlan_q possible).
- [x] GRE-stop accept (version≠0): last instance `gre` with no following
  L4/frag → `thoff` = gre.start_bit/8, ports 0, stop; `ip_proto` = 47
  falls out of positional-last; `is_encap` false (never assigned).
- [x] TEB inner-Ethernet: no flow_keys writes of its own; inner
  VLAN/MPLS/IP inherit by position (MPLS stop keeps its shape).
- [x] `project_tests` for the 14-vector matrix (hexes byte-identical to
  Task 3 corpus lines); all existing tests green unmodified.
- [x] Commit: `feat(oracle): GRE flow_keys projection — version-stop thoff, last-vlan_q n_proto`

### Task 3: Corpus

**Files:** `oracle/linux_flow_dissector/factory/corpus.txt`.

- [x] Append `# --- rung 4b: GRE ---` section: the 14 matrix vectors,
  byte-identical to Task 2's test hexes.
- [x] Full gate (goldens not yet re-minted: gate compares only committed
  golden entries, count floors unaffected).
- [x] Commit: `test(oracle): rung-4b GRE corpus vectors`

### Task 4: Goldens + floors + README + docs

- [x] Privileged re-mint (`./dev-priv.sh .../capture.sh`, kernel 6.8.0);
  HARD GATE: all 43 pre-existing entries byte-identical; commit golden.
- [x] Separate commit: floors ratchet by the minted counts
  (43 + 10 ok + 4 drop → ok ≥ 39 / drop ≥ 18).
- [x] README: delete the GRE divergence bullet (proto-47 leaves the
  excluded set); add R-bit + PPTP fidelity-boundary notes; ladder-table
  status updates in the two design docs (4b implemented).
- [x] Full gate incl. env-gated conformance; fresh vector regen.
- [x] Commit: `docs(example): rung 4b closes the GRE divergence — R-bit/PPTP fidelity boundaries`

## Build notes (2026-07-29, post-hoc)

Three latent issues surfaced and were fixed as their own commits, each a
first-exercise of machinery the GRE cycle composes:

- **Lua codegen:** parsed-value variables were per-state-function locals;
  cross-state reads (gre.proto / the GRE flag bits in parse_gre_opt) were
  nil and killed the dissector mid-tree. Now chunk-scope upvalues,
  last-extraction-wins.
- **BMv2 differential:** depth-rejected vectors are now explicitly
  skipped — the P4 backend has no max_depth counter (documented README
  seam); 4b's extra cycle produced the first suite paths that cross
  depth 10 (the unroll-2 cap kept pre-4b paths under it).
- **Projection nhoff (caught by the golden mint, vector "TEB + inner
  802.1Q"):** kernel PROG(VLAN) advances nhoff unconditionally, inner
  tags included — nhoff = first-IP start + 4 x (tags after it); kernel
  says 18, the rung-4a first-IP rule said 14. Golden untouched, our
  projection fixed.

Symex full-regen actual: ~6 min debug wall (projection from the gate
measurement held). Suite: 57,311 paths, 2,832+ byte-aligned through
BMv2, all conformance suites green.

## Definition of done

Full gate green on main with kernel agreement active over the whole
corpus including GRE; README divergence boundary updated; ladder
complete.

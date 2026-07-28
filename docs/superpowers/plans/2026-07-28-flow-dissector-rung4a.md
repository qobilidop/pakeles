# `linux_flow_dissector` rung 4a Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking.
> Execute task-by-task; every task ends with the repo green.

**Goal:** IPIP (proto 4) and IPv6-in-IP (proto 41) encap re-entrancy in
`linux_flow_dissector`, agreeing with upstream `bpf_flow.c`: two pass-through
states + six select arms + `FlowMeta.is_encap` (the first gallery metadata-v1
consumer), the projection reworked to the positional-last principle, and the
golden corpus extended with the tunnel matrix — `is_encap` and inner
addresses compared, not excluded.

**Architecture:** The IR already expresses re-entrancy (rung-2 bounded
cycles + instance stacks); rung 4a adds *no IR capability*. Work radiates
from the example: eDSL change → full gallery regen (pins stay green within
the commit) → projection rework (pure Rust, no artifact churn) → corpus +
fixed capture.c → CI-minted goldens → floors/docs.

**Spec:** `docs/superpowers/specs/2026-07-24-flow-dissector-rung4a-design.md`.
Depends on metadata v1 (landed 2026-07-25).

## Global Constraints

- `max_depth` stays the sole termination authority; metadata never extends
  the budget. No new reject reasons.
- Existing corpus vectors, goldens, symex pins, and tests are never
  weakened, skipped, or deleted to get green. `committed_goldens_agree`
  floors only ratchet UP (currently ok ≥ 17 / drop ≥ 10).
- Every commit leaves the full gate green:
  `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --features symex && buf lint && cd py && ruff check . && pyright && pytest'`.
- Goldens are minted ONLY by the factory (CI workflow or `dev-priv.sh`),
  never edited by hand. The 6.8.0 kernel tag is preserved by minting via
  the `flow-dissector-goldens.yml` workflow (ubuntu-latest), not locally
  (the Docker VM kernel would retag the file).
- Symex regen is expensive (~25–45 min solve at 779 paths; tunnel arms
  multiply paths). Measure enumeration (path count) before paying for a
  full solve; if paths exceed ~3000, stop and re-scope with the user.
- Commit style: `feat(scope): ...` / `test(scope): ...` matching `git log`,
  with the repo's Co-Authored-By trailer.

## Decisions (fixed here so the tasks are mechanical)

- **State names:** `parse_ipip` (proto 4 → re-enter `parse_ipv4`) and
  `parse_ip6ip` (proto 41 → re-enter `parse_ipv6`), matching the
  `parse_*` convention.
- **`max_depth` = 16.** Deepest tunnel-matrix chain is 7 state entries
  (double-encap; QinQ+tunnel); 16 covers it with headroom for rung 4b's
  GRE+TEB chains (~8) without inviting symex blowup (path length is
  governed by the per-cyclic-state unroll cap of 2, not max_depth).
  Documented as a fidelity boundary: the README's option-chain numbers
  (depth ~5→~13 behind eth/IPv6) must be recomputed in Task 5.
- **Projection = positional-last** (design doc table): walk
  `res.headers` in extraction order; `addr_proto`/addresses from the LAST
  IP-family instance (either family); `ip_proto` from the last-extracted
  next-protocol field overall (`ipv4.protocol` / `ipv6.next_header` /
  `ext_opt.next_header` / `ext_frag.next_header`); `flow_label` from the
  LAST `ipv6` instance; `nhoff` from the FIRST IP instance (kernel never
  rewrites it after VLAN, `bpf_flow.c` PROG(IP) :291 sets addr fields but
  nhoff advances only pre-L3); `n_proto` unchanged (outer family,
  `vlan_q` else `ethernet`); `is_encap` = `metadata.is_encap != 0`;
  thoff/ports/frag-stop already positional (LAST `ext_frag` wins).
- **capture.c fix (required for correct tunnel goldens):** the printed
  address family currently keys off `n_proto` (capture.c:113-119) — wrong
  under encap, where `n_proto` stays the outer family while the union
  holds the inner (last-written) family per `addr_proto`
  (`bpf_flow.c` :291/:333). Key off `k->addr_proto` (host-order 0x0800 /
  0x86DD). Add `"is_encap"` to `keys_subset` and per-entry output.
- **v4-in-v6 union residue:** kernel PROG(IP) writes only 8 address bytes
  over the 32-byte union; capture prints 8 bytes for the v4 family, so
  stale outer-v6 bytes are never emitted — our projection (v4 strings set,
  v6 strings empty) matches by construction.

## The tunnel corpus matrix (Task 4)

All accepts unless noted; state-entry depth in parens:

1. v4-in-v4 TCP: eth/IPv4(p=4)/IPv4/TCP (5)
2. v6-in-v4 TCP: eth/IPv4(p=41)/IPv6/TCP (5) — mixed family, addr_proto flips
3. v4-in-v6 UDP: eth/IPv6(nh=4)/IPv4/UDP (5) — mixed the other way
4. v6-in-v6 UDP: eth/IPv6(nh=41)/IPv6/UDP (5) — flow_label from INNER v6
5. double encap v4³ TCP: eth/IPv4(p=4)/IPv4(p=4)/IPv4/TCP (7)
6. tunnel behind ext chain: eth/IPv6(nh=0 HopByHop)/opt(nh=4)/IPv4/TCP (6)
7. tunnel behind QinQ: eth/AD/Q/IPv4(p=4)/IPv4/TCP (7) — nhoff = OUTER L3
8. fragmented outer: eth/IPv6(nh=44)/Frag(nh=41, off=0) (3) — frag stops
   BOTH sides before re-entry: is_frag=true, is_encap=FALSE, ip_proto=41
9. fragmented inner: eth/IPv4(p=41)/IPv6(nh=44)/Frag(nh=6) (5) —
   is_encap=true AND is_frag=true
10. inner ext chain: eth/IPv4(p=41)/IPv6(nh=0)/opt(nh=6)/TCP (6)

(Fragmented-IPv4 stays a documented divergence class — not in the corpus.
IPv4 headers in vectors use ihl=5; IPv6 `plen` consistent with payload.)

---

### Task 1: eDSL — FlowMeta + tunnel states/arms + max_depth, full regen

**Files:** `py/src/pakeles/examples/linux_flow_dissector.py`;
regenerated `examples/linux_flow_dissector/{linux_flow_dissector.ir.json,linux_flow_dissector.py,gen/*,conformance/vectors.json,conformance/vectors.pcap}`.

- [ ] Add to the example (docstring gains a rung-4a paragraph):

```python
from pakeles import ..., Meta, assign, meta_bits

class FlowMeta(Meta):
    is_encap = meta_bits(1, "Encapsulated", DEC,
                         doc="set on tunnel re-entry (IPIP / IPv6-in-IP)")
```

`parser(..., max_depth=16, metadata=FlowMeta, ...)`; label 4 as "IPIP" and
41 as "IPv6-in-IP" in the `protocol`/`next_header` label maps; add arms
`4: "parse_ipip", 41: "parse_ip6ip"` to the selects of `parse_ipv4`,
`parse_ipv6`, `parse_ipv6_opt` (NOT `parse_ipv6_frag` — kernel stops at a
fragment); add the two pass-through states:

```python
"parse_ipip": assign(FlowMeta.is_encap, 1).goto("parse_ipv4"),
"parse_ip6ip": assign(FlowMeta.is_encap, 1).goto("parse_ipv6"),
```

(Check `_states.py` for the no-select unconditional-transition spelling —
if there is no `.goto`, use the existing spelling for an unconditional
transition, e.g. a default-only select or `.then()`; match `counted_items`'
`mark_done` pattern adapted to a non-accept target.)

- [ ] Quick checks before paying for regen: `./dev.sh sh -c 'cd py && pytest && ruff check . && pyright'`;
  then enumeration-only path count (e.g. via `cargo run -- testgen` dry
  path or a small rust test printing `enumerate_ir(&ir).paths.len()`) —
  proceed if < ~3000.
- [ ] Full regen: `./dev.sh scripts/gen-examples.sh` (long: symex solve).
- [ ] Inspect `gen/doc.md` (Metadata section, tunnel arms), `graph.svg`
  regenerated, vectors.json carries `is_encap` ExpectedMeta on tunnel
  accepts.
- [ ] Full gate. `committed_goldens_agree` must stay green unchanged (old
  corpus has no tunnels; old projection semantics untouched so far).
- [ ] Commit: `feat(example): linux_flow_dissector rung 4a — IPIP/IPv6-in-IP re-entrancy, FlowMeta.is_encap, max_depth 16`

### Task 2: Projection — positional-last rework

**Files:** `src/oracle/flow_dissector.rs`.

- [ ] `FlowKeys` gains `#[serde(default)] pub is_encap: bool`; `field_pair`
  arm; `committed_goldens_agree` required-subset list gains `"is_encap"`
  ONLY in Task 4 (the committed golden predates it until re-mint — the
  test asserts subset contents, so adding the name now would go red).
- [ ] Rework `project()` per the Decisions table. Implementation shape:
  one pass over `res.headers` in order, tracking:
  `first_ip: Option<(family, start_bit)>`, `last_ip: Option<(family, idx)>`,
  `last_next_proto: Option<u64>` (updated at every `ipv4.protocol`,
  `ipv6.next_header`, `ext_opt.next_header`, `ext_frag.next_header`),
  `last_v6_flow_label`, `last_frag: Option<idx>`. Then assemble. Frag stop
  (thoff = frag start + 8, ports 0) and MPLS stop keep their existing
  shapes. `is_encap` from `res.metadata` (name `"is_encap"`).
  Per-field `bpf_flow.c` citations in comments (design-doc table).
- [ ] New `project_tests` (hexes double as Task-4 corpus lines, byte-identical
  twins — same discipline as rung 2): the 10-vector matrix above,
  asserting per vector: `is_encap`, `addr_proto`/addresses = inner family,
  `nhoff` = outer L3 start, `n_proto` = outer family, `ip_proto` = last
  next-proto (vector 8: ip_proto=41 with is_encap=false), `thoff`/ports,
  vector 4: flow_label = inner v6's, vector 9: is_encap && is_frag.
- [ ] All existing `project_tests`/`diff_tests` stay green unmodified —
  the positional-last rework must be behavior-preserving on non-tunnel
  parses (single IP instance ⇒ first == last).
- [ ] Full gate. Commit:
  `feat(oracle): positional-last flow_keys projection — is_encap from metadata, inner addresses, last next-proto`

### Task 3: capture.c encap fix

**Files:** `oracle/flow_dissector/factory/capture.c`.

- [ ] Address family by `k->addr_proto` (not `n_proto`); `"is_encap"`
  appended to `keys_subset` and each ok-entry (`k->is_encap ? "true" : "false"`).
- [ ] Compile check (no BPF needed to build the userspace half):
  `./dev.sh sh -c 'cc -O2 -c oracle/flow_dissector/factory/capture.c -o /dev/null -lbpf 2>&1 || cc -O2 -fsyntax-only oracle/flow_dissector/factory/capture.c'`
  (link needs libbpf in the container; syntax-only acceptable).
- [ ] Commit: `fix(oracle): capture.c — address family by addr_proto (encap-correct), emit is_encap`

### Task 4: Corpus + CI-minted goldens + floors + subset

**Files:** `oracle/flow_dissector/factory/corpus.txt`,
`examples/linux_flow_dissector/conformance/flow_keys.linux-*.golden.json`
(minted), `src/oracle/flow_dissector.rs` (floors + required subset).

- [ ] Append `# --- rung 4a: IPIP / IPv6-in-IP tunnels ---` section: the
  10 matrix vectors (byte-identical to Task 2's test hexes), plus drops:
  truncated inner IPv4 (extract-fail both sides), tunnel to an
  unsupported inner proto (e.g. inner protocol 89 → both drop).
- [ ] Push branch/commit to main first (workflow_dispatch runs on the
  default branch), then: `gh workflow run flow-dissector-goldens.yml`,
  poll `gh run watch`, download: `gh run download <id> -n flow-dissector-goldens -D examples/linux_flow_dissector/conformance/`,
  link the run URL in the commit message. Review the diff: existing
  entries must be byte-identical (capture.c's family fix only affects
  encap entries, absent until now); new entries' keys must match Task 2's
  test expectations exactly — any disagreement is a REAL kernel
  disagreement: stop and investigate, never adjust the golden.
- [ ] `committed_goldens_agree`: required subset gains `"is_encap"`;
  floors ratchet: ok ≥ 27, drop ≥ 12 (17+10 existing, +10 ok +2 drop new).
- [ ] Full gate. Commit:
  `test(oracle): rung-4a tunnel corpus + kernel goldens (CI run <url>) + is_encap in compared subset`

### Task 5: Docs — README fidelity boundaries, design-doc statuses

**Files:** `examples/linux_flow_dissector/README.md`,
`docs/superpowers/specs/2026-07-24-flow-dissector-rung4a-design.md` (status),
`docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md` (ladder table).

- [ ] README: "GRE/IPIP — not yet modeled" → "GRE (rung 4b)" with the
  proto-47 documented-asymmetry note (kernel accepts, we reject until 4b);
  new "Handled as of rung 4a" paragraph (tunnel matrix, is_encap via
  metadata, positional-last projection, nhoff/n_proto outer-stay
  asymmetry); recompute the option-chain depth numbers for max_depth 16
  (~13 option headers behind eth/IPv6, ~15 with no VLAN, fewer behind
  QinQ; kernel still ~30) and the max_depth-vs-tail-call boundary note;
  keys_subset text gains is_encap.
- [ ] Design docs: 4a status → "implemented"; ladder table rung-4 row
  notes 4a landed / 4b pending.
- [ ] Full gate (docs don't break it; run anyway). Commit:
  `docs(example): rung 4a boundaries — GRE-only divergence, max_depth 16 option-chain numbers`

---

## Definition of done

Full gate green with: tunnel matrix in corpus + kernel-minted goldens
(6.8.0 tag) diffed green including `is_encap` and inner addresses;
projection positional-last with per-field kernel citations; all five
backends regenerated from the rung-4a IR; README/status docs updated.
Rung 4b (GRE) follows as its own design-lite → plan → build.

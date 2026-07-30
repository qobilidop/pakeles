# Autonomous run: DPDK `rte_net_get_ptype()` — two-way diff + in-DPDK C spike

**Date:** 2026-07-29
**Status:** charter for an autonomous run; not started
**Done =** full gate green on main with a new `dpdk_ptype`-class example whose
projected packet-type agrees packet-for-packet with DPDK's own
`rte_net_get_ptype()` over a committed corpus (version-tagged claim), a
documented divergence/quirk catalog, a completed generated-C-inside-DPDK
spike with benchmark numbers, and memory updated.

This charter follows the `linux_flow_dissector` template (pinned incumbent →
projection defined before building → corpus + minted agreement → honest
boundary docs) but the incumbent is **userspace and unprivileged** — the
oracle can run inside the normal dev container, no `dev-priv.sh`.

## Context (decided 2026-07-29, conversation with the user)

- This is the first of four post-ladder targets: DPDK ptype → Katran (eBPF)
  → sai_p4 (P4) → TLS ClientHello. Each pairs a backend with an audience.
- **Two-way diff only** (Pakeles vs DPDK). A Linux-vs-DPDK three-way is
  explicitly out of scope (cheap future byproduct once this oracle exists).
- **First-class question:** can our generated C99 be used in DPDK directly
  (as/alongside the software ptype classifier)? The spike answers it with
  an adapter + benchmark. EverParse's adoption precedent (≤2% overhead) is
  the framing bar; a miss is a *finding to report*, not a failure.
- Known risk, scoped up front: `rte_net_get_ptype` handles segmented mbuf
  chains via `rte_pktmbuf_read`; our C parser assumes a contiguous buffer.
  Scope everything to **single-segment mbufs** and document that boundary.
- `rte_net_get_ptype` returns a best-effort `RTE_PTYPE_*` classification for
  every packet — **there is no drop verdict**. The projection therefore
  needs an explicit laxness rule for our reject/truncation paths (design
  phase decides; see phase 2).

## Binding references (read first)

- `examples/real_world/linux_flow_dissector/README.md` + `oracle/flow_dissector/` —
  the north-star pattern being instantiated a second time.
- `docs/superpowers/plans/2026-07-29-flow-dissector-rung4b.md` — commit
  discipline, gate, floors-ratchet ordering, build-notes convention.
- Memory: `flow-dissector-northstar` (pattern + stray-session incidents),
  `symex-perf` (bench workflow, dev.sh gotchas), `parser-target-roadmap`.
- DPDK source of truth: `lib/net/rte_net.c` (`rte_net_get_ptype`) at the
  **pinned version** chosen in phase 1. DPDK is BSD-3-Clause — vendoring
  source in-repo (with license header) is permitted, unlike the GPL
  `bpf_flow.c` (which stays fetch-at-capture-time). Prefer the distro
  package over vendoring if it works.

## Phase 0 — preflight

1. Tree clean; `main` not behind/diverged from origin (ahead is fine). If
   dirty or diverged: STOP, report.
2. Full gate green before any change (regen vectors first if absent:
   `./dev.sh scripts/gen-examples.sh`, ~6 min). If red on pristine main:
   investigate; apply the latent-bug protocol below.
3. Branch `dpdk-ptype` off main. All work happens there.

## Phase 1 — environment + incumbent harness

1. Make `rte_net_get_ptype()` callable in the dev container (arm64!).
   Preferred: Ubuntu noble's DPDK dev packages (add to
   `.devcontainer/Dockerfile`; image rebuild is sanctioned; note CI image
   size cost). Fallback: pinned-source build of the minimal subset. Record
   the exact DPDK version — it becomes the version tag in the golden file
   name and the agreement claim ("agrees with DPDK X.Y").
2. Build the oracle harness (suggested: `oracle/dpdk_ptype/`): a small C
   program mapping packet bytes → single-segment mbuf →
   `rte_net_get_ptype(mbuf, &hdr_lens, all-layers mask)` → JSON
   `{ptype_mask, hdr_lens...}` per packet. Hint to verify: a hand-built
   stack mbuf (buf_addr/data_off/data_len/pkt_len/nb_segs=1) should
   suffice — `rte_net_get_ptype` is a pure function over mbuf data, so no
   EAL init / hugepages should be needed. If EAL turns out to be
   unavoidable and won't run in-container: STOP, report what was tried.
3. Smoke-test the harness on a handful of `linux_flow_dissector` corpus
   packets; eyeball the ptype masks against a manual reading of rte_net.c.

STOP gate: DPDK not runnable in-container after a genuine bounded attempt
(both routes tried). Report findings; the fallback direction (host-side
oracle, new container) is the user's call.

## Phase 2 — design-lite (spec doc, committed before building)

Write `docs/superpowers/specs/<date>-dpdk-ptype-design.md` answering, from
a close reading of the pinned `rte_net.c`:

1. **Coverage map**: exactly which layers/tunnels/protocols the function
   classifies (L2/VLAN/QinQ, L3 + options/ext-headers, L4 incl. SCTP,
   frag behavior, which tunnels — and which it *cannot* see without
   config, e.g. UDP-port-based VXLAN/Geneve if applicable). Do not trust
   prior conversation recollections — read the source.
2. **Validation behavior**: what it checks vs blindly computes (e.g. does
   it validate ihl/length fields or emit garbage hdr_lens on malformed
   input?). Quirks are modeled faithfully and documented, never
   "corrected" — the incumbent is the authority, exclusions only with
   README boundary notes (fragmented-IPv4 precedent).
3. **Projection**: `ParseResult` → `(ptype_mask, hdr_lens)`, and the
   **laxness rule** for our reject/truncation paths (lean: our accept ⇒
   exact mask + hdr_lens match; our reject ⇒ a defined mapping onto
   DPDK's partial classification, checked, not skipped).
4. **Example scope + name** (lean: a new example, name per the gallery's
   content-naming conventions, e.g. `dpdk_ptype`; a field-for-field model
   of rte_net.c's walk — NOT a reuse of `linux_flow_dissector`, whose
   semantics are the kernel's).
5. **Gate shape** (lean: BOTH a live tool-gated differential like BMv2 —
   strongest, no staleness — AND a committed version-tagged golden file
   minted by the harness, for the reproducible claim + environments
   without DPDK; floors on entry counts as usual).
6. Out of scope: multi-segment mbufs, runtime-configured tunnel ports,
   Linux three-way, rte_flow.

STOP gate: the projection cannot be made deterministic per-packet (e.g.
classification depends on config we can't pin). Report the specifics.

## Phase 3 — plan doc

`docs/superpowers/plans/<date>-dpdk-ptype.md` per the repo convention:
tasks with checkboxes, corpus matrix (accepts + malformed/truncation
lines exercising the laxness rule and any discovered quirks), floors,
commit messages. Symex cost should be far below the flow dissector's
(measure with `symex_bench` anyway if the example has cycles).

## Phase 4 — build (small semantic commits, gate green per commit)

1. eDSL example + full regen; gallery pins green.
2. Rust projection + `diff dpdk-ptype` oracle + live differential test.
3. Corpus; goldens minted BY THE HARNESS (never hand-edited); byte-identity
   discipline on re-mints; floors ratchet AFTER the golden commit.
4. Any disagreement during minting = investigate against rte_net.c source;
   fix OUR side or document a boundary — never adjust the golden.

## Phase 5 — quirk hunt / divergence catalog

Replay the full symex witness set (especially reject/truncation paths)
through the harness; catalog where DPDK's classification is surprising
(unvalidated fields, garbage hdr_lens, over-classification). README gets
an honest boundary/quirks section. The roadmap rule is ≥1 real
divergence/quirk surfaced per target — if genuinely nothing surfaces,
report that plainly rather than manufacturing one.

## Phase 6 — generated-C-in-DPDK spike

1. Adapter: generated `parser.c` output → `RTE_PTYPE_*` mask + hdr_lens
   (single-segment). Correctness: adapter output ≡ DPDK output over the
   corpus + witness set, modulo the documented laxness rule.
2. Benchmark cycles/packet (or ns/packet), adapter vs `rte_net_get_ptype`,
   over the vector set; container-on-Apple-Silicon numbers are indicative
   only — say so. Report against the ≤2% EverParse bar; a miss is a
   finding with analysis, not a blocker.
3. Deliverable: a short docs note (suggested:
   `docs/designs/<date>-dpdk-integration-spike.md`) — numbers, the
   single-segment boundary, and what a real upstream integration would
   look like. Spike discipline: findings over polish.

## Phase 7 — closure

1. Full gate incl. all conformance; fresh vector regen leaves tree clean.
2. ff-merge to main + push ONLY if every gate passed. Otherwise leave the
   branch and report.
3. Update memory: `parser-target-roadmap` (DPDK status, what surfaced),
   `symex-perf` if numbers are notable; new memory for this example's
   oracle pattern if it diverged from the flow-dissector template.

## Ground rules

- Single line of work; no parallel agents writing to the tree
  (stray-session incidents 2026-07-25 / 2026-07-28).
- `dev.sh` does not forward host env vars — `./dev.sh env VAR=x cmd`.
  Never TaskStop a `./dev.sh` command (orphans the container). zsh eats
  bare `===` (equals-expansion).
- Full gate per commit:
  `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --features symex && buf lint && cd py && ruff check . && pyright && pytest'`.
- Floors only ratchet up; suites never weakened/skipped/deleted to get
  green; goldens minted only by the harness.
- **Latent-bug protocol** (norm established in the 2026-07-29 ladder run,
  where five surfaced): a bug in OUR harness/codegen/model that is
  precisely characterized with empirical evidence (failing-set analysis,
  incumbent-source citation) may be fixed in its own commit and must be
  prominently flagged in the final report. A semantic judgment call
  without decisive evidence is a STOP.
- Every STOP means: commit nothing further, write up observed-vs-expected,
  end the run with the tree green.

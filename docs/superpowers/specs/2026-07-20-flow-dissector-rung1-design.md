# Flow-dissector rung 1: VLAN/MPLS kernel fidelity + the upstream `bpf_flow.c` oracle

**Date:** 2026-07-20
**Status:** design approved; implementation pending
**Builds on:** `2026-07-19-linux-flow-dissector-design.md` (north-star + ladder), rung 0 (merged 2026-07-20).

## The finding that reframes rung 1

The ladder projected rung 1 as "VLAN + MPLS stacks → counted header loops / header stacks." Reading upstream `bpf_flow.c` at the v6.8 pin refutes that premise:

- **VLAN is position-dependent with a hard depth of 2, not a uniform loop.** `PROG(VLAN)`: if the outer ethertype is 802.1AD, the next header *must* be 802.1Q or the packet drops; after the final tag, any further Q/AD tag drops (no triple tagging — and no Q-in-Q with two 0x8100 tags either). Each tag advances `nhoff` and `thoff` by 4; `n_proto` becomes the inner encapsulated proto.
- **MPLS is not a stack walk.** `PROG(MPLS)` reads exactly one label entry, sets no `flow_keys` fields, and returns `BPF_OK` — dissection stops there. (`thoff`/`nhoff` are left where the previous layer put them.)
- Unknown ethertypes → `BPF_DROP`.

**Decision (user-approved):** rung 1's goal is *kernel fidelity with no IR change*. The depth-≤2 VLAN structure is expressed by unrolling into explicit states (the IR's `Extract.instance` already supports two extractions of one header type). The loop/header-stack IR construct is **re-scoped to rung 2**, where the IPv6 extension-header chain genuinely demands loop-until-terminal. The ladder table in the rung-0 design doc is superseded on this one row; that doc is left as-is (historical), this spec is the amendment of record.

Other approved decisions:

- **Drop goldens:** the golden format learns to record kernel drops, so the oracle checks agreement-on-rejection (VLAN's sequencing rules are mostly drops — they become ground truth, not untested corners).
- **Fetch-pinned upstream source:** `bpf_flow.c` is GPL-2.0 (kernel selftests); pakeles is Apache-2.0. The factory downloads it at capture time from a pinned kernel-tag URL with a recorded sha256, into a gitignored build dir. No GPL code is committed.
- **Replace-and-extend factory:** one libbpf-based pipeline; upstream becomes *the* factory dissector; the rung-0 minimal dissector and raw-syscall loader are retired after cross-validation.

## 1. Golden factory & golden schema

All under `oracle/flow_dissector/factory/`, still invoked via `./dev-priv.sh oracle/flow_dissector/factory/capture.sh`, still privileged and outside the normal gate.

1. **Fetch:** `capture.sh` downloads `bpf_flow.c` from the kernel v6.8 tag (raw-file URL + sha256 pinned in the script) into gitignored `build/`. It is the only fetched file; its includes resolve from `linux-libc-dev` and `libbpf-dev` (`bpf/bpf_helpers.h`, `bpf/bpf_endian.h`), added to the privileged image as apt packages.
2. **Compile:** `clang -O2 -target bpf -c` → `build/bpf_flow.o` — a real ELF with `.maps`, not a bare `.text` blob. Exact flags mirror the selftests Makefile as needed (implementation detail; `bpf_flow.c` uses no CO-RE).
3. **Load:** `capture.c` is rewritten against libbpf: `bpf_object__open_file` → load → populate `jmp_table`. Upstream's `PROG()` macro names each tail-called program `flow_dissector_<index>` (the `IP`=0 … `VLAN`=5 macros expand inside the name), so population is: for i in 0..6, find program `flow_dissector_<i>`, put its fd at key i — the same trick the selftests' loader uses. (Verify the names against the fetched source at implementation; fallback is enumerating `flow_dissector`-section programs in order.)
4. **Run:** `BPF_PROG_TEST_RUN` on the entry program `_dissect` over `corpus.txt`. The retval is *recorded* per entry instead of being required to be 0.
5. **Cross-validate, then retire:** the four rung-0 corpus lines stay first in `corpus.txt`; the regenerated golden must leave their keys byte-identical (reviewed via `git diff` — this is the promised cross-validation of rung-0 goldens against upstream). Then `flow_dissector.bpf.c` and the raw-syscall loader are deleted.

**Golden schema v2:** each entry becomes `{packet_hex, disposition: "ok" | "drop", keys?}` — `keys` present only when `ok`. `kernel_version` and `keys_subset` unchanged. The committed golden is regenerated wholesale in the new schema (no compat shim; the serde types change). Semantic note recorded in the file/docs: for VLAN packets golden `n_proto` is the *inner* encapsulated proto (kernel semantics), not 0x8100; the capture tool's address formatting already keys off `n_proto` and keeps working.

The CI golden-refresh workflow gains the two apt packages; otherwise unchanged. Single-golden discovery (one kernel version) is kept; the existing multi-golden TODO stays open.

## 2. Example, eDSL instance references, projection

**No IR schema change.** New surface is example-level + one eDSL affordance.

**Header types** (in `examples/linux_flow_dissector/linux_flow_dissector.py`):

- `VLAN`: `pcp` (3), `dei` (1), `vid` (12), `encapsulated_proto` (16). tshark tags where clean (`vlan.priority`, `vlan.dei`, `vlan.id`, `vlan.etype`).
- `MPLS`: `label` (20), `tc` (3), `s` (1), `ttl` (8). tshark tags where clean (`mpls.label`, `mpls.exp`, `mpls.bottom`, `mpls.ttl`).

**States** (mirroring `bpf_flow.c`'s structure, including its common tail as a DAG join):

- `parse_ethernet`: select on `ethertype` — `0x0800→parse_ipv4`, `0x86DD→parse_ipv6`, `0x8100→parse_vlan_q`, `0x88A8→parse_vlan_ad`, `0x8847/0x8848→parse_mpls`; default `reject("unsupported ethertype", info)`.
- `parse_vlan_ad`: extract `VLAN["vlan_ad"]`; select on its `encapsulated_proto` — `0x8100→parse_vlan_q`; default `reject("802.1AD must be followed by 802.1Q")`.
- `parse_vlan_q`: extract `VLAN["vlan_q"]` (shared join state — the single-Q path and the AD path both land here, exactly like upstream's common tail); select on its `encapsulated_proto` — `0x0800→parse_ipv4`, `0x86DD→parse_ipv6`, `0x8847/0x8848→parse_mpls`, `0x8100/0x88A8→reject("vlan stacking beyond kernel depth")`; default `reject("unsupported ethertype", info)`.
- `parse_mpls`: extract `MPLS`; accept (single-entry read, kernel-faithful stop).
- `parse_ipv4/ipv6/tcp/udp`: unchanged.
- `max_depth`: 4 → 5 (eth + vlan_ad + vlan_q + ip + l4).

Reject reasons for kernel-drop paths use default (error) severity; unknown-ethertype/protocol boundaries stay `info`. Both map to "Pakeles rejects" for oracle purposes.

**eDSL instance affordance:** `Header["name"]` (via `__class_getitem__`) returns an `Instance` proxy: `extract(VLAN["vlan_q"])` extracts under that instance name, and `VLAN["vlan_q"].encapsulated_proto` yields a field reference whose `FieldRef.header` is the instance name. Bare `extract(VLAN)`/`VLAN.field` keep meaning the default instance (= header-type name). The schema already supports all of this; only the Python surface is new.

**Projection updates** (`src/oracle/flow_dissector.rs`, still harness-side option A):

- `n_proto` = `vlan_q.encapsulated_proto` if `vlan_q` was extracted, else `ethernet.ethertype` (covers all paths, including VLAN→MPLS).
- `nhoff` = byte offset of the post-link layer (start of ipv4/ipv6/mpls header) — already derived from header start bits, so unrolled VLAN shifts it for free.
- `addr_proto` = 0x0800 if ipv4 extracted, 0x86DD if ipv6 extracted, else 0 (fixes rung 0's `addr_proto = n_proto` shortcut, which upstream contradicts for MPLS).
- `thoff` = L4 start when tcp/udp extracted; else = `nhoff` (MPLS stop: kernel leaves `thoff` where the link layer put it).
- MPLS accepts project to otherwise-zero keys (ports 0, addresses empty, `ip_proto` 0) — matching the kernel's read-and-stop.
- Diff contract becomes two-sided: Pakeles reject ⇔ golden `drop`; field agreement over `keys_subset` on `ok` entries only.

## 3. Corpus, testing, docs, definition of done

**Corpus** (existing 4 rung-0 lines, then new — comments in `corpus.txt` label intent):

Accepts: single-Q + IPv4/TCP; single-Q + IPv6/UDP; AD+Q + IPv4/TCP; MPLS (direct) + payload; single-Q + MPLS.
Drops: Q-in-Q (0x8100 then 0x8100); AD-after-Q (0x8100 then 0x88A8); AD not followed by Q (0x88A8 then IPv4 directly); triple tag (AD+Q+Q); unknown ethertype (ARP 0x0806).

**Testing:**

- `committed_goldens_agree` (the rung-1 DoD gate) extends to disposition agreement and asserts the corpus shape (≥ 9 ok entries, ≥ 4 drop entries) so a silently-shrunken golden can't pass.
- Example conformance regenerates end-to-end: `testgen` vectors, then every backend suite (interp, Lua/tshark, C field-level, eBPF verdict-level, P4/BMv2 verdict-level) green. **Known risk surface:** two instances of one header type is new for every backend — codegen paths may assume instance == header-type name (P4 header instance declarations, C struct slots, Lua subtree keys, doc/viz labels). No schema change, but each backend needs a look.
- Symex handles the new reject-bearing select arms as ordinary arms (no new expression forms).
- Proto-equality conformance between the eDSL example and committed `ir.json` continues to gate authoring.

**Docs:** example README updates (regenerated graph, per-artifact table; the rung-0 fidelity caveat is replaced by the pinned-upstream statement: goldens now come from upstream `bpf_flow.c`@v6.8 run in the kernel). This spec records the ladder amendment; rung-2 spec inherits the loop-construct mandate.

**Definition of done:** `pakeles diff flow-dissector` green over the expanded golden (key agreement on ok entries, reject⇔drop agreement, corpus-shape floor); all existing suites green; the factory reproducibly rebuilds the committed golden from the pinned upstream source on the 6.8.0 VM.

## Non-goals / deferred

- Loop / header-stack IR construct → rung 2 (IPv6 extension headers), per the reframing decision.
- Native (`net/core/flow_dissector.c`) MPLS semantics (multi-LSE key) — the oracle is `bpf_flow.c`, which stops at one entry.
- `flow_label`, `is_frag`, `is_first_frag` (rung 2), tunnels/`is_encap` (rung 4), in-IR projection (unchanged deferral).
- Multi-kernel-version golden management (TODO stays open).

## Risks

- **Backend instance-name assumptions** (above) — the main implementation risk; shaken out by the regenerated conformance suites.
- **Upstream build/load details:** exact clang flags, `PROG` symbol names, libbpf version in Ubuntu 24.04 (`libbpf-dev` 1.3.x — fine for this loader). All verified against the fetched source at implementation; the capture mechanism itself is proven.
- **Fetch availability:** pinned URL + sha256; if the primary mirror is down, any kernel-tree mirror serving the same tag satisfies the hash.
- **`test_run` VLAN path:** tags are in-band in packet data and the kernel presets `n_proto` from the outer ethertype, so `_dissect` enters `PROG(VLAN)` as on a real skb — no `vlan_present` special-casing in the test_run path at v6.8 (re-verify while implementing; if wrong, goldens will say so loudly).

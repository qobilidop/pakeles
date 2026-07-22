# Flow-Dissector Rung 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (executed inline). Spec: `docs/superpowers/specs/2026-07-21-flow-dissector-rung3-design.md`.

**Goal:** Make Pakeles agree with the in-kernel flow dissector on TCP-options packets by giving the `TCP` header a `doff`-sized `var_bytes` option region — mirroring IPv4.

**Architecture:** One eDSL line (`options = var_bytes(data_offset * 4 - 20)` on `linux_flow_dissector`'s `TCP` class). No IR, projection, backend, or symex change — the symbolic-layout rework already generates the wrapping-oob + truncation forks. Validation is corpus growth + a privileged golden re-mint.

**Tech Stack:** Python eDSL, `./dev.sh` (unprivileged gate + regen), `./dev-priv.sh` (privileged kernel re-mint).

## Global Constraints

- `linux_flow_dissector` ONLY. `eth_ipvx_l4` keeps fixed TCP.
- Reference interpreter is normative; the two-sided reject⇔drop golden diff maps a Pakeles reject to a kernel `BPF_DROP`.
- Existing `doff=5` corpus TCP packets must stay OK (empty option region) — do not perturb them.
- Regen: `./dev.sh scripts/gen-examples.sh`. Gate: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'` + python.

---

## Task 1: eDSL change + regen + unprivileged validation

**Files:**
- Modify: `py/src/pakeles/examples/linux_flow_dissector.py` (`TCP` class, add `options`)

- [ ] **Step 1: Add the option region.** In the `TCP` class (after `urgent`), add:
```python
    options = var_bytes(data_offset * 4 - 20)
```
- [ ] **Step 2: Regenerate the gallery.** `./dev.sh scripts/gen-examples.sh` (regenerates linux_flow_dissector ir.json + gen artifacts + gitignored vectors.json/pcap; eth_ipvx_l4 untouched). Expect a modest vector-count bump (TCP now forks into accept + oob + body-trunc per transport arm; small BVs, fast).
- [ ] **Step 3: Unprivileged gate green.** `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'`.
  - `committed_goldens_agree` MUST still pass — the OLD golden's packets are all `doff=5`, unaffected by the empty option region. (The new TCP-options *kernel* cases aren't covered until Task 2's re-mint; internal C/eBPF/Lua/BMv2 vs interp agreement over the new vectors IS covered here.)
  - If any conformance floor trips low, recalibrate (as in the symex rework).
- [ ] **Step 4: Commit.**
```bash
git add py/src/pakeles/examples/linux_flow_dissector.py examples/linux_flow_dissector
git commit -m "feat(example): rung 3 — TCP options as a doff-sized var_bytes region"
```

## Task 2: Corpus growth + privileged re-mint + kernel agreement

**Files:**
- Modify: `oracle/flow_dissector/factory/corpus.txt`
- Regenerate (privileged): `examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json`

- [ ] **Step 1: Confirm existing corpus TCP packets are `doff=5`.** In `corpus.txt`, TCP packets carry `...5018ffff...` (the `5` nibble = doff). Grep to be sure none is `doff≠5` with mismatched framing (a green gate already implies this, but verify).
- [ ] **Step 2: Append a rung-3 section to `corpus.txt`** (4 packets). Ethernet `aabbccddeeff112233445566`; TCP sport `3039`/dport `01bb`; a 4-byte MSS option `020405b4` where present:
```
# --- rung 3: TCP options (doff-sized region) ---
# accept: IPv4 + TCP doff=6 (+4 option bytes, MSS) — options fit, ports read
aabbccddeeff1122334455660800 4500002c123440004006dead0a0000010a000002 303901bb00000001000000006018ffff00000000 020405b4
# accept: IPv6 + TCP doff=6 (+4 option bytes, MSS)
aabbccddeeff11223344556686dd 6000000000180640 20010db8000000000000000000000001 20010db8000000000000000000000002 303901bb00000001000000006018ffff00000000 020405b4
# drop: IPv4 + TCP doff=4 (< 5) — kernel `tcp->doff < 5` DROP == our wrapped-length oob reject
aabbccddeeff1122334455660800 45000028123440004006dead0a0000010a000002 303901bb00000001000000004018ffff00000000
# drop: IPv4 + TCP doff=6 but no option bytes present — kernel `tcp+doff*4 > data_end` DROP == our truncation
aabbccddeeff1122334455660800 45000028123440004006dead0a0000010a000002 303901bb00000001000000006018ffff00000000
```
(Write each packet as ONE unbroken hex line — the spaces above are for readability only. Strip them.)
- [ ] **Step 3: Sanity-decode each new packet** before minting — confirm: IPv4 `total_len` (`002c`=44 for the +opts case, `0028`=40 otherwise), IPv6 `payload_len` (`0018`=24 for +opts), TCP doff nibble (`6018`/`4018`), and that the OK packets carry the trailing `020405b4` while the truncated/doff<5 packets do not.
- [ ] **Step 4: Privileged golden re-mint.** `./dev-priv.sh oracle/flow_dissector/factory/capture.sh` (kernel 6.8.0). Regenerates `flow_keys.linux-6.8.0.golden.json` with the 4 new vectors (2 ok / 2 drop). `keys_subset` name set unchanged. If `dev-priv.sh` cannot obtain privilege in this environment, STOP and report — this step is the DoD and cannot be faked.
- [ ] **Step 5: Kernel agreement green.** `./dev.sh cargo test committed_goldens_agree` MUST pass — Pakeles agrees packet-for-packet with in-kernel `bpf_flow.c@v6.8` on the 2 new OK (v4+v6 TCP options, ports read) and 2 new drops (doff<5, truncated). Also re-run the shape-floor assertions in the golden test (bump `ok`/`drop` floors if they now exceed the committed count).
- [ ] **Step 6: Commit.**
```bash
git add oracle/flow_dissector/factory/corpus.txt examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json
git commit -m "feat(oracle): rung 3 goldens — kernel agreement over TCP options (doff-sized)"
```

## Task 3: Docs + final gate + integrate

**Files:**
- Modify: `examples/linux_flow_dissector/README.md` (or the repo README carrying the divergence boundary)

- [ ] **Step 1: Update the known-divergence boundary.** Move "TCP options" from the future-rungs list to handled; note the doff<5 / truncated-options drops now agree with the kernel.
- [ ] **Step 2: Full gate green** (Rust + buf + ruff/pyright/pytest), plus anti-drift pins (`committed_ir_json_is_canonical`, gen-artifact currency).
- [ ] **Step 3: Commit docs**, then fast-forward `main` and push (per project pattern).
```bash
git add -A && git commit -m "docs: rung 3 — README divergence boundary (TCP options handled)"
git checkout main && git merge --ff-only <branch> && git push origin main
```
- [ ] **Step 4: Update memory** — flow-dissector-northstar: rung 3 done, ladder now at rung 4 (GRE/IPIP tunnel).

## Self-review

- Spec covered: TCP options field ✓, kernel mapping ✓ (doff<5 oob / truncated drop / options-fit accept / doff=5 unchanged), corpus cases ✓ (doff=6 OK v4+v6, doff<5 drop, truncated drop), re-mint ✓, README ✓, no-projection/backend/symex-change asserted and relied on ✓.
- Ordering: eDSL+regen FIRST (Task 1, tree green against old goldens), THEN corpus+re-mint (Task 2) — matches the rung-2 pattern (privileged mint last).
- Risk concentrated in Task 2 bytes + re-mint, as the spec flagged.

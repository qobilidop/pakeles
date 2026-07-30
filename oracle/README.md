# `oracle/` — golden factories and spikes for the real-world examples

This tree mints the goldens that `examples/real_world/` is checked
against, and holds the throwaway harnesses used to probe an incumbent.
It is **not** part of the everyday loop: nothing here is built or run by
`cargo test`.

One directory per incumbent, named exactly like its gallery example and
its projection module:

| `oracle/` | golden it mints | projection |
|---|---|---|
| `linux_flow_dissector/` | `examples/real_world/linux_flow_dissector/conformance/flow_keys.linux-*.golden.json` | `src/oracle/linux_flow_dissector.rs` |
| `dpdk_ptype/` | `.../dpdk_ptype/conformance/ptype.dpdk-*.golden.json` | `src/oracle/dpdk_ptype.rs` |
| `katran_flow/` | `.../katran_flow/conformance/katran.*.golden.json` | `src/oracle/katran_flow.rs` |
| `sai_parser/` | `.../sai_parser/conformance/sai.*.golden.json` | `src/oracle/sai_parser.rs` |
| `tls_clienthello/` | `.../tls_clienthello/conformance/clienthello.rustls-*.golden.json` | `src/oracle/tls_clienthello.rs` |

`<name>/factory/` mints the committed golden — `capture.sh` runs the
real implementation over `corpus.txt` and writes a version-tagged file
into the example's `conformance/`. `<name>/spike/` holds exploratory
harnesses (the eBPF loaders, the DPDK integration probe); spikes answer
a question and are kept for the record, not maintained as products.

## Why this is a separate top-level tree

**Third-party code lives or lands here, and nowhere else.**
`sai_parser/vendor/` holds Apache-2.0 sources copied verbatim from
sonic-pins at a pinned commit (see its `PROVENANCE.md`), and
`katran_flow/factory/fetch.sh` fetches GPL-2.0 katran sources at capture
time — fetch-only, deliberately never committed. Keeping all of it under
one root means the licensing rule is one sentence, and `examples/` stays
unambiguously ours.

**Everything here is out-of-gate, and some of it is privileged.** The
normal `./dev.sh` container has no `CAP_BPF`/`CAP_SYS_ADMIN`; the
factories and spikes that need a real kernel run through `./dev-priv.sh`
instead. The gate only ever diffs the committed golden.

## Rules

- **Never `git add` a whole factory or spike directory.** They generate
  build outputs, and the katran factory can hold fetched GPL sources. A
  past `git add oracle/katran/factory/` swept both into two commits and
  needed a `filter-branch` to purge. Add named files; check
  `git status` after every commit.
- **Never hand-edit a golden.** If a diff fails, the incumbent is right
  until proven otherwise — investigate our side.
- **Pin, and put the pin in the filename.** That is what makes an
  agreement claim falsifiable rather than aspirational.

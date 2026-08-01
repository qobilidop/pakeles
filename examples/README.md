# `examples/` — learn the Pakeles Python eDSL

One tutorial per directory. This is where a new Pakeles user starts:
each `<name>.py` is a complete, runnable parser description whose
docstrings generate its own rendered documentation (`gen/doc.md`) and
whose parse graph is committed beside it (`gen/graph.svg`). Read them
in order:

1. **`eth_ipvx_l4/`** — the hello-world: headers, `bits()`, select
   dispatch, branching (Ethernet → IPv4/IPv6 → TCP/UDP).
2. **`counted_items/`** — parse metadata: `Metadata` classes,
   `assign()`, metadata-driven select loops.
3. **`tlv_items/`** — sized regions: `push_region`/`pop_region`,
   `remaining()`, the region-bounded TLV loop.

To run one against a packet capture:

```sh
./dev.sh cargo run --bin pakeles -- run \
    --ir examples/eth_ipvx_l4/eth_ipvx_l4.ir.json --pcap testdata/basic.pcap
```

Editing a tutorial: change the `.py`, then regenerate its committed
artifacts with `./dev.sh scripts/gen-examples.sh`. Every tutorial
passes the full gate (canonical IR, artifacts current, backend
conformance — `rust/pakeles-dev/tests/tutorials.rs`), so they can
never rot — but they are deliberately NOT the engine's regression
fixtures: those live independently in `testdata/parsers/` and are
free to diverge (see
`docs/designs/2026-07-31-benchmarks-examples-testdata-layout.md`).

The measured corpus — incumbent-agreement claims and transcriptions
from published evaluations — lives in `../benchmarks/`.

# Pakeles

> [!WARNING]
> **Work in progress, iterating fast — don't use this yet.** The IR
> schema (`v1alpha1`), the CLI, and every API change without notice,
> and compatibility is deliberately not promised at this stage. Watch
> the repo if you're curious; don't build on it.

A toolchain built around a serializable IR (the Pakeles IR) for
wire-format parsers — one description yields many artifacts that
provably agree: reference
interpretation, generated dissectors and datapath parsers, validators,
and golden test vectors. Parsing is the decidable subset of packet
processing — parsers here are bounded by construction, which is what
makes cross-artifact equivalence provable rather than merely tested.

Status: slice 4 ("the datapath"). One description (Ethernet→IPv4→TCP)
is authored in Rust, serialized as proto3, interpreted, visualized,
differentially tested against `tshark`, compiled by symbolic execution
into a path-complete conformance suite (every parse path — truncations
and rejects included — gets a solver-derived witness packet), and compiled into three
more implementations that provably agree with it: a working Wireshark
dissector (`gen lua`, verified inside real tshark), a portable C99
parser (`gen c`, verified field-for-field on all 164 vectors), and an
eBPF program (`gen ebpf`, clang-compiled BPF bytecode verified under
the rbpf VM). Docs generate from the same description via `pakeles
doc`.

## Quickstart

The only host requirement is Docker; `./dev.sh` runs everything inside
the pinned dev image (Ubuntu 24.04 + Rust, protoc, buf, tshark 4.2, graphviz):

```sh
./dev.sh cargo test                                        # full suite
./dev.sh cargo run -- diff tshark --pcap testdata/basic.pcap
./dev.sh cargo run -- run --pcap testdata/basic.pcap       # JSON per packet
./dev.sh cargo run -- viz | dot -Tsvg -o graph.svg         # parse graph
./dev.sh cargo run -- export-ir                            # the IR itself
./dev.sh cargo run -- testgen --out vectors.json           # conformance suite
./dev.sh cargo run -- lint                                 # unreachable/shadowed
./dev.sh cargo run -- cov --pcap testdata/basic.pcap       # path coverage
./dev.sh cargo run -- gen lua --out dissector.lua          # Wireshark dissector
./dev.sh cargo run -- doc                                  # markdown docs
./dev.sh cargo run -- gen c --out-dir .                    # portable C99 parser
./dev.sh cargo run -- gen ebpf --out ebpf.c                # eBPF variant
```

Try the dissector in your own Wireshark:
`tshark -X lua_script:dissector.lua -r some.pcap` (it registers as a
postdissector, so its tree appears alongside Wireshark's built-in
dissection — side-by-side comparison for free).

## Layout

- `proto/pakeles/{ir,testvec}/v1alpha1/` — the normative schemas (proto3)
- `src/` — `ir` (types + validation), `builder`, `interp` (reference
  interpreter), `symex` (symbolic engine: testgen/lint/cov, z3 behind a
  solver trait), `codegen` (backends: Wireshark Lua), `docgen`, `viz`,
  `oracle` (tshark diff), `cli`
- `testdata/` — language-neutral fixtures (regenerate: `cargo run --bin gen_fixtures`)
- `examples/eth_ipv4_tcp/` — the gallery: every artifact one
  description yields, equality-guarded by tests
- `docs/superpowers/specs/` — design docs; start with
  `2026-07-18-pakelesir-v0-design.md`

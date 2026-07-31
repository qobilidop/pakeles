# Pakeles

[![CI](https://github.com/qobilidop/pakeles/actions/workflows/ci.yml/badge.svg)](https://github.com/qobilidop/pakeles/actions/workflows/ci.yml)

> [!WARNING]
> **Work in progress, iterating fast — don't use this yet.** The IR
> schema (`v1alpha1`), the CLI, and every API change without notice;
> compatibility is deliberately not promised at this stage. Watch
> the repo if you're curious; don't build on it.

A toolchain built around a serializable IR (the Pakeles IR) for
wire-format parsers — one description yields many artifacts that
provably agree. Parsing is the decidable subset of packet
processing — parsers here are bounded by construction, which is what
makes cross-artifact equivalence provable rather than merely tested.

A description is authored in the Python eDSL (`python/`) and canonicalized
by the Rust CLI; everything else derives from it — reference
interpretation, Graphviz parse graphs, markdown docs, a path-complete
conformance suite compiled by symbolic execution (every parse path —
truncations and rejects included — gets a solver-derived witness
packet), and four generated implementations that provably agree: a
working Wireshark dissector (`gen lua`, verified inside real tshark), a
portable C99 parser (`gen c`, verified field-for-field on the vector
suite), an eBPF program (`gen bpf`, clang-compiled and verified under
the rbpf VM), and a P4-16 program (`gen p4`, p4c-compiled and
verdict-verified on BMv2's `simple_switch`).

The gallery (`examples/`) exercises all of it: three synthetic
descriptions that each isolate one IR capability, and five models of
parsers that already run in the world — the Linux flow dissector,
DPDK's `rte_net_get_ptype()`, Meta's Katran, SONiC PINS `sai_p4`, and
TLS ClientHello / SNI — each verified to agree with the real
implementation, packet for packet, at a pinned version.

## Quickstart

The only host requirement is Docker; `./dev.sh` runs everything inside
the pinned dev image (Ubuntu 24.04 + Rust, protoc, buf, tshark 4.2,
graphviz, clang/llvm, and prebuilt p4c + BMv2 grafted from
[p4lang-builds](https://github.com/qobilidop/p4lang-builds)):

```sh
./dev.sh cargo test                    # the whole gate: core + every example crate
./dev.sh cargo run --bin pakeles -- diff tshark --pcap testdata/basic.pcap
./dev.sh cargo run --bin pakeles -- run --pcap testdata/basic.pcap    # JSON per packet
./dev.sh cargo run --bin pakeles -- viz | dot -Tsvg -o graph.svg      # parse graph
./dev.sh cargo run --bin pakeles -- export-ir                         # the IR itself
./dev.sh cargo run --bin pakeles -- testgen --out vectors.json        # conformance suite
./dev.sh cargo run --bin pakeles -- lint                              # unreachable/shadowed
./dev.sh cargo run --bin pakeles -- cov --pcap testdata/basic.pcap    # path coverage
./dev.sh cargo run --bin pakeles -- gen lua --out dissector.lua       # Wireshark dissector
./dev.sh cargo run --bin pakeles -- doc                               # markdown docs
./dev.sh cargo run --bin pakeles -- gen c --out-dir .                 # portable C99 parser
./dev.sh cargo run --bin pakeles -- gen bpf --out parser.bpf.c        # eBPF variant
./dev.sh cargo run --bin pakeles -- gen p4 --out parser.p4            # P4-16 (v1model)
./dev.sh cargo run --bin pakeles -- diff bmv2                         # vectors vs BMv2
./dev.sh cargo run -p pakeles-example-linux-flow-dissector            # vs the kernel golden
./dev.sh cargo test -p pakeles-example-tls-clienthello                # one example's gate
```

Try the generated dissector in your own Wireshark:
`tshark -X lua_script:dissector.lua -r some.pcap` (it registers as a
postdissector, so its tree appears alongside Wireshark's built-in
dissection — side-by-side comparison for free).

## Length-bounded formats (sized regions)

A length field can open a **sized region**: reads inside it are bounded
by the region, `remaining()` says how much of it is left, and closing it
requires exact exhaustion. That is what lets one description walk a TLV
loop — TLS ClientHello extensions, say — with `max_depth` still the sole
termination authority. A P4-16 parser can extract a length-computed
varbit blob but cannot parse *inside* it, so `gen p4` refuses
region-bearing descriptions and commits the refusal as
`gen/P4-UNSUPPORTED.txt`; the C, eBPF, and Wireshark backends lower them.
See [`examples/real_world/tls_clienthello/`](examples/real_world/tls_clienthello/) and
`docs/superpowers/specs/2026-07-29-sized-region-tlv-ir-design.md`.

## The Python eDSL

Parsers are authored in the Python eDSL — declarative header classes,
real infix expressions, and a parser class whose methods are the
states. Transition targets are plain attribute references, so a typo
is an editor error (unknown attribute), forward references and cycles
cost nothing, and rename/jump-to-definition just work:

```python
from pakeles import Header, Parser, State, bits, extract, reject, var_bytes
from pakeles.fmt import DEC, HEX

class Ethernet(Header):
    ethertype = bits(16, "Type", HEX)

class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl     = bits(4, "Header Length", DEC, doc="in 32-bit words")
    # ...
    options = var_bytes(ihl * 4 - 20)   # operator trees, eagerly built

class MyParser(Parser):
    max_depth = 4

    def ethernet(self) -> State:        # first-defined state = start
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {0x0800: self.ipv4},        # states reference states
            default=reject("unsupported ethertype"),
        )

    def ipv4(self) -> State:
        return extract(IPv4).accept()

MyParser.save("ir.json")                # then: pakeles lint ir.json
```

The serialized IR stays the only contract: the eDSL is the single
source, and the Rust CLI validates and canonicalizes it. The
committed gallery `ir.json` is proto-equality-tested against the
eDSL's output, and separately proven to already be in Rust-canonical
form — one authoring surface, one provably-canonical artifact. See
`python/README.md`.

## Layout

Organized by **artifact, not by language**: the repo root holds only
language-neutral trees beside the two language surfaces, and
everything about one real-world incumbent lives in one directory.
(Rationale + rejected alternatives:
`docs/designs/2026-07-30-polyglot-repo-layout.md`.)

- `proto/pakeles/{ir,testvec}/v1alpha1/` — the normative schemas
  (proto3), the contract both language surfaces vendor their
  generated code from
- `rust/` — the toolchain crates (a cargo workspace rooted at `/`):
  - `pakeles/` — the library AND the `pakeles` binary (the CLI is
    incumbent-agnostic — run/viz/gen/testgen/doc/fmt-ir plus the
    tshark/BMv2 diffs — so it lives with the core; clap sits behind a
    default-on `cli` feature). Contains `ir` (types + validation),
    `builder`, `interp` (reference interpreter), `symex` (symbolic
    engine: testgen/lint/cov, z3 behind a solver trait), `codegen`
    (backends: Wireshark Lua, C99/eBPF, P4-16), `docgen`, `viz`,
    `oracle` (tshark + BMv2 diffs). Vendors its generated protobuf
    code (`src/gen/`) and the embedded synthetic IRs (`src/examples/`),
    both equality-guarded — packaged crates are self-contained;
    consumers never need protoc.
  - `pakeles-testkit/` — the shared conformance harnesses every
    gallery example runs (compile-and-execute each backend,
    equality-guard each committed artifact)
  - `pakeles-dev/` — repo maintenance bins: `pakeles-pbgen`
    (regenerate the vendored protobuf code after a `proto/` change),
    `gen_fixtures`, `gen_examples`, `symex_bench`
- `python/` — the Python eDSL (`pakeles` on PyPI, eventually);
  vendors its generated `_pb` modules the same way
- `testdata/` — language-neutral fixtures (regenerate: `cargo run --bin gen_fixtures`)
- `examples/` — the gallery: each `<name>.py` description (the single
  authoritative source — no in-package copy) beside every artifact it
  yields, equality-guarded by tests, in two groups:
  - `synthetic/` — formats constructed to isolate one capability.
    `eth_ipvx_l4/` is the hello-world (branching demux), `counted_items/`
    exercises parse metadata, `tlv_items/` exercises sized regions.
  - `real_world/` — one workspace member per incumbent: the
    description, committed IR, generated artifacts, goldens, golden
    factory, and the projection + gate tests (`src/lib.rs`) all in one
    directory; `cargo test -p pakeles-example-<x>` runs one gate and
    `cargo run -p pakeles-example-<x>` runs its golden diff.
    `linux_flow_dissector/` is the kernel-agreement north-star (see
    below); `tls_clienthello/` is the TLV flagship (agrees with rustls
    0.23.43).
- `third_party/` — the ONLY tree holding third-party code (vendored
  sonic-pins sources; see its README for the licensing rule)
- `docs/superpowers/specs/` — design docs; start with
  `2026-07-18-pakelesir-v0-design.md`

Regenerate the gallery from its single source (the eDSL):
`./dev.sh scripts/gen-examples.sh`.

## Kernel agreement: the flow-dissector golden factory

[`examples/real_world/linux_flow_dissector/`](examples/real_world/linux_flow_dissector/) is a
north-star example: its golden-diff oracle checks that Pakeles's
extracted flow keys agree with the kernel's own flow dissector (upstream
`bpf_flow.c`, Linux 6.8), via golden `flow_keys` captured by
running that BPF program in the kernel (`BPF_PROG_TEST_RUN`). That capture
needs real kernel privilege
(`CAP_BPF`/`CAP_SYS_ADMIN`), which the normal `./dev.sh` container
deliberately doesn't have — so the golden factory is **privileged and
out-of-gate**, run through a separate `dev-priv.sh` (`docker run
--privileged`) instead:

```sh
./dev-priv.sh examples/real_world/linux_flow_dissector/factory/capture.sh
```

The everyday gate only diffs the committed, version-tagged golden file —
no privilege, no BPF, in the normal loop. See
[`examples/real_world/linux_flow_dissector/README.md`](examples/real_world/linux_flow_dissector/README.md)
for the full oracle architecture.

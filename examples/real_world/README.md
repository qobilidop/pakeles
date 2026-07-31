# `real_world/` — descriptions checked against real implementations

Each example here models a parser that already exists in the world, and
is verified to agree with it **packet for packet, at a pinned version**.
That external check is the point: without it, "our parser is correct"
only means "it passes tests we wrote from a spec we read", which is
exactly how real parsers drift apart.

Each example is its own workspace member (crate
`pakeles-example-<name>`), so **everything about one incumbent lives in
one directory**: the description (`<name>.py`, `<name>.ir.json`), the
generated artifacts (`gen/`), the goldens and vector suite
(`conformance/`), the golden factory (`factory/`, plus `spike/` where
exploratory harnesses exist), and the projection + gate tests
(`src/lib.rs`), plus the diff command itself (`src/main.rs` —
`cargo run -p pakeles-example-<name>`, or just `cargo run` from inside
the directory). `cargo test -p pakeles-example-<name>` runs one
example's gate; deleting an example is deleting one directory.

| Example (here) | Incumbent | Pinned at |
|---|---|---|
| `linux_flow_dissector/` | Linux kernel flow dissector | 6.8.0 |
| `dpdk_ptype/` | DPDK `rte_net_get_ptype()` | 23.11.4 |
| `katran_parser/` | Katran (Meta's eBPF L4 load balancer) | dd915fd2 |
| `sai_parser/` | SONiC PINS `sai_p4` on BMv2 | e77250b8 |
| `tls_clienthello/` | TLS ClientHello via rustls | 0.23.43 |

## Naming

`<namespace>_<component>`, and the directory name is THE name: it
becomes the IR parser name (`snake(ClassName)`), the `.py` / `.ir.json`
filenames, and the crate suffix, so pick it once and pick it well.

- **Namespace: whose thing we model.** The incumbent's, normally
  (`linux`, `dpdk`, `katran`, `sai`). The protocol's when the model
  target is the wire format itself and the incumbent is only the
  referee (`tls_clienthello` — rustls checks it, but what's modeled is
  the ClientHello, so `rustls_` would misstate the subject).
- **Component: the incumbent's own noun** for its parsing component or
  that component's output artifact — never our paraphrase. "Flow
  dissector" is the kernel's term, `ptype` is DPDK's noun for the
  classification (the `RTE_PTYPE_*` namespace — preferred over the
  `get_ptype` function spelling: second tokens name things, not
  calls), `parser` is the P4 pipeline stage `sai_parser.p4` names
  itself after. Where the incumbent doesn't name one, plain `parser`
  (`katran_parser` — the parse slice of `process_packet`; naming the
  whole function would overclaim the LB logic we don't model).

## How a claim is built

**The golden is minted by the incumbent, never hand-written.** Each
example's `conformance/*.golden.json` comes from running the real thing
— the actual DPDK function, the actual Katran program under
`BPF_PROG_TEST_RUN`, the actual rustls — via its `factory/`. Factories
are out-of-gate (nothing in them is built or run by `cargo test`; some
need the privileged `./dev-priv.sh`), and any third-party code they
consume lives in [`third_party/`](../../third_party/), never here.
If a diff fails, investigate our side; never edit the golden. The
oracle is the boss.

**The filename carries the version**, which is what makes a claim
falsifiable and bounded: not "we agree with DPDK" but "we agree with
DPDK 23.11.4 over these packets".

**A projection and laxness rule** (in the example's `src/lib.rs`) says
how our `ParseResult` maps onto whatever the incumbent actually
exposes, and where the two surfaces legitimately differ.

**Every example documents its boundaries and quirks** — the places we
deliberately diverge, and the surprises the incumbent turned out to
contain. Read each example's `README.md` for those; they are the most
interesting output of the exercise.

## Rules

- **Never `git add` a whole factory or spike directory.** They generate
  build outputs, and the katran factory can hold fetched GPL sources. A
  past `git add` of a factory directory swept both into two commits and
  needed a `filter-branch` to purge. Add named files; check
  `git status` after every commit.
- **Never hand-edit a golden.** If a diff fails, the incumbent is right
  until proven otherwise — investigate our side.
- **Pin, and put the pin in the filename.** That is what makes an
  agreement claim falsifiable rather than aspirational.

## What these claims are not

They are corpus-bounded and version-pinned, not proofs of equivalence
over all inputs. Symbolic-execution witness replay pushes past the
hand-written corpus by generating packets that sit exactly on path
boundaries — that is how the rustls record-version quirk was found —
but it is still evidence, not a theorem.

Contrast `../synthetic/`, whose formats were constructed to isolate one
IR capability and have no outside referent to agree with.

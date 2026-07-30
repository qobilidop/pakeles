# `real_world/` — descriptions checked against real implementations

Each example here models a parser that already exists in the world, and
is verified to agree with it **packet for packet, at a pinned version**.
That external check is the point: without it, "our parser is correct"
only means "it passes tests we wrote from a spec we read", which is
exactly how real parsers drift apart.

Each example shares its name with the factory that mints its golden and
the module that projects our parse onto the incumbent's output, so one
name follows an incumbent across all three:

| Example (here) | Incumbent | Pinned at | Factory | Projection |
|---|---|---|---|---|
| `linux_flow_dissector/` | Linux kernel flow dissector | 6.8.0 | `oracle/linux_flow_dissector/` | `src/oracle/linux_flow_dissector.rs` |
| `dpdk_ptype/` | DPDK `rte_net_get_ptype()` | 23.11.4 | `oracle/dpdk_ptype/` | `src/oracle/dpdk_ptype.rs` |
| `katran_flow/` | Katran (Meta's eBPF L4 load balancer) | dd915fd2 | `oracle/katran_flow/` | `src/oracle/katran_flow.rs` |
| `sai_parser/` | SONiC PINS `sai_p4` on BMv2 | e77250b8 | `oracle/sai_parser/` | `src/oracle/sai_parser.rs` |
| `tls_clienthello/` | TLS ClientHello via rustls | 0.23.43 | `oracle/tls_clienthello/` | `src/oracle/tls_clienthello.rs` |

## How a claim is built

**The golden is minted by the incumbent, never hand-written.** Each
example's `conformance/*.golden.json` comes from running the real thing
— the actual DPDK function, the actual Katran program under
`BPF_PROG_TEST_RUN`, the actual rustls — via `oracle/<name>/factory/`
(see [`oracle/README.md`](../../oracle/README.md) for why that tree is
separate: it is where third-party code lives, and it is out-of-gate).
If a diff fails, investigate our side; never edit the golden. The
oracle is the boss.

**The filename carries the version**, which is what makes a claim
falsifiable and bounded: not "we agree with DPDK" but "we agree with
DPDK 23.11.4 over these packets".

**A projection and laxness rule** (in `src/oracle/<name>.rs`) says how
our `ParseResult` maps onto whatever the incumbent actually exposes,
and where the two surfaces legitimately differ.

**Every example documents its boundaries and quirks** — the places we
deliberately diverge, and the surprises the incumbent turned out to
contain. Read each example's `README.md` for those; they are the most
interesting output of the exercise.

## What these claims are not

They are corpus-bounded and version-pinned, not proofs of equivalence
over all inputs. Symbolic-execution witness replay pushes past the
hand-written corpus by generating packets that sit exactly on path
boundaries — that is how the rustls record-version quirk was found —
but it is still evidence, not a theorem.

Contrast `../synthetic/`, whose formats were constructed to isolate one
IR capability and have no outside referent to agree with.

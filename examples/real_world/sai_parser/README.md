# Example: `sai_parser`

The fourth **incumbent-agreement** example (after
[`linux_flow_dissector`](../linux_flow_dissector),
[`dpdk_ptype`](../dpdk_ptype), and [`katran_flow`](../katran_flow)): a
field-for-field model of the **SONiC PINS `sai_p4` parser** — the packet
parser of Google/SONiC's production switch pipeline
([sonic-net/sonic-pins](https://github.com/sonic-net/sonic-pins)) — whose
per-packet (extracted-header bitmap, parser-error) agrees packet-for
-packet with the real program.

**The agreement claim:** agrees with **sonic-pins @ commit `e77250b8`**
(the `p4_symbolic/testdata/parser/sai_parser.p4` snapshot) over
[`conformance/sai.e77250b8dcab.golden.json`](conformance/sai.e77250b8dcab.golden.json)
— for every packet the extracted-header bitmap and the parser-error flag
match. Design doc:
[`docs/superpowers/specs/2026-07-29-sai-p4-design.md`](../../../docs/superpowers/specs/2026-07-29-sai-p4-design.md).

## A P4-vs-P4 differential on one `simple_switch`

Uniquely among the four targets, the incumbent is itself a **P4 program**
run on **BMv2 `simple_switch`** — the exact toolchain Pakeles's own BMv2
oracle ([`src/oracle/bmv2.rs`](../../../src/oracle/bmv2.rs)) already drives.
So this example is agreement between two P4 programs on one switch:

- **Our** generated `sai_parser` P4 ([`gen/parser.p4`](gen/parser.p4)) is
  run against our interpreter in the everyday gate (`bmv2.rs`).
- **Theirs** — the vendored sonic-pins parser
  ([`oracle/sai_parser/vendor/`](../../../oracle/sai_parser/vendor/), Apache-2.0,
  `PROVENANCE.md`) — is instrumented
  ([`oracle/sai_parser/factory/instrument.py`](../../../oracle/sai_parser/factory/instrument.py))
  to emit the **same verdict format** Pakeles's P4 backend uses (a
  header-validity bitmap + error byte, forwarded, deparser emits only the
  verdict), compiled with `p4c-bm2-ss`, and run over the corpus. Our
  projection ([`src/oracle/sai_parser.rs`](../../../src/oracle/sai_parser.rs)) is diffed
  against the resulting golden.

The observation patch was necessary because the prebuilt `simple_switch`
in the dev image has **logging compiled out** — `--log-console -L trace`
emits only startup lines, so SONiC's own DVaaS parser-trace route is
unavailable here (a phase-1 finding).

Re-minting (unprivileged, in the normal container):

```sh
./dev.sh oracle/sai_parser/factory/capture.sh
```

## Scope

The snapshot is a clean, bounded v1model parser: Ethernet → {IPv4, IPv6,
ARP, 802.1Q VLAN} → {ICMP, TCP, UDP}. Beyond the committed corpus, the
full byte-aligned symbolic-execution witness set (20 packets) was
replayed through the real parser on `simple_switch` — **0 divergences**.

**Boundary (documented, not modeled):**

- **The CPU `packet_out_header` arm.** `start` branches on
  `standard_metadata.ingress_port == SAI_P4_CPU_PORT`; Pakeles has no
  intrinsic-metadata input, so the model starts at `parse_ethernet` and
  the corpus never injects on port 510. Bit 0 of the bitmap (packet_out)
  is thus always 0 on both sides here.
- **Feature side-corpus.** sai_p4 uses only exact/wildcard select
  entries — no value_sets, lookahead, varbit, header stacks, or
  masked/range keys — so it does not exercise Pakeles's lookahead/
  value_set/mask-range machinery. A parity claim for those features
  needs a separate P4-feature side-corpus (a deferred roadmap item).
- **Match-action tables, the deparser's tunnel/mirror emits, and
  `verify_ipv4_checksum`** are pipeline/forwarding logic, not the parse.
- **802.1Q double-tagging** (0x88a8) is unmodeled upstream (→ accept).

## Quirk catalog (harness-verified against sonic-pins @ e77250b8)

- **No IPv6 extension-header walk.** `parse_ipv6` dispatches
  `next_header` straight to L4; a HopByHop/Routing/etc. next_header is
  taken as the L4 proto and every non-{ICMPv6,TCP,UDP} value **accepts**
  with just `ipv6` extracted — no walking. (Same shape as katran; the
  opposite of the Linux dissector.)
- **Every select miss is `accept`, never drop.** Unknown EtherType,
  unknown IP protocol, unknown VLAN inner type — all accept with the
  headers parsed so far. A v1model parser has no reject; running off the
  packet raises `error.PacketTooShort`, which the pipeline records (our
  truncation reject maps onto it) while keeping the partially-parsed
  headers valid — so a TCP-proto packet truncated after the IP header
  surfaces as `{ethernet, ipv4}` + error, `tcp` invalid.
- **The prebuilt `simple_switch` has logging compiled out** — a
  toolchain quirk that shaped the whole observation approach (a P4
  instrumentation patch rather than a log scrape).

## Files

| File | What it is |
|---|---|
| [`sai_parser.py`](sai_parser.py) | The description in the Python eDSL |
| [`sai_parser.ir.json`](sai_parser.ir.json) | The normative Pakeles IR |
| [`gen/`](gen/) | Wireshark dissector, C99 + eBPF parsers, P4-16, docs, parse graph |
| [`conformance/`](conformance/) | Symbolic-execution vectors + the sonic-pins-minted golden |

## Try it

```sh
./dev.sh cargo run -- diff sai   # our (bitmap, err) vs the committed golden
```

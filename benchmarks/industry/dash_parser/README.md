# Example: `dash_parser`

The seventh **incumbent-agreement** example (after
[`linux_flow_dissector`](../linux_flow_dissector),
[`dpdk_ptype`](../dpdk_ptype), [`katran_parser`](../katran_parser),
[`sai_parser`](../sai_parser), [`tls_clienthello`](../tls_clienthello),
and [`quic_initial`](../quic_initial)): a field-for-field model of the
**DASH BMv2 pipeline parser** — the packet parser of Microsoft's Azure
SmartNIC data plane
([sonic-net/DASH](https://github.com/sonic-net/DASH),
`dash-pipeline/bmv2/dash_parser.p4`, Apache-2.0) — whose per-packet
verdict (header-validity bitmap, parser-error code, key parsed fields)
agrees packet-for-packet with the real program.

**The agreement claim:** agrees with **DASH @ commit
`d5c003dd7774c2b43f275c0233acc73a0ea28d2f`** over
[`conformance/dash.d5c003dd7774.golden.json`](conformance/dash.d5c003dd7774.golden.json)
— for every packet the validity bitmap over the 18 parser-touched
`headers_t` instances, the parser-error code, and four key fields
(packet_subtype, u0 IHL, u0 UDP dst_port, customer EtherType) all
match. Upstream activity has decelerated (22 commits in 2025), so the
pin matters: the claim is about this snapshot, not "DASH". Charter:
[`docs/plans/2026-07-31-dash-parser-charter.md`](../../../docs/plans/2026-07-31-dash-parser-charter.md).

## The oracle

Like [`sai_parser`](../sai_parser), the incumbent is itself a P4
program run on BMv2 `simple_switch`. The vendored snapshot
([`third_party/dash/`](../../../third_party/dash/), verbatim +
`PROVENANCE.md`) is a bare parser + deparser, so nothing is patched at
all: [`factory/instrument.py`](factory/instrument.py) generates a
minimal v1model wrapper that `#include`s the unmodified parser, runs it
as a sub-parser, and emits ONLY a `pk_verdict` header (bitmap + err +
fields); `p4c-bm2-ss` compiles it and
[`factory/capture.py`](factory/capture.py) replays the corpus
([`factory/corpus.txt`](factory/corpus.txt), 63 deterministic entries
from [`factory/mk_corpus.py`](factory/mk_corpus.py)) through
`simple_switch`. The parser's explicit `verify` rejects are preserved:
v1model records them in `standard_metadata.parser_error`, which the
wrapper maps to the err byte (0 NoError, 1 PacketTooShort,
2 IPv4IncorrectVersion, 3 IPv4OptionsNotSupported,
4 InvalidIPv4Header — the contract with
[`src/lib.rs`](src/lib.rs)).

Re-minting (unprivileged, in the normal container):

```sh
./dev.sh benchmarks/industry/dash_parser/factory/capture.sh
```

**No laxness rows.** The projection matches the incumbent's verdict
field-for-field. Its two non-graph rules are transcriptions of source
semantics, not laxness: (1) bit 0 (`packet_meta`) is always set — the
source's `start` pre-sets that header valid with defaults on every
packet; (2) a `verify` reject keeps its header's bit — BMv2 runs
`verify` after the extract completes, so only a truncation loses the
in-flight header.

## Scope

Two layers straight from the source: u0 (underlay) Ethernet → {IPv4
(IHL ladder with an options varbit), IPv6, the DASH packet-metadata
sentinel EtherType `0x876d`} → UDP/TCP; UDP dst_port 4789 opens VXLAN
and the customer (overlay) layer; the sentinel path demuxes
`packet_subtype` into the flow_key / flow_data / overlay + encap
headers. 23 states, 12 header types, 18 instances; the source's
statement-level parser `if`s (subtype cascade, `flow_data.actions` bit
tests) become select states with masked arms — same truth table,
first-match order.

**Boundary (documented, not modeled):**

- **Parser only.** The 20 pipeline stages, conntrack, routing actions,
  tunnel/deparser logic, and checksum controls are forwarding logic,
  not the parse. `dp_ethernet` and the whole `u1_*` header layer are
  declared in `headers_t` but never touched by the parser (they belong
  to the pipeline's re-encap path), so they are outside the bitmap.
- **The PNA variant is not modeled.** `dash_parser.p4` carries
  `TARGET_DPDK_PNA` arms; the harness compiles the
  `TARGET_BMV2_V1MODEL` arm, which is also what DASH's own bmv2 CI
  runs.
- **Harness-supplied one-liners.** Upstream defines
  `dash_routing_actions_t` (a typedef of `dash_flow_action_t`) and
  `metadata_t` outside the vendored pair; the wrapper mirrors the
  typedef and supplies an empty `metadata_t` (the parser threads
  `meta` through untouched). See `third_party/dash/PROVENANCE.md`.
- This example's 18 header instances were the driver for widening the
  gate's BMv2 oracle bitmap decode past its old `u16` cap
  (`oracle/bmv2.rs`), so its generated `gen/parser.p4` (bit<32>
  verdict tier) is BMv2-conformance-tested like every other example —
  on top of the golden, which runs the actual incumbent on the same
  switch.

## Quirk catalog (harness-verified against DASH @ d5c003dd7774)

- **Every packet "has" DASH packet metadata.** `start` pre-sets
  `packet_meta` valid with defaults (EXTERNAL / REGULAR / NONE) before
  extracting anything; the wire header exists only behind EtherType
  `0x876d`, where its extract overwrites the defaults. A truncated
  wire re-extract leaves the valid defaults in place.
- **`packet_type` is dead to the demux.** Only `packet_subtype`
  routes; a FLOW_SYNC_REQ-typed packet with subtype NONE parses like a
  regular one.
- **The VXLAN port only counts on u0 UDP.** TCP to dst_port 4789
  stays plain TCP; UDP *src*_port 4789 does not open the tunnel; and
  there is no recursion — a customer UDP to 4789 just accepts.
- **Asymmetric IPv4-options policy.** u0 accepts options (`ihl > 5` →
  a `(ihl-5)*4`-byte varbit; `ihl < 5` → `InvalidIPv4Header`), but the
  customer layer refuses them outright (`ihl != 5` →
  `IPv4OptionsNotSupported`). Both layers verify `version == 4` first,
  so a bad version wins over a bad IHL.
- **`verify` rejects keep their header.** The failing IPv4 is valid in
  the incumbent's own verdict (extract completes before the check) —
  visible in the golden as err 2/3/4 entries with the ipv4 bit set.
- **The sentinel is u0-only.** EtherType `0x876d` as the *customer*
  EtherType is a select miss: accept, no metadata header.
- **NVGRE is dead vocabulary at this pin.** `NVGRE_PROTO` is
  `#define`d and `nvgre_t`/`u0_nvgre` declared, but no parser state
  references them — the NVGRE leg exists only in the deparser's emit
  list.
- **Everything else accepts.** Unknown EtherType, unknown IP
  protocol, unknown subtype — every select miss is `accept` with the
  headers parsed so far; the three named verifies plus truncation
  (`PacketTooShort`) are the only rejects.

## Academic footnote

`dash_pipeline.p4` is itself a published benchmark: P4Testgen
(SIGCOMM '23) evaluates on it, and ParserHawk (SIGCOMM '25) uses
`dash_parser.p4` directly. With [`sai_parser`](../sai_parser) and
[`p4lang_switch_parser`](../../academic/p4lang_switch_parser), the
gallery now holds all three of ParserHawk's benchmark sources — here
checked against the running incumbent rather than reproduced from the
paper.

## Files

| File | What it is |
|---|---|
| [`dash_parser.py`](dash_parser.py) | The description in the Python eDSL |
| [`dash_parser.ir.json`](dash_parser.ir.json) | The normative Pakeles IR |
| [`gen/`](gen/) | Wireshark dissector, C99 + eBPF parsers, P4-16, docs, parse graph |
| [`conformance/`](conformance/) | Symbolic-execution vectors + the DASH-minted golden |

## Try it

```sh
./dev.sh cargo run -p pakeles-benchmark-dash-parser   # our verdict vs the committed golden
```

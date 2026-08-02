# Example: `linux_flow_dissector`

This is Pakeles's **kernel-agreement north-star**: the permanent home of an
initiative to make Pakeles's extracted flow keys agree, packet-for-packet,
with the Linux kernel's own flow dissector (`net/core/flow_dissector.c` and
its eBPF twin `bpf_flow.c`) — the most complicated, most widely-run *bounded*
packet parser in existence. It runs on essentially every packet on every
Linux box. No synthetic example carries that credibility.

The initiative landed in **rungs**, each one flow-dissector feature, the IR
capability it forced, and the `flow_keys` fields it newly made correct. See
the full roadmap and rationale in
[`docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md`](../../../docs/superpowers/specs/2026-07-19-linux-flow-dissector-design.md).

The ladder is **complete** (rungs 0–4b): the description covers the whole
bounded core scoped below — Ethernet, VLAN/MPLS stacks, IPv4/IPv6 with
extension headers, IPv4/TCP options, and IPIP/IPv6-in-IP/GRE tunnels (TEB
included) — with kernel agreement proven over the full committed corpus.
It began as rung 0, the same demultiplexing shape as
[`eth_ipvx_l4`](../../synthetic/eth_ipvx_l4); the sections below record
what each later rung added and why.

## Scope: the bounded core, not the heuristic tail

**In scope** (across all rungs): the structurally-clean, bounded core of
flow dissection — Ethernet, VLAN/MPLS stacks, IPv4/IPv6 (incl. extension
headers), IPv4/TCP options, tunnels (IPIP, IPv6-in-IP, GRE incl. TEB),
TCP/UDP.

**Explicitly out of scope:** the heuristic / rare tail of `flow_dissector`
— PPPoE, batman-adv, PPTP-GRE quirks, and the long grab-bag of
`FLOW_DISSECTOR_KEY_*`. Parts of that tail are genuinely heuristic and
arguably outside the decidable subset Pakeles is about. The honest claim is
**"the bounded core of the Linux flow dissector,"** stated as a deliberate
boundary — not 100% parity with every dissector quirk.

## The golden-diff oracle

The oracle is a **golden-diff**, not a live BPF run in the everyday gate:

1. **Golden factory** (privileged, out-of-gate; [`factory/`](factory/)) —
   upstream `bpf_flow.c` (Linux v6.8 selftests, fetched pinned at capture
   time), compiled and loaded as `BPF_PROG_TYPE_FLOW_DISSECTOR`, run over a
   packet corpus via `BPF_PROG_TEST_RUN` inside the real kernel. Its output is a
   **kernel-version-tagged** golden file, e.g.
   [`conformance/flow_keys.linux-6.8.0.golden.json`](conformance/flow_keys.linux-6.8.0.golden.json),
   making "agrees with Linux 6.8's flow dissector" a precise, reproducible
   claim.
2. **The golden diff** ([`src/lib.rs`](src/lib.rs);
   `cargo run -p pakeles-benchmark-linux-flow-dissector`) — the everyday, unprivileged gate:
   runs Pakeles's parse, projects the result to the rung-0 subset of
   `struct bpf_flow_keys` (harness-side projection, not in the IR), and
   compares field-for-field against the committed goldens. No BPF, no
   privilege, in the normal loop.

**A note on fidelity:** as of rung 1, the goldens are minted from
**upstream `bpf_flow.c`** itself — the Linux v6.8 selftests source, fetched
pinned at capture time, compiled with its tail-call prog-array and BTF/CO-RE
`jmp_table` population, and run in-kernel via `BPF_PROG_TEST_RUN`. This is a
strictly stronger claim than rung 0's in-repo approximation: agreement now
covers VLAN (depth ≤ 2, following the kernel's own tag-sequencing rules) and
MPLS (single-entry stop), *including* agreement on kernel drops (malformed
or over-depth tag stacks), not just accepts. The rung-1 state graph — VLAN
and MPLS states added — is regenerated at
[`gen/graph.svg`](gen/graph.svg).

**Handled as of rung 3 — IPv4/TCP options.** Both are `doff`/`ihl`-sized
regions the kernel opaque-skips (it validates the size, never parses into
the options). IPv4 options were covered from rung 0 (`var_bytes(ihl*4-20)`);
rung 3 gives TCP the same treatment (`var_bytes(data_offset*4-20)`), so the
corpus now proves agreement on TCP options: `doff<5` (kernel `tcp->doff<5`
drop == our wrapped-length reject), truncated options (kernel
`tcp+doff*4>data_end` drop == our truncation), and options-present accepts
with ports read. No new IR — the same sized-region `var_bytes` mechanism.

**Handled as of rung 4b — GRE.** The kernel's `IPPROTO_GRE` arm is
order-sensitive and the parser mirrors it structurally: the 4-byte GRE
base and the C/K/S-sized optional region are *separate* states, so a
version≠0 packet is accepted immediately — `thoff` still at the GRE base,
no `is_encap`, the optionals never read even if the flags promise bytes
the packet doesn't have (the corpus proves this with a version=1,
all-flags, truncated-tail accept). Version-0 packets skip the flag-sized
optional region (a cross-header `var_bytes` over the GRE flag bits), set
`is_encap`, and dispatch: IPv4/IPv6 re-enter the IP states, and TEB
(0x6558) re-enters `parse_ethernet` itself — the kernel runs its full
`parse_eth_proto` dispatcher on the inner Ethernet, so inner VLAN
(rewriting `n_proto` and advancing `nhoff`, exactly as `PROG(VLAN)`
always does), inner MPLS (read-and-stop behind the tunnel), and nested
GRE/IPIP all compose. With this rung the bounded-core ladder is
complete: proto-47 leaves the excluded set below, and kernel agreement
is proven over the full committed corpus.

Two GRE fidelity boundaries (faithful by construction, not divergences):
the kernel masks only C/K/S/version, so the RFC 1701 R (routing) bit is
ignored by both sides — an R=1 packet parses as plain version-0 GRE with
no routing-field skip; and PPTP (version 1) is *parsed* no further than
the kernel's own accept-stop — its enhanced-GRE header lives in the
heuristic tail that is out of scope by charter.

**Handled as of rung 4a — IPIP / IPv6-in-IP tunnels.** The kernel
implements encapsulation by re-entering its own state machine
(`parse_ip_proto`'s proto-4/proto-41 arms tail-call back with a synthetic
EtherType); this parser mirrors that with two pass-through states
(`parse_ipip`, `parse_ip6ip`) that set the declared `FlowMeta.is_encap`
metadata bit — the first kernel-facing consumer of metadata v1 — and
re-enter `parse_ipv4`/`parse_ipv6` as bounded back edges (rung-2 cycle
semantics; `max_depth` 10 is the sole budget). The projection follows the
**positional-last principle**: a `flow_keys` field takes the value of the
last extraction that would have written it, replaying the kernel's
overwrite order — so `addr_proto`/addresses come from the *innermost* IP
layer (either family), `ip_proto` from the last next-protocol field, and
`flow_label` from the last IPv6 header, while `nhoff` (outer L3 start) and
`n_proto` (outer family) are deliberately written-once, exactly as
`bpf_flow.c` behaves. The corpus carries the full mixed-family matrix —
{v4,v6}×{v4,v6}, double encap, tunnels behind QinQ and behind ext-header
chains, fragmented outer (stops both sides before re-entry, `is_encap`
stays false) and fragmented inner (`is_encap` *and* `is_frag`) — with
projection unit tests on byte-identical twins of every vector, and
kernel agreement proven over all of them: the committed golden is
minted with the rung-4a capture.c, so `is_encap` and inner addresses
are compared, not excluded.

**Boundary of the agreement claim:** the reject⇔drop agreement above is
proven over the committed corpus, no further. There are known divergence
classes *outside this rung's scope* where upstream `bpf_flow.c` **accepts**
packets this parser rejects (or parses differently) — these are deliberate
rung boundaries, not bugs:

- **Fragmented IPv4** — the kernel's `PROG(IP)` stops before port parsing
  when `MF`/frag-off is set, returning `BPF_OK` with zero ports; this
  parser would instead read TCP/UDP ports off fragment data or reject.
- **IP protocols the kernel dissects beyond TCP/UDP** — ICMP and UDP-Lite
  (kernel accepts; we reject). IP protocols
  outside the kernel's dissected set are dropped by both sides, so that
  direction already agrees.
- **IPv6 extension headers (default flags):** we model `flags == 0` (what
  `BPF_PROG_TEST_RUN` produces). `flow_label` is recorded but never triggers
  an early stop (`STOP_AT_FLOW_LABEL` off); a Fragment header always stops
  after setting `is_frag`/`is_first_frag` (`PARSE_1ST_FRAG` off). Flag-driven
  behavior is out of scope — the parser takes no side channel.
- **Option-chain depth:** we bound the chain by `max_depth` (~5 option
  headers behind an Ethernet/IPv6 prefix, up to ~7 with no VLAN prefix,
  fewer behind QinQ). The kernel bounds it by the tail-call limit (~30).
  Chains of 6–~30 option headers are a known divergence: the kernel
  accepts, we reject. Not in the agreement corpus by construction. As of
  rung 4a the same budget also bounds tunnel nesting (each crossing costs
  2 entries — the corpus's deepest chain spends 7 of the 10) vs the
  kernel's tail-call limit — differently-shaped global budgets, same
  documented-boundary treatment.
  Note this bound is per-backend: the interpreter, C, BPF, and Lua count
  *every* state entered against `max_depth`, whereas the P4 backend's only
  loop bound is its option-header stack size (which counts *only* option
  pushes). So for a deep plain-IPv6 option chain the P4 datapath accepts a
  few more options than the others (and there agrees with the kernel) —
  a seam that lives entirely in this untested divergence zone.

Adding any of these as a corpus vector would make the gate legitimately
red until a future rung models them.

Refreshing the goldens (privileged; never part of the normal gate):

```sh
./dev-priv.sh benchmarks/industry/linux_flow_dissector/factory/capture.sh
```

That is the only mint path, and it needs no CI: the dev container runs a
real Linux kernel (`6.8.0-100-generic`), so the capture re-mints the
committed golden **byte-for-byte** — verified 2026-08-01, from macOS.
Goldens are kernel *behavior* over a packet corpus, so they do not
depend on the host architecture. The everyday gate never mints; it only
diffs what is committed here.

## Output contract

Agreement = matching the subset of `bpf_flow_keys` fields the covered
protocols populate, growing per rung. Rung-0 subset: `{ nhoff, thoff,
n_proto, addr_proto, ip_proto, sport, dport, ipv4_src, ipv4_dst, ipv6_src,
ipv6_dst }`; rung 2 added `{ flow_label, is_frag, is_first_frag }`; rung 4a
adds `is_encap` (declared program metadata, compared like any other
field — the committed golden is minted with the rung-4a capture.c and
carries it for every ok entry). Fields outside the current rung's subset are not compared
(documented in each golden file's `keys_subset`, never silently skipped).

## Files

| File | What it is |
|---|---|
| [`linux_flow_dissector.py`](linux_flow_dissector.py) | The description, authored in the Python eDSL — the single source; proto-equal to the IR below |
| [`linux_flow_dissector.ir.json`](linux_flow_dissector.ir.json) | The normative Pakeles IR (protojson) |
| [`gen/`](gen/) | Every generated artifact: Wireshark dissector, C99 parser, eBPF program, P4-16 program, docs, parse graph — same equality-guarded derivation as `eth_ipvx_l4` |
| [`conformance/vectors.json`](conformance/vectors.json) / [`vectors.pcap`](conformance/vectors.pcap) | Path-complete symbolic-execution suite (same discipline as `eth_ipvx_l4`) |
| [`conformance/flow_keys.linux-*.golden.json`](conformance/) | Kernel-captured golden `flow_keys`, version-tagged — the north-star artifact this example exists to hold |

## Try it

```sh
./dev.sh cargo run -p pakeles-benchmark-linux-flow-dissector   # everyday gate: our flow_keys vs committed goldens
tshark -X lua_script:gen/dissector.lua -r conformance/vectors.pcap -V
```

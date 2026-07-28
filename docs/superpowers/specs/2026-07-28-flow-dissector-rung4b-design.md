# `linux_flow_dissector` rung 4b: GRE encapsulation (design-lite)

**Date:** 2026-07-28
**Status:** design draft; implementation pending (starts after rung 4a lands)
**Depends on:** rung 4a (encap re-entrancy + `FlowMeta.is_encap` +
positional-last projection).
**Scope:** GRE (proto 47) per upstream `bpf_flow.c`'s `IPPROTO_GRE` arm:
version≠0 accept-stop, C/K/S-sized optional region, proto dispatch including
TEB (0x6558) inner-Ethernet re-entry. No new IR expected — confirmed below.

## Kernel semantics (vendored `bpf_flow.c`, IPPROTO_GRE arm)

Order matters and is the crux (verified against the vendored source):

1. Read 4-byte GRE base `{ __be16 flags; __be16 proto }`; header-read fail
   → `BPF_DROP`.
2. `flags & GRE_VERSION != 0` → **export `BPF_OK` immediately**: no thoff
   advance, **no `is_encap`**, optionals never read. A version≠0 packet
   with C/K/S set and a truncated tail is still an accept.
3. version == 0: `thoff += 4`, then `+4` for each of C (csum+pad), K (key),
   S (seq); **then** `is_encap = true`.
4. Dispatch: `proto == ETH_P_TEB` → read 14-byte inner Ethernet at thoff
   (fail → DROP), `thoff += 14`, `parse_eth_proto(eth->h_proto)` — the full
   dispatcher: inner VLAN/MPLS/IPv4/IPv6 all live. Else
   `parse_eth_proto(gre->proto)` (0x0800/0x86DD re-enter IP; others hit the
   dispatcher default → DROP, e.g. ARP-over-GRE).

## Example changes

GRE base and optional region are **separate headers/states** — required so
the version≠0 accept (step 2) never touches the optional region:

```python
class GRE(Header):
    c = bits(1); routing = bits(1); key_flag = bits(1); seq_flag = bits(1)
    reserved = bits(9)          # unchecked by the kernel — never reject
    version = bits(3)
    proto = bits(16, labels={0x0800: "IPv4", 0x86DD: "IPv6", 0x6558: "TEB"})

class GREOpt(Header):
    # C/K/S each contribute 4 bytes; cross-header byte_len is legal — the
    # definite-extraction analysis (validate.rs) admits refs to any
    # instance must-extracted on every path here, and pathid's replay is
    # sound for header fields (only metadata is banned in byte_len).
    body = var_bytes(GRE.c * 4 + GRE.key_flag * 4 + GRE.seq_flag * 4)

# parse_ipv4 / parse_ipv6 / parse_ipv6_opt selects gain: 47: "parse_gre"
"parse_gre": extract(GRE).select(GRE.version, {0: "parse_gre_opt"},
                                 default=accept()),   # version != 0: kernel stop
"parse_gre_opt": extract(GREOpt["gre_opt"])
    .assign(FlowMeta.is_encap, 1)                      # after the version gate
    .select(GRE.proto, {
        0x0800: "parse_ipv4",
        0x86DD: "parse_ipv6",
        0x6558: "parse_gre_teb",
    }, default=reject("unsupported gre proto", info=True)),
# TEB: read the inner Ethernet and re-enter the top dispatcher — a back
# edge to parse_ethernet itself (kernel: parse_eth_proto(eth->h_proto)).
"parse_gre_teb": ...  # direct transition to "parse_ethernet"
```

Open spelling question for the plan: `parse_gre_teb` needs no extract of
its own — TEB re-entry IS `parse_ethernet` (which extracts the 14-byte
Ethernet and dispatches). So the TEB arm can target `"parse_ethernet"`
directly and `parse_gre_teb` disappears. Decide in the plan; leaning
direct.

`max_depth` stays 10: deepest reasonable golden chain
eth/IPv4/GRE/GREOpt/eth/vlan_q/IPv4/TCP = 8 entries. GRE behind QinQ plus
inner VLAN (10) is the documented edge; anything deeper is the same
budget-vs-tail-call boundary as rung 3/4a.

## Projection deltas (positional-last extensions)

- **`n_proto`**: kernel PROG(VLAN) rewrites `n_proto` for INNER vlan tags
  behind TEB — the rule becomes "LAST `vlan_q` instance, else first
  `ethernet`". Identical results for all pre-4b parses (only one vlan_q
  could exist).
- **GRE-stop accept (version≠0)**: no L4 instance — projection must not
  expect one. Kernel state at export: `thoff` = GRE base start (advanced
  past the outer IP header, not past GRE), `ip_proto` = 47 (set by
  PROG(IP)/ext chain before dispatch — positional-last gives this for
  free), ports 0, `is_encap` false. Rule: last instance `gre` with no
  following L4/frag → thoff = gre.start_bit/8, stop.
- **TEB inner-Ethernet**: contributes no flow_keys writes itself (thoff
  advances structurally); inner VLAN/MPLS/IP behavior inherits from the
  rungs-1/2/4a rules by position.
- `is_encap` unchanged (metadata-declared; set only in `parse_gre_opt`).

## Oracle / corpus (the GRE matrix)

Accepts: GRE-v4/TCP, GRE-v6/UDP, GRE+C, GRE+K+S, GRE all flags,
version=1 accept-stop (with flags set + truncated tail — proves step-2
ordering), TEB + inner eth + IPv4/TCP, TEB + inner 802.1Q + IPv4/TCP
(n_proto = inner tag's encapsulated proto!), GRE behind IPIP (mixed-arm
double encap), GRE inner MPLS-over-TEB (MPLS stop inherits).
Drops: truncated GRE base, version=0 truncated optionals (kernel
header-read... optionals are thoff arithmetic, not reads — a version-0
C-flagged packet with missing option bytes drops only when the INNER
header read fails: model as truncated inner), TEB truncated inner eth,
GRE proto ARP (dispatcher default drop).
Boundary bookkeeping: the README's GRE divergence line is deleted;
proto-47 leaves the excluded set. `committed_goldens_agree` floors ratchet
by the new vector counts.

## Symex risk

Rung 4a measured: tunnel back edges multiplied per-check cost ~45x at the
old budget; mitigations were `max_depth` 10 (not 16) and parallel witness
solves. GRE adds: one more cyclic cluster entry point (`parse_gre` /
`parse_gre_opt` on the cycle through `parse_ethernet`!) — the TEB back
edge makes even `parse_ethernet`/`parse_vlan_*` cyclic. Enumeration cost
must be re-measured BEFORE building (plan gate: enumerate-only heartbeat
run; if wall-clock projects beyond a few hours, the incremental-solving
lever (symex-perf memory, lever 2) becomes a prerequisite and the user
decides sequencing).

## Fidelity boundaries (new)

- GRE routing-present packets (R bit, RFC 1701): kernel ignores the bit
  (masks only C/K/S/version), so both sides treat R=1 as plain version-0
  GRE. Faithful by construction; noted, not diverging.
- PPTP (version=1) parsing beyond the accept-stop: out of scope (the
  kernel's PPTP handling lives behind `CONFIG_NET_PTP...` heuristic tail
  — the README's out-of-scope list already covers it).

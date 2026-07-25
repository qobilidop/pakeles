# `linux_flow_dissector` rung 4a: IPIP / IPv6-in-IP encap re-entrancy

**Date:** 2026-07-24
**Status:** design approved; implementation pending
**Depends on:** metadata v1 (`2026-07-24-metadata-v1-design.md`) — rung 4a is
its first gallery consumer.
**Scope split:** rung 4 lands in two halves. **4a** (this doc): IPIP (proto 4)
and IPv6-in-IP (proto 41) — pure re-entrancy with zero new header machinery.
**4b** (future design-lite): GRE (proto 47) — flag-sized skip region (rung-3
machinery), TEB inner-Ethernet, version≠0 accept; no new IR expected.

## Reframing the "research milestone"

The ladder called rung 4 "the deepest structural change." Designing it showed
the depth lands elsewhere than expected: **re-entrancy itself is already
expressible** — the kernel implements encap by tail-calling back into the same
state machine, and the IR has allowed `max_depth`-bounded cycles since rung 2
(the ext-header self-loop), with repeated states yielding instance stacks.
Encap is "more back edges." The genuinely new capability rung 4 forces is
**metadata v1** (see its spec): `is_encap` cannot be robustly inferred from
trace shape (GRE sets it with no second IP layer; mixed-family tunnels defeat
instance counting), so the program must declare it. The research claim:
*the decidable-cycle IR subsumes tunnel re-entrancy; the reference
implementation's key-writing behavior is captured by declared, analyzable
metadata — proven by kernel agreement.*

## Kernel semantics (verified against vendored `bpf_flow.c`)

- `parse_ip_proto` holds the encap arms (`factory/build/bpf_flow.c:181-192`):
  proto 4 → `is_encap = true`, re-enter as `ETH_P_IP`; proto 41 →
  `is_encap = true`, re-enter as `ETH_P_IPV6`. Under default flags
  (`STOP_AT_ENCAP` off — same flag stance as rung 2) parsing continues into
  the inner packet.
- `parse_ip_proto` is reachable from **three** places: IPv4 (after its frag
  check), IPv6's direct `next_header`, and the ext-header chain's last link.
  All three of our demux states therefore grow tunnel arms.
- **Overwrite semantics**: each PROG simply overwrites `keys` fields as
  parsing descends — `addr_proto`, addresses, `ip_proto`, `thoff` advance per
  layer (innermost wins). But **`nhoff` is never touched after VLAN** (stays
  at the *outer* L3 start) and **`n_proto` is never rewritten on re-entry**
  (stays the outer family even for v6-in-v4). Projection must not assume
  "innermost wins" globally.
- Bounding: the kernel's budget is the ~33 tail-call limit — one global
  budget, the same shape as our `max_depth`.

## Example changes (`linux_flow_dissector.py`)

```python
class FlowMeta(Meta):
    is_encap = meta_bits(1)

# Two pass-through states — the kernel case-arms as mini-states:
"ipip":  assign(FlowMeta.is_encap, 1).goto("parse_ipv4"),   # proto 4
"ip6ip": assign(FlowMeta.is_encap, 1).goto("parse_ipv6"),   # proto 41

# parse_ipv4, parse_ipv6, parse_ipv6_opt selects each gain:
#   4: "ipip",  41: "ip6ip"
# parse_ipv6_frag keeps its unconditional accept (kernel stops there).
```

Covers v4-in-v4, v6-in-v4, v4-in-v6, v6-in-v6, tunnels behind ext-header
chains and QinQ, and arbitrary nesting — two pass-through states, six select
arms. Repeated `ipv4`/`ipv6` instances on one path are the rung-2 stack
semantics; nothing new in the IR.

**`max_depth`**: each crossing costs 2 entries (pass-through + IP state);
worst reasonable chains exceed today's 10. Raise it to cover the golden
corpus's deepest chain with headroom (likely 16), decided in the plan, and
document it as a fidelity boundary alongside rung 3's option-chain note (the
kernel's differently-shaped bound: tail-call limit).

## Projection: the positional-last principle

One rule, not per-field hacks: **a `flow_keys` field takes its value from the
last extraction that would have written it, in parse order** — the trace-order
analog of the kernel's overwrite semantics. Concretely:

| flow_keys field | Rule | Change |
|---|---|---|
| `is_encap` | `metadata.is_encap` — the metadata v1 consumer | new |
| `addr_proto`, addresses | **last** IP-family instance (either family, by position) | was: first, per-family if/else |
| `ip_proto` | last-extracted next-protocol field overall (`ipv4.protocol` / `ipv6.next_header` / ext links) — rung-2 ext-chain logic generalized by position | small |
| `nhoff` | **first** IP instance — kernel never updates `nhoff` after VLAN | stays first (verified) |
| `n_proto` | unchanged (`vlan_q` else `ethernet`) — outer family always | none (verified) |
| `thoff`, ports, frag stop | innermost L4 / last `ext_frag` — existing logic already positional | none |

The `nhoff`/`n_proto` rows are why the principle is "replay the kernel's
writes in order," not "innermost wins": some fields are written once, early.
Each row cites its `bpf_flow.c` lines in the implementation.

## Oracle, corpus, conformance

- **Golden factory**: extend the corpus with the tunnel matrix —
  {v4,v6}×{v4,v6} single encap, one double-encap, tunnel behind an ext-header
  chain, tunnel behind QinQ, fragmented **outer** (kernel stops before
  re-entry; existing frag boundary inherits), fragmented **inner**.
  Kernel-version-tagged as always; `committed_goldens_agree` gains rung-4a
  floors (rung-2 precedent).
- **Boundary bookkeeping**: after 4a the README's "GRE/IPIP — not yet
  modeled" line shrinks to "GRE (rung 4b)". Proto-47 packets stay excluded
  from comparison until 4b (kernel accepts; we reject — same
  documented-asymmetry treatment as ICMP/UDP-Lite).
- **Conformance**: rung-2 stack-aware comparison already handles repeated
  instances; tshark renders nested IP layers natively. Testvec `Expected`
  carries metadata (metadata v1), so vectors assert `is_encap` end-to-end.
- **Symex**: tunnel arms multiply paths (three demux states × two arms,
  cycles compound) — the first real nested-cycle stress of the
  symbolic-layout rework. Witness-count floors in the plan surface blowup
  early.

## Sequencing

Three independently-green slices:

1. **Metadata v1 + toy example** (its own spec/plan — lands first, like the
   symex rework before rung 3).
2. **Rung 4a**: example back edges + `FlowMeta` + projection rework
   (positional-last) + tunnel corpus/goldens + floors.
3. **Docs**: README fidelity-boundary updates, gallery regen.

Rung 4b (GRE) follows as its own design-lite → plan → build.

## Fidelity boundaries (new or inherited)

- Depth budget: `max_depth` (~16) vs the kernel's tail-call limit —
  differently shaped global budgets; ours documented per rung-3 precedent.
- Fragmented-IPv4 asymmetry inherits unchanged into encap combinations
  (fragmented outer stops both sides before re-entry under default flags).
- Proto 47 (GRE): excluded from comparison until 4b.
- Flag-driven behavior (`STOP_AT_ENCAP`): out of scope, flags == 0 only —
  unchanged rung-2 stance.

## Risks

- **Symex path growth** at nested-cycle scale. Mitigation: per-path witnesses
  from the rework; floors; `max_depth` chosen from corpus need, not
  generosity.
- **Projection subtleties** (`nhoff`/`n_proto` asymmetry class). Mitigation:
  positional-last principle stated once; per-field kernel citations; golden
  tunnel matrix covers exactly the overwrite-order cases.
- **`max_depth` clipping golden chains**. Mitigation: derive from the corpus
  and assert headroom in the floor test.

# `p4lang_switch_parser` — the parser of classic switch.p4

The parser of switch.p4, the data-plane program the P4 verification
literature measures itself against, transcribed at full size in its
as-shipped configuration: two parse layers (outer + `inner_*` twins
after tunnel decap), the fabric-header family, INT over VXLAN-GPE,
sFlow, and the LLC/SNAP, QinQ, MPLS and GRE side branches.

## Source

- `p4lang/switch` @ `7874f565` (the repo's final master commit,
  2020-10-29), `p4src/includes/parser.p4` + `headers.p4`, P4_14.
- **Configuration:** as-shipped feature defaults (`p4features.h`) +
  `__TARGET_BMV2__` — FABRIC_ENABLE, INT_EP_ENABLE +
  INT_TRANSIT_ENABLE (⇒ INT_ENABLE) and SFLOW_ENABLE on,
  ADV_FEATURES off. Preprocessed under that configuration the source
  has **63 parser states, 57 header types, 56 header instances**,
  including the stacks `vlan_tag_[2]`, `mpls[3]`, `int_val[24]`.
- The source files carry Apache-2.0 headers (the repo has no root
  LICENSE); they are reference-only here — per the group rule, this
  transcription is original expression over facts (state graph,
  dispatch values, field widths).
- Secondary cross-reference: the 2017 P4-16 translation of switch.p4
  (jafingerhut's p4lang-tests tree), the form ParserHawk benchmarks
  against. This transcription deliberately follows the original
  P4_14 repo at its final commit instead.

## Why it is here (the citation trail)

| Work | One-liner |
|---|---|
| p4v (SIGCOMM 2018) | verified switch.p4 — "58 parse states" in its modified config — in under 3 minutes |
| Vera (SIGCOMM 2018) | called switch.p4 "the largest P4 program available today" |
| bf4 (SIGCOMM 2020) | reported 165 bugs across its switch.p4 evaluation |
| SafeP4 (ECOOP 2019) | used switch.p4 in its header-validity bug study |
| Gauntlet (OSDI 2020) | translated switch.p4 as a compiler-testing workload |
| ParserHawk (SIGCOMM 2025) | benchmarks parser subsets via the 2017 P4-16 translation |

## Comparison numbers

| | source | here |
|---|---|---|
| parse states | 63 (p4v: "58" in its modified config) | **64** = 63 − 1 (`start` folded into the entry) + 2 (`mpls[3]` unrolled) |
| header types | 57 declared, 45 extracted | **47** = 45 + 1 (`ipv6_t` split into `Ipv6`/`InnerIpv6`) + 1 (`IpVersionNibble`, the `current(0, 4)` peek's type) |
| header instances | 56 declared (53 singles + 3 stacks), 52 extracted (counting each stack once) | **53** = 52 + 1 (the peeked `ip_version_nibble`) |
| verdict bitmap | — | 53 instances > 32 ⇒ the 64-bit bitmap tier |

Symbolic execution enumerates **~93.7k paths**; the conformance
suite carries **93,727 vectors** (13,003 accept / 162 reject /
80,562 truncation; ~161 MB of vectors.json — the gallery's largest
suite by far, past linux_flow_dissector's ~57k-path record).
Notably, the 2026-08-01 re-transcription of the two `current(0, 4)`
sites from the nibble-split emulation to the real `lookahead`
primitive reproduced **exactly** these counts — the two encodings
are observationally equivalent; the primitive is just the honest
structure.
All backends generate: C, eBPF C, Lua dissector, and P4-16 (no
sized regions, so no `P4-UNSUPPORTED` marker; no >32-bit select
material, so no `LUA-UNSUPPORTED` marker). C and eBPF (rbpf)
conformance pass over the full suite.

**Known scale finding (Lua):** the generated `dissector.lua`
declares one top-level `local` per ProtoField — 360 here, and
Lua's per-chunk limit is 200 locals — so the artifact generates
but fails to *load*: `tshark: Lua: syntax error: ... too many
local variables (limit is 200) in main function`. The gallery's
Lua conformance test therefore fails for this example until the
Lua backend batches its field declarations; every prior member
stayed under the limit (gibb_big_union: 154 locals). This is the
first gallery member big enough to hit it.

`pakeles lint` (the symex dead-code report) flags **16 unreachable
states** — exactly the states whose entry arms the shipped feature
flags compile out (see Transcription notes below). They are kept:
the source keeps them, and the dead code is itself a documented
property of switch.p4 in the literature (dead/unreachable code is
what p4v- and bf4-style analyses report on this program). The lint
exit code is accordingly non-zero for this example, by design.

## Transcription notes

- **`start` is folded into the entry.** The source's `start` state is
  a bare `return parse_ethernet`; `start` is a reserved attribute of
  the eDSL `Parser` class (the start-override hook), so
  `parse_ethernet` is the entry state directly (first-defined rule).
  Hence 62 of the source's 63 states appear under their own names.
- **`value mask M` arms become `masked(value, mask)`**, preserving
  the source's arm order (first-match priority): the two LLC arms of
  `parse_ethernet`/`parse_fabric_payload_header` (`0 mask 0xfe00`,
  `0 mask 0xfa00`), the three ICMPv6 typeCode arms of `parse_icmp`,
  the INT `0x000 mask 0xf00` arm, and `parse_vxlan_gpe`'s
  `0x05 mask 0xff`.
- **Concatenated select literals are split per key width.**
  `select(latest.fragOffset, latest.ihl, latest.protocol)` with
  `0x501` becomes `(0, 5, 1)`; LLC's `0xAAAA` becomes
  `(0xAA, 0xAA)`; GRE's nine-field 32-bit key turns `0x20006558`
  into K=1 ++ proto `0x6558` and the bare EtherTypes into
  all-zero-flag arms; Geneve's `0x6558` becomes `(0, 0, 0x6558)`;
  INT's `0x000 mask 0xf00` over (rsvd1:5, total_hop_cnt:8) becomes
  `(masked(0, 0x0f), masked(0, 0x00))`.
- **The IPv4 routing-protocol arms match only ihl=0 [sic].** The
  source writes the IGMP/EIGRP/OSPF/PIM/VRRP arms as bare literals
  (`2`, `88`, `89`, `103`, `112`) on the 25-bit
  (fragOffset, ihl, protocol) key, which decomposes to
  `(0, 0, proto)` — unlike the L4 arms, they carry ihl=0, so they
  match only packets whose IHL is zero. A known switch.p4 quirk;
  kept exactly.
- **The two `current(0, 4)` lookaheads** (`parse_mpls_bos`,
  `parse_lisp`) are the IR's `lookahead()` of a 4-bit
  `IpVersionNibble`, 1:1 with the source: the nibble is bound and
  dispatched on without consuming, and the continuations extract the
  REAL full inner types (`inner_ipv4`, `inner_ipv6`,
  `inner_ethernet`) over the peeked bits.
  `parse_mpls_inner_ipv4`/`_ipv6` are the pure pass-throughs they
  are in the source (metadata-only), and `parse_eompls` jumps
  straight to `parse_inner_ethernet` exactly as the source does.
  *(Until 2026-08-01 this needed the nibble-split emulation — a
  consuming nibble extract plus three invented `*Rest` headers
  defined minus their leading bits, with rerouted continuations.
  The `lookahead` IR primitive deleted all three invented types and
  restored the source correspondence; this transcription was its
  motivating exhibit.)*
- **Stacks.** `vlan_tag_[2]`: the source's three VLAN states extract
  `vlan_tag_[0]`/`[1]`; here all three share one `vlan_tag_`
  instance (the gibb pattern — a later extract overwrites).
  `mpls[3]`: the source is one self-looping state over
  `extract(mpls[next])`; the 3-entry bound is transcribed by
  unrolling into `parse_mpls`/`parse_mpls_2`/`parse_mpls_3`
  (suffixed names are unroll-invented), where a fourth label —
  a P4_14 stack-overflow parse exception — is an explicit
  `reject()`. `int_val[24]`: kept as ONE cyclic state; `max_depth`
  is the loop bound, so the source's 24-entry cap surfaces as a
  depth budget rather than an exact count (on prefixes shorter than
  the deepest one, more than 24 iterations fit).
- **`ingress` = accept.** The match-action control ends parsing, so
  every `default: ingress` (and metadata-only terminal state) is
  `accept()` — the group's classify-don't-validate rule. Where the
  source has *no* default the P4_14 semantics is a parse exception
  (drop), which is *not* "unrecognized = done": `parse_geneve`'s
  single-arm select therefore gets `default=reject(...)`. Selects
  whose 1-bit key is exhaustively covered (`bos`) keep an
  unreachable `default=accept()`.
- **All `set_metadata` is dropped** — lookup-field copies
  (`lkp_*`), tunnel-type codes, and `intrinsic_metadata.priority`
  are match-action interface state, not parse structure. The
  priority states (`parse_set_prio_med/high/max`) and the tunnel
  pass-throughs (`parse_gre_ipv4`, `parse_ipv4_in_ip`, …,
  `parse_arp_rarp`, `parse_vpls`, `parse_pw`) remain as states, as
  extract-less `goto`/accept states.
- **Fixed-width everywhere the source is.** `parse_ipv4` extracts a
  fixed 20-byte IPv4 header — options are never consumed (the
  select even reads `ihl` and dispatches only on ihl=5 for L4);
  same for TCP (dataOffset read, options never consumed). Fields
  wider than the 64-bit `bits()` ceiling are transcription
  artifacts: IPv6 addresses become opaque `var_bytes(16)` runs (the
  house idiom), while RoCE's 320-bit ib_grh / 96-bit ib_bth become
  fixed 64/32-bit words — `var_bytes` needs a statically known byte
  alignment at its extract site, and the unreachable RoCE states
  have none.
- **`ipv6_t` becomes two identical types** (`Ipv6`, `InnerIpv6`):
  a header type with variable-length fields may be extracted under
  only one instance name in the eDSL. Fixed-width types are shared
  across instances as in the source (`ethernet`/`inner_ethernet`,
  `ipv4`/`inner_ipv4`, `icmp`, `tcp`, `udp`, `sctp`).
- **Names.** State and instance names are the source's
  (`parse_all_int_meta_value_heders` keeps the source's typo;
  instance names `vlan_tag_`, `roce`, `fcoe`, `roce_v2`,
  `erspan_t3_header`, `sflow`, `int_val` are kept where they differ
  from the type name). Fields are the source's, snake-cased
  (`fragOffset` → `frag_offset`); trailing-underscore P4
  keyword-avoidance spellings stay (`type_`, `control_`, `length_`,
  `size_`); GRE's case-distinct `S`/`s` pair becomes `s`/`strict`
  (the gibb_* convention). Header types drop the source's `_t`
  suffix. Dispatch values are named after the source's defines
  (`ETHERTYPE_*`, `IP_PROTOCOLS_*`, `UDP_PORT_*`, `TCP_PORT_*`,
  `FABRIC_HEADER_TYPE_*`; `CPU_REASON_CODE_SFLOW` = 0x4, whose
  define sits outside the parser include — value cross-checked
  against the P4-16 translation).
- **Declared-but-never-extracted headers are not transcribed** (the
  eDSL emits header types from extracts): `eompls_t` (its extract is
  commented out), `outer_udp`, `arp_rarp_t`/`arp_rarp_ipv4_t`,
  `ieee802_1ah_t`, `ipsec_esp_t`/`ipsec_ah_t`, `genv_opt_*_t`,
  `sflow_sample_t`, `sflow_raw_hdr_record_t`, `sflow_sample_cpu_t`
  — hence 45 of the 57 declared types carry over.
- **Unreachable states are transcribed anyway** (the source keeps
  them; their entry arms are feature-flagged out of this
  configuration): `parse_roce`, `parse_fcoe`, `parse_roce_v2`,
  `parse_sctp`, `parse_inner_sctp`, `parse_udp_v6`,
  `parse_gre_v6`, `parse_vpls`, `parse_pw`, `parse_nsh`,
  `parse_lisp`, `parse_trill`, `parse_vntag`, `parse_bfd` — plus
  `parse_set_prio_max` (its only caller is `parse_bfd`) and
  `parse_all_int_meta_value_heders`, which the source itself
  documents as never-transitioned-to (its `0 mask 0` catch-all arm
  shadows the default; the state exists to teach the deparser the
  header order) — 16 in all, and exactly the 16 that
  `pakeles lint` reports.
- **`max_depth = 43`.** The deepest structural path is 42 states:
  ethernet → fabric_header → fabric_header_cpu →
  fabric_sflow_header → fabric_payload_header → llc_header →
  snap_header → qinq → qinq_vlan → ipv4 → udp → vxlan_gpe →
  gpe_int_header → int_header → all_int_meta_value_heders (a
  structural edge only — semantically shadowed, see above) →
  int_val ×24 → inner_ethernet → inner_ipv4 → inner L4
  (15 + 24 + 3 = 42); plus one, the group's headroom convention.
  The deepest *feasible* path skips the shadowed edge: 41 states.

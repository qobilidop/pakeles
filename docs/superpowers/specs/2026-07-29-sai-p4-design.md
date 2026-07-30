# `sai_parser` design-lite

**Date:** 2026-07-29
**Status:** BINDING.
**Incumbent pin:** sonic-net/sonic-pins @
**e77250b8dcab96e6f0e6ba1a9643f66771caa46c** (main, 2026-04-27),
`p4_symbolic/testdata/parser/sai_parser.p4` (the self-contained
single-file snapshot) + `p4_symbolic/testdata/common/headers.p4`.
**Apache-2.0 → vendored in-repo** with license header + provenance
(unlike GPL katran).

## 1. Phase-1 feasibility (done)

- The snapshot **compiles cleanly** with the container's `p4c-bm2-ss`
  (`--arch v1model -DPLATFORM_BMV2`; only unused-decl warnings) → BMv2
  JSON. No external tooling needed — it is the exact p4c/simple_switch
  Pakeles's own BMv2 oracle already drives.
- **Observation finding:** the prebuilt `simple_switch` has **logging
  compiled out** — `--log-console -L trace` yields only startup lines,
  no per-packet parser trace. So the `--log-console` route (SONiC's own
  DVaaS route) is unavailable here.
- **Chosen observation:** a P4 instrumentation patch producing the SAME
  wire verdict Pakeles's own P4 backend emits (a header-validity bitmap
  + err byte, forwarded to port 1, deparser emits only the verdict) —
  see §4. This makes the oracle a true **P4-vs-P4 differential on one
  `simple_switch`**: our generated `sai_parser` P4 and the patched
  incumbent both emit the identical (bitmap, err) format.

## 2. Coverage map (from the pinned snapshot)

A clean, bounded parser — NO IP-in-IP, NO hop-by-hop, NO tunnels (the
snapshot is simpler than `sai_p4/fixed/parser.p4`):

- `start`: `select(standard_metadata.ingress_port)` — the CPU port
  (`SAI_P4_CPU_PORT` 510) → `parse_packet_out_header` → `parse_ethernet`;
  any other port → `parse_ethernet`. **Select on intrinsic metadata**
  (the one non-header select).
- `parse_ethernet`: `select(ether_type)` → IPv4 / IPv6 / ARP / 802.1Q
  VLAN / else **accept**. (0x88a8 double-tag → accept, unmodeled.)
- `parse_8021q_vlan`: same {IPv4, IPv6, ARP, else accept}.
- `parse_ipv4`: `select(protocol)` → ICMP / TCP / UDP / else accept.
- `parse_ipv6`: `select(next_header)` → ICMPv6 / TCP / UDP / else accept
  (**no extension-header handling** — nexthdr taken as L4 directly).
- `parse_tcp` / `parse_udp` / `parse_icmp` / `parse_arp`: extract,
  accept.

Extractable headers (9): `packet_out_header, ethernet, vlan, ipv4,
ipv6, arp, icmp, tcp, udp`. **Features used:** select-on-metadata,
metadata assigns in states (the `start` init block; L4 port
normalization), duplicate-target select arms. **NOT used:** value_sets,
lookahead, varbit, header stacks, masked/range select entries — every
select entry is exact-or-wildcard. (Coverage caveat, per the roadmap:
sai_p4 will not exercise our lookahead/value_set/mask-range machinery;
a P4-feature side-corpus is a documented future item, not this run.)

## 3. Validation behavior

The only validation is `verify_ipv4_checksum` (a *control*, not the
parser) — the parser itself validates nothing beyond field widths;
there is no "reject": in v1model a parse that runs off the end of the
packet raises a parser error (`error.PacketTooShort`) that BMv2 records
and the pipeline still runs. Every select miss is `accept`. So the
observable outcome per packet is (extracted-header set, parser-error
code) — exactly our (bitmap, err).

## 4. The observation patch (vendored, derived, Apache)

A small, clearly-marked modification of the snapshot (NOT the pristine
copy — both are vendored): add a `pk_verdict_t { bit<16> bitmap; bit<8>
err }` header; in `ingress` set `egress_spec = 1` (forward); in `egress`
build `bitmap` from each header's `isValid()` in **our model's instance
order** and set `err` from `standard_metadata.parser_error`; the
deparser emits ONLY `pk_verdict`. The bit order is the contract between
the two programs and is pinned in both this doc and the example.

Bitmap bit assignment (bit i, LSB=0):

| bit | header |
|---|---|
| 0 | packet_out_header |
| 1 | ethernet |
| 2 | vlan |
| 3 | ipv4 |
| 4 | ipv6 |
| 5 | arp |
| 6 | icmp |
| 7 | tcp |
| 8 | udp |

## 5. Projection: `ParseResult` → (bitmap, err)

Harness-side (`src/oracle/sai.rs`): our `sai_parser` interp result →
`bitmap` (bit i set iff instance i was extracted) + `err` (0 on accept;
the v1model `PacketTooShort` code on a truncation reject — mapped from
our out-of-bounds reject). **Laxness rule:** our accept ⇒ exact bitmap,
err 0; our truncation reject ⇒ the bitmap of headers extracted *before*
the failing read + the `PacketTooShort` err, mirroring BMv2 (which
records the partial extraction + the error and still deparses the
verdict). Checked, not skipped.

## 6. Example scope + name

New example **`sai_parser`** — a field-for-field model of the snapshot's
parser. Header set + state graph exactly §2. Instance order (= bitmap
bit order) fixed as the table above. The CPU packet_out arm is modeled
(a select on a synthetic "ingress_port" is not expressible — Pakeles has
no intrinsic-metadata input — so packet_out is a **documented boundary**:
our model starts at `parse_ethernet`; the incumbent's CPU arm is
exercised only when injecting on port 510, which the corpus does not).
`max_depth` small (longest path eth/vlan/ip/l4 = 4).

## 7. Gate shape

- **Committed golden** (version-tagged by the sonic-pins commit):
  `examples/real_world/sai_parser/conformance/sai.<pin>.golden.json`, minted by
  `oracle/sai_p4/factory/capture.sh` (compile the patched incumbent,
  run the corpus through `simple_switch`, read the verdict). Everyday
  gate test diffs our projection against it.
- **Live differential**, tool-gated on `p4c-bm2-ss`+`simple_switch`
  (the BMv2-precedent gating already in `bmv2.rs`): recompile + re-run
  the incumbent and compare.
- `diff sai` CLI.

## 8. Out of scope

The CPU packet_out arm (needs port-510 injection / intrinsic-metadata
input Pakeles lacks), match-action tables + the deparser's tunnel/mirror
emits (LB/forwarding logic), VLAN double-tagging (unmodeled upstream),
the exact/wildcard-only feature caveat (feature side-corpus deferred),
and `verify_ipv4_checksum` (a control, not the parse).

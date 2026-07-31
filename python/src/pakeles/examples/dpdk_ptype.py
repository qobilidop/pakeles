"""A field-for-field model of DPDK 23.11's `rte_net_get_ptype()` walk.

The second incumbent-agreement example (after `linux_flow_dissector`):
the parse graph mirrors `lib/net/rte_net.c` (pinned v23.11.4), whose
output — a `RTE_PTYPE_*` classification mask plus `rte_net_hdr_lens` —
is computed by the example crate (`examples/real_world/dpdk_ptype/src/lib.rs`) as a projection of this
parser's trace and diffed against goldens minted by DPDK itself
(`examples/real_world/dpdk_ptype/factory/`).

rte_net_get_ptype classifies EVERY packet — there is no drop verdict —
so unmatched dispatch values are `accept()` here, never `reject()`: an
unknown EtherType or IP protocol just stops adding classification bits.
The only rejects this parser can produce are truncations (our eager
extraction meets DPDK's early-return-on-failed-read), which the
projection maps onto DPDK's partial masks (the laxness rule), and the
wrapped-length reject for ihl < 5 (a documented modeling boundary: DPDK
rewinds its cursor into the IP header; ours is monotonic).

Deliberate fidelity choices, all verified against the pinned source and
the in-container harness (design doc:
docs/superpowers/specs/2026-07-29-dpdk-ptype-design.md):

- MPLS (0x8847/0x8848) is an immediate accept: in 23.11.4 the MPLS
  classification is dead code (the label loop has no bottom-of-stack
  break), so the observable result is plain L2_ETHER with l2_len 14,
  label stack present or not.
- QinQ reads ONLY the second tag (`first_tag` is a blind 4-byte skip
  whose TPID is never validated), exactly like rte_net.c's
  `rte_pktmbuf_read(m, off + sizeof(*vh), ...)`.
- The IPv4 fragment word is split `flags_res_df`(2) / `mf_frag_off`(14)
  so DPDK's `0x3FFF` fragment mask is an exact select key; frag and
  protocol dispatch fold into one multi-key select.
- TCP is the fixed 20 bytes with NO options region: DPDK reports
  l4_len = doff*4 without ever reading (or requiring) the options.
  UDP and SCTP are never extracted at all — their l4_len (8/12) is
  reported blind.
- GRE has NO select on `version` (DPDK masks only C/R/K/S); R=1 means
  "not a tunnel" (accept, no optional skip). The C/K/S-sized optional
  region is `gre_opt`, arithmetic in DPDK but eager bytes here.
- The IPv6 extension-header walk is unrolled to DPDK's MAX_EXT_HDRS=5:
  the 5th consumed option link always bails (extract + accept), and a
  Fragment header is always terminal.
- The "inner" section is reachable WITHOUT a tunnel (any leftover
  post-L2 proto that misses L3 falls through): double-VLAN, Q-then-AD,
  and top-level TEB (0x6558) all land in inner states — faithful to
  the pipeline's unconditional fall-through.
- Exactly one inner level: inner tunnel protocols are default-accepts
  (`ptype_inner_l4` knows only TCP/UDP/SCTP).
- Byte-swap quirks (LITTLE-ENDIAN hosts — the golden's platform):
  rte_net.c mixes endianness in two comparisons. ptype_tunnel switches
  the big-endian leftover proto against host IPPROTO values, so
  EtherTypes 0x0400/0x2900/0x2F00 classify as IPIP/IPv6-in-IP/GRE
  tunnels; the inner section compares host u8 IP protos against
  big-endian EtherType constants, so protocol 8 (EGP) parses an inner
  IPv4 and protocol 129 an inner VLAN (both without a tunnel bit). All
  six harness-verified.

The graph is a DAG — no cycles; max_depth 20 is headroom over the
longest path (~18 states), not a semantic bound.
"""

from pakeles import (
    Header,
    Parser,
    accept,
    bits,
    extract,
    parser,
    var_bytes,
)
from pakeles._states import ArmKey, Target
from pakeles.fmt import DEC, ETHER, HEX

_ETHERTYPE_LABELS = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x88A8: "802.1AD (QinQ)",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x6558: "TEB",
}

_IP_PROTO_LABELS = {
    4: "IPIP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IP",
    47: "GRE",
    132: "SCTP",
}


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER)
    src = bits(48, "Source", ETHER)
    ethertype = bits(16, "Type", HEX, labels=_ETHERTYPE_LABELS)


class VLAN(Header):
    pcp = bits(3, "Priority", DEC)
    dei = bits(1, "DEI", DEC)
    vid = bits(12, "VLAN ID", DEC)
    proto = bits(16, "Type", HEX, labels=_ETHERTYPE_LABELS)


class QinQ(Header, name="qinq"):
    # rte_net.c reads only the SECOND tag (off + sizeof(*vh)); the first
    # tag — including its TPID — is a blind skip, never validated.
    first_tag = bits(32, "First Tag (blind)", HEX, doc="never examined by DPDK")
    tci = bits(16, "Second Tag TCI", HEX)
    proto = bits(16, "Type", HEX, labels=_ETHERTYPE_LABELS)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC, doc="never validated by DPDK")
    id = bits(16, "Identification", HEX)
    flags_res_df = bits(2, "Reserved/DF", HEX, doc="outside DPDK's 0x3FFF fragment mask")
    mf_frag_off = bits(14, "MF + Fragment Offset", HEX, doc="DPDK's frag test: != 0")
    ttl = bits(8, "Time to Live", DEC)
    protocol = bits(8, "Protocol", DEC, labels=_IP_PROTO_LABELS)
    checksum = bits(16, "Header Checksum", HEX, doc="never validated by DPDK")
    src = bits(32, "Source Address", HEX)
    dst = bits(32, "Destination Address", HEX)
    # DPDK arithmetic-skips options (off += ihl*4, never read); eager
    # bytes here — and ihl < 5 wraps, a documented modeling boundary.
    options = var_bytes(ihl * 4 - 20)


class IPv6(Header):
    version = bits(4, "Version", DEC)
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC, doc="never validated by DPDK")
    next_header = bits(8, "Next Header", DEC, labels=_IP_PROTO_LABELS)
    hop_limit = bits(8, "Hop Limit", DEC)
    src = var_bytes(16)
    dst = var_bytes(16)


class IPv6ExtOpt(Header):  # HopByHop (0) / Routing (43) / DestOpts (60)
    next_header = bits(8, "Next Header", DEC)
    hdr_ext_len = bits(8, "Hdr Ext Len", DEC, doc="in 8-octet units, excl. first 8")
    # DPDK reads only the 2-byte prefix and arithmetic-advances
    # (len+1)*8; eager bytes here (laxness boundary when absent).
    body = var_bytes(((1 + hdr_ext_len) << 3) - 2)


class IPv6Frag(Header):  # fragment header (next_header 44), always terminal
    next_header = bits(8, "Next Header", DEC)
    reserved = bits(8, "Reserved", HEX)
    frag_off = bits(13, "Fragment Offset", DEC, doc="in 8-octet units")
    res2 = bits(2, "Res", HEX)
    m_flag = bits(1, "More Fragments", DEC)
    identification = bits(32, "Identification", HEX)


class GRE(Header):
    # DPDK's opt_len table is indexed by this C/R/K/S nibble; version is
    # never examined (contrast: the kernel accept-stops on version != 0).
    c = bits(1, "Checksum Present", DEC)
    r = bits(1, "Routing Present", DEC, doc="R=1 -> not a tunnel to DPDK (opt_len 0)")
    k = bits(1, "Key Present", DEC)
    s = bits(1, "Sequence Present", DEC)
    reserved = bits(9, "Reserved0", HEX)
    version = bits(3, "Version", DEC, doc="ignored by DPDK")
    proto = bits(
        16,
        "Protocol Type",
        HEX,
        labels={0x0800: "IPv4", 0x86DD: "IPv6", 0x6558: "TEB", 0x8100: "802.1Q VLAN"},
    )


class GREOpt(Header, name="gre_opt"):  # C/K/S optional region; DPDK arithmetic, eager here
    body = var_bytes(GRE.c * 4 + GRE.k * 4 + GRE.s * 4)


class TCP(Header):
    # Fixed 20 bytes ONLY: DPDK reads sizeof(rte_tcp_hdr) and reports
    # l4_len = doff*4 blind — options are never read, doff never
    # validated (doff < 5 yields l4_len < 20 faithfully).
    sport = bits(16, "Source Port", DEC)
    dport = bits(16, "Destination Port", DEC)
    seq = bits(32, "Sequence Number", DEC)
    ack = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4, "Data Offset", DEC, doc="in 32-bit words; unvalidated")
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent Pointer", DEC)


def _l2_arms() -> dict[ArmKey, Target]:
    """Post-L2 dispatch shared by vlan/qinq: leftover EtherTypes that
    still classify are the two IP families and the inner-L2 trio."""
    return {
        0x0800: "parse_ipv4",
        0x86DD: "parse_ipv6",
        0x6558: "parse_inner_ethernet",
        0x8100: "parse_inner_vlan",
        0x88A8: "parse_inner_qinq",
        # Byte-swap quirk arms (see parse_ethernet).
        0x0400: "parse_inner_ipv4",
        0x2900: "parse_inner_ipv6",
        0x2F00: "parse_gre",
    }


def _ext_arms(opt_target: str) -> dict[ArmKey, Target]:
    """IPv6 next-header dispatch shared by ipv6 and ext_opt1..4: option
    links loop on, Fragment is terminal-bound, and the tunnel/L4 arms
    mirror rte_net.c's post-walk switch."""
    return {
        0: opt_target,
        43: opt_target,
        60: opt_target,
        44: "parse_ext_frag",
        6: "parse_tcp",
        4: "parse_inner_ipv4",
        41: "parse_inner_ipv6",
        47: "parse_gre",
        # Byte-swap quirk arms (see parse_ipv4).
        8: "parse_inner_ipv4",
        129: "parse_inner_vlan",
    }


def _inner_ext_arms(opt_target: str) -> dict[ArmKey, Target]:
    return {
        0: opt_target,
        43: opt_target,
        60: opt_target,
        44: "parse_inner_ext_frag",
        6: "parse_inner_tcp",
    }


def dpdk_ptype() -> Parser:
    states = {
        # rte_net.c:236-290. IPv4 is the fast path; one VLAN tag OR one
        # blind QinQ pair OR the MPLS dead-code stop; 0x6558 falls all
        # the way through to the inner-Ethernet read.
        "parse_ethernet": extract(Ethernet).select(
            Ethernet.ethertype,
            {
                0x0800: "parse_ipv4",
                0x86DD: "parse_ipv6",
                0x8100: "parse_vlan",
                0x88A8: "parse_qinq",
                0x8847: accept(),  # MPLS: dead code in 23.11.4 — L2_ETHER only
                0x8848: accept(),
                0x6558: "parse_inner_ethernet",
                # Byte-swap quirk (little-endian hosts): ptype_tunnel
                # switches the BIG-ENDIAN leftover proto against HOST
                # IPPROTO_* values, so these EtherTypes read as tunnels.
                0x0400: "parse_inner_ipv4",  # LE u16 4 = IPPROTO_IPIP
                0x2900: "parse_inner_ipv6",  # LE u16 41 = IPPROTO_IPV6
                0x2F00: "parse_gre",  # LE u16 47 = IPPROTO_GRE
            },
            default=accept(),
        ),
        "parse_vlan": extract(VLAN).select(
            VLAN.proto, _l2_arms(), default=accept()
        ),
        "parse_qinq": extract(QinQ).select(
            QinQ.proto, _l2_arms(), default=accept()
        ),
        # rte_net.c:296-318. One multi-key select: any nonzero MF|offset
        # hits default (frag stop — the projection reads the field);
        # otherwise dispatch on protocol. UDP(17)/SCTP(132) are blind
        # accepts — never extracted.
        "parse_ipv4": extract(IPv4).select(
            (IPv4.mf_frag_off, IPv4.protocol),
            {
                (0, 6): "parse_tcp",
                (0, 4): "parse_inner_ipv4",
                (0, 41): "parse_inner_ipv6",
                (0, 47): "parse_gre",
                # Byte-swap quirk (LE): the inner section compares the
                # HOST u8 proto against BIG-ENDIAN EtherType constants —
                # 8 matches be16(0x0800), 129 matches be16(0x8100). No
                # tunnel bit (ptype_tunnel missed).
                (0, 8): "parse_inner_ipv4",
                (0, 129): "parse_inner_vlan",
            },
            default=accept(),
        ),
        "parse_ipv6": extract(IPv6).select(
            IPv6.next_header, _ext_arms("parse_ext_opt1"), default=accept()
        ),
        # rte_net_skip_ip6_ext, unrolled to MAX_EXT_HDRS=5: the 5th
        # consumed link exhausts the loop — extract + bail, whatever its
        # next_header says (the projection snaps l3_len back to 40).
        "parse_ext_opt1": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _ext_arms("parse_ext_opt2"),
            default=accept(),
        ),
        "parse_ext_opt2": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _ext_arms("parse_ext_opt3"),
            default=accept(),
        ),
        "parse_ext_opt3": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _ext_arms("parse_ext_opt4"),
            default=accept(),
        ),
        "parse_ext_opt4": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _ext_arms("parse_ext_opt5"),
            default=accept(),
        ),
        "parse_ext_opt5": extract(IPv6ExtOpt).accept(),
        "parse_ext_frag": extract(IPv6Frag).accept(),
        # rte_net.c:133-163. Select on R only: any R=1 nibble has
        # opt_len 0 ("not a tunnel") — accept with no optional skip, no
        # tunnel bit. Version is never examined.
        "parse_gre": extract(GRE).select(
            GRE.r,
            {0: "parse_gre_opt"},
            default=accept(),
        ),
        "parse_gre_opt": extract(GREOpt).select(
            GRE.proto,
            {
                0x0800: "parse_inner_ipv4",
                0x86DD: "parse_inner_ipv6",
                0x6558: "parse_inner_ethernet",
                0x8100: "parse_inner_vlan",
                0x88A8: "parse_inner_qinq",
            },
            default=accept(),
        ),
        "parse_tcp": extract(TCP).accept(),
        # rte_net.c:384-508 — the inner mirror. Reachable without any
        # tunnel (double-VLAN, Q-then-AD, top-level TEB): the pipeline
        # falls through unconditionally. Exactly one inner level: inner
        # tunnel protocols hit default accepts.
        "parse_inner_ethernet": extract(Ethernet).select(
            Ethernet.ethertype,
            {
                0x0800: "parse_inner_ipv4",
                0x86DD: "parse_inner_ipv6",
                0x8100: "parse_inner_vlan",
                0x88A8: "parse_inner_qinq",
            },
            default=accept(),
        ),
        "parse_inner_vlan": extract(VLAN).select(
            VLAN.proto,
            {0x0800: "parse_inner_ipv4", 0x86DD: "parse_inner_ipv6"},
            default=accept(),
        ),
        "parse_inner_qinq": extract(QinQ).select(
            QinQ.proto,
            {0x0800: "parse_inner_ipv4", 0x86DD: "parse_inner_ipv6"},
            default=accept(),
        ),
        "parse_inner_ipv4": extract(IPv4).select(
            (IPv4.mf_frag_off, IPv4.protocol),
            {(0, 6): "parse_inner_tcp"},
            default=accept(),
        ),
        "parse_inner_ipv6": extract(IPv6).select(
            IPv6.next_header,
            _inner_ext_arms("parse_inner_ext_opt1"),
            default=accept(),
        ),
        "parse_inner_ext_opt1": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _inner_ext_arms("parse_inner_ext_opt2"),
            default=accept(),
        ),
        "parse_inner_ext_opt2": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _inner_ext_arms("parse_inner_ext_opt3"),
            default=accept(),
        ),
        "parse_inner_ext_opt3": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _inner_ext_arms("parse_inner_ext_opt4"),
            default=accept(),
        ),
        "parse_inner_ext_opt4": extract(IPv6ExtOpt).select(
            IPv6ExtOpt.next_header,
            _inner_ext_arms("parse_inner_ext_opt5"),
            default=accept(),
        ),
        "parse_inner_ext_opt5": extract(IPv6ExtOpt).accept(),
        "parse_inner_ext_frag": extract(IPv6Frag).accept(),
        "parse_inner_tcp": extract(TCP).accept(),
    }
    return parser(
        "dpdk_ptype",
        max_depth=20,
        start="parse_ethernet",
        states=states,
    )


if __name__ == "__main__":
    print(dpdk_ptype().to_json())

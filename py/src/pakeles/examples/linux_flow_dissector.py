"""Ethernet -> {VLAN | MPLS | IPv4 (with options) | IPv6} -> {TCP | UDP}.

The flow-dissector target: the permanent home the flow-dissector
initiative grows in. Rung 0 mirrored `eth_ipvx_l4` — plain EtherType
demux to IPv4 or IPv6, each IP header demuxing to a shared TCP or UDP
successor (a join in the parse DAG). Rung 1 adds kernel-faithful VLAN
and MPLS handling, agreeing with upstream `bpf_flow.c`:

- VLAN is unrolled to depth <=2 to mirror upstream `PROG(VLAN)`'s
  position-dependent rules: an 802.1AD (QinQ) outer tag must be followed
  by exactly one 802.1Q tag (`parse_vlan_ad` -> `parse_vlan_q` only); a
  bare 802.1Q tag is the common tail (`parse_vlan_q`) and demuxes to
  IPv4/IPv6/MPLS; a third tag of either kind is a kernel drop (no triple
  tagging, no double-Q).
- MPLS is a single-entry read-and-stop state (`parse_mpls`) mirroring
  upstream `PROG(MPLS)`: read one label entry and accept, regardless of
  the bottom-of-stack bit.

A field-for-field port of the Rust builder description (src/examples.rs)
for the rung-0 subset; the conformance test asserts proto equality with
the committed gallery `ir.json`.

IPv6 addresses are 128-bit, above the fixed-`bits` ceiling, so they are
`var_bytes` opaque runs (rendered as hex; not tshark-diffed).
"""

from pakeles import Header, Parser, bits, extract, parser, reject, var_bytes
from pakeles.fmt import DEC, ETHER, HEX, IPV4


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER, tshark="eth.dst")
    src = bits(48, "Source", ETHER, tshark="eth.src")
    ethertype = bits(
        16,
        "Type",
        HEX,
        tshark="eth.type",
        labels={
            0x0800: "IPv4",
            0x0806: "ARP",
            0x8100: "802.1Q VLAN",
            0x86DD: "IPv6",
            0x88A8: "802.1AD (QinQ)",
            0x8847: "MPLS unicast",
            0x8848: "MPLS multicast",
        },
    )


class VLAN(Header):
    pcp = bits(3, "Priority", DEC, tshark="vlan.priority")
    dei = bits(1, "DEI", DEC, tshark="vlan.dei")
    vid = bits(12, "VLAN ID", DEC, tshark="vlan.id")
    encapsulated_proto = bits(
        16,
        "Type",
        HEX,
        tshark="vlan.etype",
        labels={
            0x0800: "IPv4",
            0x86DD: "IPv6",
            0x8847: "MPLS unicast",
            0x8848: "MPLS multicast",
        },
    )


class MPLS(Header):
    label = bits(20, "Label", DEC, tshark="mpls.label")
    tc = bits(3, "Traffic Class", DEC, tshark="mpls.exp")
    s = bits(1, "Bottom of Stack", DEC, tshark="mpls.bottom")
    ttl = bits(8, "TTL", DEC, tshark="mpls.ttl")


class IPv4(Header):
    version = bits(4, "Version", DEC, tshark="ip.version")
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC, tshark="ip.len")
    id = bits(16, "Identification", HEX)
    flags = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "Time to Live", DEC, tshark="ip.ttl")
    protocol = bits(
        8,
        "Protocol",
        DEC,
        tshark="ip.proto",
        labels={1: "ICMP", 6: "TCP", 17: "UDP"},
    )
    checksum = bits(16, "Header Checksum", HEX, tshark="ip.checksum")
    src = bits(32, "Source Address", IPV4, tshark="ip.src")
    dst = bits(32, "Destination Address", IPV4, tshark="ip.dst")
    options = var_bytes(ihl * 4 - 20)


class IPv6(Header):
    version = bits(4, "Version", DEC, tshark="ipv6.version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC, tshark="ipv6.plen")
    next_header = bits(
        8,
        "Next Header",
        DEC,
        tshark="ipv6.nxt",
        labels={1: "ICMP", 6: "TCP", 17: "UDP"},
    )
    hop_limit = bits(8, "Hop Limit", DEC, tshark="ipv6.hlim")
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src = var_bytes(16)
    dst = var_bytes(16)


class IPv6ExtOpt(Header):  # HopByHop (0) / DestOpts (60) option header
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.opt.nxt")
    hdr_ext_len = bits(8, "Hdr Ext Len", DEC, doc="in 8-octet units, excl. first 8")
    # option body: (1 + hdr_ext_len) * 8 total bytes, minus the 2-byte prefix.
    body = var_bytes(((1 + hdr_ext_len) << 3) - 2)


class IPv6Frag(Header):  # fragment header (nexthdr 44)
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.frag.nxt")
    reserved = bits(8, "Reserved", HEX)
    frag_off = bits(13, "Fragment Offset", DEC, doc="in 8-octet units")
    res2 = bits(2, "Res", HEX)
    m_flag = bits(1, "More Fragments", DEC)
    identification = bits(32, "Identification", HEX)


class TCP(Header):
    sport = bits(16, "Source Port", DEC, tshark="tcp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="tcp.dstport")
    seq = bits(32, "Sequence Number", DEC)
    ack = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4, "Data Offset", DEC, doc="in 32-bit words")
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent Pointer", DEC)


class UDP(Header):
    sport = bits(16, "Source Port", DEC, tshark="udp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="udp.dstport")
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


def linux_flow_dissector() -> Parser:
    return parser(
        "linux_flow_dissector",
        max_depth=10,
        start="parse_ethernet",
        states={
            "parse_ethernet": extract(Ethernet).select(
                Ethernet.ethertype,
                {
                    0x0800: "parse_ipv4",
                    0x86DD: "parse_ipv6",
                    0x8100: "parse_vlan_q",
                    0x88A8: "parse_vlan_ad",
                    0x8847: "parse_mpls",
                    0x8848: "parse_mpls",
                },
                default=reject("unsupported ethertype", info=True),
            ),
            # Upstream PROG(VLAN), 802.1AD arm: the outer S-tag must be
            # followed by exactly one 802.1Q C-tag.
            "parse_vlan_ad": extract(VLAN["vlan_ad"]).select(
                VLAN["vlan_ad"].encapsulated_proto,
                {0x8100: "parse_vlan_q"},
                default=reject("802.1AD must be followed by 802.1Q"),
            ),
            # Upstream PROG(VLAN), common tail: the final (or only) tag;
            # a further Q/AD tag is a kernel drop (no triple tagging, no
            # double-Q).
            "parse_vlan_q": extract(VLAN["vlan_q"]).select(
                VLAN["vlan_q"].encapsulated_proto,
                {
                    0x0800: "parse_ipv4",
                    0x86DD: "parse_ipv6",
                    0x8847: "parse_mpls",
                    0x8848: "parse_mpls",
                    0x8100: reject("vlan stacking beyond kernel depth"),
                    0x88A8: reject("vlan stacking beyond kernel depth"),
                },
                default=reject("unsupported ethertype", info=True),
            ),
            "parse_ipv4": extract(IPv4).select(
                IPv4.protocol,
                {6: "parse_tcp", 17: "parse_udp"},
                default=reject("unsupported ip protocol", info=True),
            ),
            "parse_ipv6": extract(IPv6).select(
                IPv6.next_header,
                {
                    0x00: "parse_ipv6_opt",  # HopByHop
                    0x3C: "parse_ipv6_opt",  # DestOpts (60)
                    0x2C: "parse_ipv6_frag",  # Fragment (44)
                    6: "parse_tcp",
                    17: "parse_udp",
                },
                default=reject("unsupported ip protocol", info=True),
            ),
            # Kernel PROG(IPV6OP): walk the option, dispatch on its own
            # next_header — HopByHop/DestOpts loop back (self-edge).
            "parse_ipv6_opt": extract(IPv6ExtOpt["ext_opt"]).select(
                IPv6ExtOpt["ext_opt"].next_header,
                {
                    0x00: "parse_ipv6_opt",
                    0x3C: "parse_ipv6_opt",
                    0x2C: "parse_ipv6_frag",
                    6: "parse_tcp",
                    17: "parse_udp",
                },
                default=reject("unsupported ip protocol", info=True),
            ),
            # Kernel PROG(IPV6FR) under default flags: read the fragment
            # header and stop (BPF_OK), always.
            "parse_ipv6_frag": extract(IPv6Frag["ext_frag"]).accept(),
            # Upstream PROG(MPLS): read one label entry, stop, BPF_OK.
            "parse_mpls": extract(MPLS).accept(),
            "parse_tcp": extract(TCP).accept(),
            "parse_udp": extract(UDP).accept(),
        },
    )


if __name__ == "__main__":
    print(linux_flow_dissector().to_json())

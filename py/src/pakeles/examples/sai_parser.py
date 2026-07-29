"""A field-for-field model of the SONiC PINS `sai_p4` parser.

The fourth incumbent-agreement example (after `linux_flow_dissector`,
`dpdk_ptype`, and `katran_flow`): the parse graph mirrors sonic-net/
sonic-pins `p4_symbolic/testdata/parser/sai_parser.p4` (pinned commit
e77250b8), whose per-packet (extracted-header bitmap, parser-error)
is read back from the instrumented incumbent run on `simple_switch`
and compared by `src/oracle/sai.rs`.

Design doc: docs/superpowers/specs/2026-07-29-sai-p4-design.md (binding).

The sai parser is a clean, bounded v1model parser: Ethernet →
{IPv4, IPv6, ARP, 802.1Q VLAN} → {ICMP, TCP, UDP}. NO IP-in-IP, NO
hop-by-hop, NO tunnels (this snapshot is simpler than the full
`sai_p4/fixed/parser.p4`); every select miss is `accept`, and there is
no reject — a v1model parse that runs off the packet raises
`error.PacketTooShort`, which the pipeline records (our truncation
reject maps onto it).

The bitmap bit order is the contract between this example and the
incumbent's observation patch (design §4): the instance extraction
order below is exactly {ethernet, vlan, ipv4, ipv6, arp, icmp, tcp,
udp}, i.e. bits 1..8 (bit 0 = the CPU `packet_out_header`, a documented
boundary — Pakeles has no intrinsic-metadata `ingress_port` input, so
the CPU arm is not modeled and the corpus never injects on port 510).
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
from pakeles.fmt import DEC, ETHER, HEX, IPV4

_ETHERTYPE = {0x0800: "IPv4", 0x0806: "ARP", 0x8100: "802.1Q VLAN", 0x86DD: "IPv6"}
_IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER)
    src = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=_ETHERTYPE)


class VLAN(Header):
    pcp = bits(3, "PCP", DEC)
    dei = bits(1, "DEI", DEC)
    vid = bits(12, "VLAN ID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=_ETHERTYPE)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "IHL", DEC)
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC)
    identification = bits(16, "Identification", HEX)
    flags = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "TTL", DEC)
    protocol = bits(8, "Protocol", DEC, labels=_IP_PROTO)
    header_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", IPV4)
    dst_addr = bits(32, "Destination", IPV4)


class IPv6(Header):
    version = bits(4, "Version", DEC)
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC)
    next_header = bits(8, "Next Header", DEC, labels=_IP_PROTO)
    hop_limit = bits(8, "Hop Limit", DEC)
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class ARP(Header):
    hw_type = bits(16, "HW Type", DEC)
    proto_type = bits(16, "Proto Type", HEX)
    hw_addr_len = bits(8, "HW Addr Len", DEC)
    proto_addr_len = bits(8, "Proto Addr Len", DEC)
    opcode = bits(16, "Opcode", DEC)
    sender_hw = bits(48, "Sender HW", ETHER)
    sender_proto = bits(32, "Sender Proto", IPV4)
    target_hw = bits(48, "Target HW", ETHER)
    target_proto = bits(32, "Target Proto", IPV4)


class ICMP(Header):
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    checksum = bits(16, "Checksum", HEX)
    rest = bits(32, "Rest of Header", HEX)


class TCP(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    seq = bits(32, "Sequence", DEC)
    ack = bits(32, "Acknowledgment", DEC)
    data_offset = bits(4, "Data Offset", DEC)
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent", DEC)


class UDP(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


def _l3_arms() -> dict[ArmKey, Target]:
    return {0x0800: "parse_ipv4", 0x86DD: "parse_ipv6", 0x0806: "parse_arp"}


def sai_parser() -> Parser:
    return parser(
        "sai_parser",
        max_depth=6,
        start="parse_ethernet",
        states={
            # parse_ethernet: EtherType demux; 802.1Q -> vlan; else accept.
            "parse_ethernet": extract(Ethernet).select(
                Ethernet.ether_type,
                {**_l3_arms(), 0x8100: "parse_vlan"},
                default=accept(),
            ),
            # parse_8021q_vlan: same L3 demux; no further VLAN (double-tag
            # 0x88a8 unmodeled upstream -> accept).
            "parse_vlan": extract(VLAN).select(
                VLAN.ether_type, _l3_arms(), default=accept()
            ),
            "parse_ipv4": extract(IPv4).select(
                IPv4.protocol,
                {1: "parse_icmp", 6: "parse_tcp", 17: "parse_udp"},
                default=accept(),
            ),
            # No extension-header handling: next_header taken as L4 directly.
            "parse_ipv6": extract(IPv6).select(
                IPv6.next_header,
                {58: "parse_icmp", 6: "parse_tcp", 17: "parse_udp"},
                default=accept(),
            ),
            "parse_arp": extract(ARP).accept(),
            "parse_icmp": extract(ICMP).accept(),
            "parse_tcp": extract(TCP).accept(),
            "parse_udp": extract(UDP).accept(),
        },
    )


if __name__ == "__main__":
    print(sai_parser().to_json())

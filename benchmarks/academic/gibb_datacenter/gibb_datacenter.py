"""Gibb et al.'s "Data center" parse graph (ANCS 2013, Fig. 3b).

Ethernet, VLAN(x2), IPv4, ARP/RARP, and the tunnel stack: GRE (nested
up to 3), NVGRE, and VXLAN, each ending in an inner Ethernet.
Transcribed from Gibb, Varghese, Horowitz & McKeown, "Design
Principles for Packet Parsers" (ANCS 2013) - see this example's
README for the source citation and every transcription choice
(including the VXLAN port, 65535 in the source [sic]).

Suite-wide transcription semantics (shared by all gibb_* examples):
unmatched dispatch ends the recognized sequence (`default=accept()` -
these graphs classify, they do not validate); bounded repetition
(VLAN <= 2 and GRE <= 3 here) is unrolled into states, exactly as
the paper draws it; IPv4/TCP options are `var_bytes(len*4 - 20)`,
where sub-5 length values wrap to a huge byte count and reject
out-of-bounds (the linux_flow_dissector `doff < 5` idiom).
"""

from pakeles import (
    Header,
    LabeledEnum,
    Parser,
    State,
    accept,
    bits,
    extract,
    oneof,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX


class EtherType(LabeledEnum):
    """The dispatch values this graph recognizes (the source maps four
    legacy tag TPIDs to the VLAN node, and both the ARP and RARP
    EtherTypes to one `arp_rarp` node; no IPv6 in this graph)."""

    VLAN_Q = 0x8100, "802.1Q"
    VLAN_9100 = 0x9100, "802.1Q (legacy 0x9100)"
    VLAN_9200 = 0x9200, "802.1Q (legacy 0x9200)"
    VLAN_9300 = 0x9300, "802.1Q (legacy 0x9300)"
    IPV4 = 0x0800, "IPv4"
    ARP = 0x0806, "ARP"
    RARP = 0x8035, "RARP"


class IpProto(LabeledEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47


class GreProto(LabeledEnum):
    NVGRE = 0x6558, "NVGRE inner (Transparent Ethernet Bridging)"
    NESTED_GRE = 0x6559, "GRE-in-GRE"


class UdpPort(LabeledEnum):
    VXLAN = 0xFFFF, "VXLAN (pre-assignment placeholder port)"


def vlan_tags():  # a fresh OneOf per select arm
    return oneof(
        EtherType.VLAN_Q,
        EtherType.VLAN_9100,
        EtherType.VLAN_9200,
        EtherType.VLAN_9300,
    )


def arp_rarp_types():  # a fresh OneOf per select arm
    return oneof(EtherType.ARP, EtherType.RARP)


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Vlan(Header):
    """The source's `ieee802-1q` node."""

    pcp = bits(3, "PCP")
    cfi = bits(1, "CFI")
    vid = bits(12, "VLAN ID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Ipv4(Header):
    version = bits(4, "Version")
    ihl = bits(4, "IHL", DEC)
    diffserv = bits(8, "DiffServ", HEX)
    total_len = bits(16, "Total Length", DEC)
    identification = bits(16, "Identification", HEX)
    flags = bits(3, "Flags")
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "TTL", DEC)
    protocol = bits(8, "Protocol", DEC, labels=IpProto)
    hdr_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", HEX)
    dst_addr = bits(32, "Destination", HEX)
    options = var_bytes(ihl * 4 - 20)


class Icmp(Header):
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    hdr_checksum = bits(16, "Checksum", HEX)


class Tcp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    seq_no = bits(32, "Sequence Number", DEC)
    ack_no = bits(32, "Ack Number", DEC)
    data_offset = bits(4, "Data Offset", DEC)
    res = bits(3, "Reserved")
    ecn = bits(3, "ECN")
    ctrl = bits(6, "Control Bits")
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent_ptr = bits(16, "Urgent Pointer", DEC)
    options = var_bytes(data_offset * 4 - 20)


class Udp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC, labels=UdpPort)
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class Gre(Header):
    """RFC 1701-style base header. The source's single-bit flags `S`
    and `s` collide once snake-cased; here they are `s` (sequence)
    and `strict` (strict source route)."""

    c = bits(1, "C (Checksum Present)")
    r = bits(1, "R (Routing Present)")
    k = bits(1, "K (Key Present)")
    s = bits(1, "S (Sequence Present)")
    strict = bits(1, "s (Strict Source Route)")
    recurse = bits(3, "Recursion Control")
    flags = bits(5, "Flags")
    ver = bits(3, "Version", DEC)
    proto = bits(16, "Protocol", HEX, labels=GreProto)


class NvGreInner(Header):
    """The source's `nv_gre_inner` node (the NVGRE key body)."""

    tni = bits(24, "TNI", HEX)
    reserved = bits(8, "Reserved")


class Vxlan(Header):
    flags = bits(8, "Flags", HEX)
    reserved = bits(24, "Reserved")
    vni = bits(24, "VNI", HEX)
    reserved2 = bits(8, "Reserved")


class ArpRarp(Header):
    """The source's `arp_rarp` node - one node serves both ARP
    (0x0806) and RARP (0x8035)."""

    hw_type = bits(16, "Hardware Type", DEC)
    proto_type = bits(16, "Protocol Type", HEX, labels=EtherType)
    hw_addr_len = bits(8, "Hardware Address Length", DEC)
    proto_addr_len = bits(8, "Protocol Address Length", DEC)
    opcode = bits(16, "Opcode", DEC)


class ArpRarpIpv4(Header):
    """The source's `arp_rarp_ipv4` node: the address body for
    IPv4-protocol ARP/RARP."""

    src_hw_addr = bits(48, "Sender Hardware Address", ETHER)
    src_proto_addr = bits(32, "Sender Protocol Address", HEX)
    dst_hw_addr = bits(48, "Target Hardware Address", ETHER)
    dst_proto_addr = bits(32, "Target Protocol Address", HEX)


class GibbDatacenter(Parser):
    max_depth = 10

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                vlan_tags(): self.parse_vlan1,
                EtherType.IPV4: self.parse_ipv4,
                arp_rarp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_vlan1(self) -> State:
        """First of the two bounded VLAN tags (`max = 2` in the
        source, drawn as two nodes in the paper's graphs); the tag
        dispatches exactly as Ethernet does."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {
                vlan_tags(): self.parse_vlan2,
                EtherType.IPV4: self.parse_ipv4,
                arp_rarp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_vlan2(self) -> State:
        """Second VLAN tag; a third falls to the default - beyond the
        graph's bound is simply not a recognized sequence."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {
                EtherType.IPV4: self.parse_ipv4,
                arp_rarp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_ipv4(self) -> State:
        """L4 dispatch keys on (frag_offset, protocol) concatenated -
        the source's `map(fragOffset, protocol)`, so only first
        fragments dispatch."""
        return extract(Ipv4).select(
            (Ipv4.frag_offset, Ipv4.protocol),
            {
                (0, IpProto.ICMP): self.parse_icmp,
                (0, IpProto.TCP): self.parse_tcp,
                (0, IpProto.UDP): self.parse_udp,
                (0, IpProto.GRE): self.parse_gre1,
            },
            default=accept(),
        )

    def parse_icmp(self) -> State:
        return extract(Icmp).accept()

    def parse_tcp(self) -> State:
        return extract(Tcp).accept()

    def parse_udp(self) -> State:
        """The VXLAN port is the source's 65535 [sic] - a made-up
        placeholder that predates the IANA 4789 assignment."""
        return extract(Udp).select(
            Udp.dst_port,
            {UdpPort.VXLAN: self.parse_vxlan},
            default=accept(),
        )

    def parse_gre1(self) -> State:
        """First of the three bounded GRE headers (`max = 3` in the
        source). Dispatch keys on (K, proto) concatenated - the
        source's map values 0x16558/0x16559 are (K=1, EtherType)."""
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {
                (1, GreProto.NVGRE): self.parse_nv_gre_inner,
                (1, GreProto.NESTED_GRE): self.parse_gre2,
            },
            default=accept(),
        )

    def parse_gre2(self) -> State:
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {
                (1, GreProto.NVGRE): self.parse_nv_gre_inner,
                (1, GreProto.NESTED_GRE): self.parse_gre3,
            },
            default=accept(),
        )

    def parse_gre3(self) -> State:
        """Third GRE header; a fourth nesting falls to the default -
        beyond the graph's bound is simply not a recognized
        sequence. The NVGRE arm stays."""
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {(1, GreProto.NVGRE): self.parse_nv_gre_inner},
            default=accept(),
        )

    def parse_nv_gre_inner(self) -> State:
        return extract(NvGreInner).then(self.parse_ethernet2)

    def parse_vxlan(self) -> State:
        return extract(Vxlan).then(self.parse_ethernet2)

    def parse_ethernet2(self) -> State:
        """The source's `ethernet2`: the inner (tunneled) Ethernet
        header, terminal. Same layout as `Ethernet` - reused as a
        second instance."""
        return extract(Ethernet, "ethernet2").accept()

    def parse_arp_rarp(self) -> State:
        """Only IPv4-protocol ARP/RARP has a recognized body."""
        return extract(ArpRarp).select(
            ArpRarp.proto_type,
            {EtherType.IPV4: self.parse_arp_rarp_ipv4},
            default=accept(),
        )

    def parse_arp_rarp_ipv4(self) -> State:
        return extract(ArpRarpIpv4).accept()


if __name__ == "__main__":
    print(GibbDatacenter.to_json())

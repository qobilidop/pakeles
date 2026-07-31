"""Gibb et al.'s "simple" parse graph: Ethernet, VLAN(x2), IPv4, TCP, UDP.

Transcribed from the parse-graph suite of Gibb, Varghese, Horowitz &
McKeown, "Design Principles for Packet Parsers" (ANCS 2013). This
graph is the artifact/thesis member of the suite (it does not appear
in the paper's Figure 3 — see this example's README for the
provenance note and every transcription choice).

Suite-wide transcription semantics (shared by all gibb_* examples):
unmatched dispatch ends the recognized sequence (`default=accept()` -
these graphs classify, they do not validate); bounded repetition
(VLAN <= 2 here) is unrolled into states, exactly as the paper draws
it; IPv4/TCP options are `var_bytes(len*4 - 20)`, where sub-5 length
values wrap to a huge byte count and reject out-of-bounds (the
linux_flow_dissector `doff < 5` idiom).
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
    legacy tag TPIDs to the VLAN node)."""

    VLAN_Q = 0x8100, "802.1Q"
    VLAN_9100 = 0x9100, "802.1Q (legacy 0x9100)"
    VLAN_9200 = 0x9200, "802.1Q (legacy 0x9200)"
    VLAN_9300 = 0x9300, "802.1Q (legacy 0x9300)"
    IPV4 = 0x0800, "IPv4"


class IpProto(LabeledEnum):
    TCP = 6
    UDP = 17


def vlan_tags():  # a fresh OneOf per select arm
    return oneof(
        EtherType.VLAN_Q,
        EtherType.VLAN_9100,
        EtherType.VLAN_9200,
        EtherType.VLAN_9300,
    )


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
    dst_port = bits(16, "Destination Port", DEC)
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class GibbSimple(Parser):
    max_depth = 6

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                vlan_tags(): self.parse_vlan1,
                EtherType.IPV4: self.parse_ipv4,
            },
            default=accept(),
        )

    def parse_vlan1(self) -> State:
        """First of the two bounded VLAN tags (`max = 2` in the
        source, drawn as two nodes in the paper's graphs)."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {
                vlan_tags(): self.parse_vlan2,
                EtherType.IPV4: self.parse_ipv4,
            },
            default=accept(),
        )

    def parse_vlan2(self) -> State:
        """Second VLAN tag; a third falls to the default - beyond the
        graph's bound is simply not a recognized sequence."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {EtherType.IPV4: self.parse_ipv4},
            default=accept(),
        )

    def parse_ipv4(self) -> State:
        """L4 dispatch keys on (frag_offset, protocol) concatenated -
        the source's `map(fragOffset, protocol)`, so only first
        fragments dispatch."""
        return extract(Ipv4).select(
            (Ipv4.frag_offset, Ipv4.protocol),
            {
                (0, IpProto.TCP): self.parse_tcp,
                (0, IpProto.UDP): self.parse_udp,
            },
            default=accept(),
        )

    def parse_tcp(self) -> State:
        return extract(Tcp).accept()

    def parse_udp(self) -> State:
        return extract(Udp).accept()


if __name__ == "__main__":
    print(GibbSimple.to_json())

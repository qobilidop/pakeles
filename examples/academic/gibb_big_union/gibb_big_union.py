"""Gibb et al.'s "big-union" parse graph: the union of the suite's scenarios.

Transcribed from Fig. 3e of Gibb, Varghese, Horowitz & McKeown,
"Design Principles for Packet Parsers" (ANCS 2013): VLAN (802.1Q and
802.1ad, sharing one two-tag budget), 802.1ah/PBB, MPLS(x5) with
EoMPLS, IPv4/IPv6 with a full L4 fan-out (ICMP/ICMPv6, TCP, UDP,
GRE(x3) with NVGRE, IPsec ESP/AH, SCTP), VXLAN, ARP/RARP, and inner
Ethernet after each tunnel. The paper counts 28 nodes and 677 paths
on the unrolled graph.

Suite-wide transcription semantics (shared by all gibb_* examples):
unmatched dispatch ends the recognized sequence (`default=accept()` -
these graphs classify, they do not validate); bounded repetition
(VLAN <= 2 combined, MPLS <= 5, GRE <= 3) is unrolled into states;
IPv4/TCP options are `var_bytes(len*4 - 20)`; the source's MPLS
(bos, pseudo-field) lookahead becomes a bos select plus a 4-bit
nibble header with `*Rest` continuations (see gibb_service_provider).
"""

from pakeles import (
    ArmKey,
    Header,
    LabeledEnum,
    Parser,
    State,
    Target,
    accept,
    bits,
    extract,
    oneof,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX


class EtherType(LabeledEnum):
    VLAN_Q = 0x8100, "802.1Q"
    VLAN_9100 = 0x9100, "802.1Q (legacy 0x9100)"
    VLAN_9200 = 0x9200, "802.1Q (legacy 0x9200)"
    VLAN_9300 = 0x9300, "802.1Q (legacy 0x9300)"
    VLAN_AD = 0x88A8, "802.1ad"
    VLAN_AH = 0x88E7, "802.1ah (PBB)"
    MPLS_UC = 0x8847, "MPLS (unicast)"
    MPLS_MC = 0x8848, "MPLS (multicast)"
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"
    ARP = 0x0806, "ARP"
    RARP = 0x8035, "RARP"


class IpProto(LabeledEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50, "IPsec ESP"
    AH = 51, "IPsec AH"
    ICMPV6 = 58, "ICMPv6"
    SCTP = 132


class PayloadNibble(LabeledEnum):
    """First nibble of the MPLS payload (the source's 4-bit
    pseudo-field): EoMPLS control word or an IP version number."""

    EOMPLS = 0, "EoMPLS"
    IPV4 = 4, "IPv4"
    IPV6 = 6, "IPv6"


class GreProto(LabeledEnum):
    TEB = 0x6558, "Transparent Ethernet Bridging (NVGRE)"
    NESTED_GRE = 0x6559, "nested GRE (the source's GRE-in-GRE arm)"


class UdpPort(LabeledEnum):
    VXLAN = 65535, "VXLAN (the source's made-up pre-assignment port)"


def vlan_tags():  # a fresh OneOf per select arm
    return oneof(
        EtherType.VLAN_Q,
        EtherType.VLAN_9100,
        EtherType.VLAN_9200,
        EtherType.VLAN_9300,
    )


def mpls_types():
    return oneof(EtherType.MPLS_UC, EtherType.MPLS_MC)


def arp_types():
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


class Ieee8021Ad(Header):
    """The source's `ieee802-1ad` node (identical layout to 802.1Q;
    its own node in the graph, with a different dispatch map)."""

    pcp = bits(3, "PCP")
    cfi = bits(1, "CFI")
    vid = bits(12, "VLAN ID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Ieee8021Ah(Header):
    """The source's `ieee802-1ah` (PBB) node - unconditionally
    followed by the inner Ethernet."""

    pcp = bits(3, "PCP")
    dei = bits(1, "DEI")
    uca = bits(1, "UCA")
    reserved = bits(3, "Reserved")
    i_sid = bits(24, "I-SID", DEC)


class Mpls(Header):
    label = bits(20, "Label", DEC)
    tc = bits(3, "Traffic Class")
    bos = bits(1, "Bottom of Stack", DEC)
    ttl = bits(8, "TTL", DEC)


class MplsPayloadNibble(Header):
    """The source's decision-only pseudo-field, extracted as a real
    4-bit header once the label stack bottoms out."""

    v = bits(4, "Version Nibble", DEC, labels=PayloadNibble)


class EomplsRest(Header):
    """The source's `eompls` control word minus its leading zero
    nibble (already consumed as `MplsPayloadNibble`)."""

    reserved = bits(12, "Reserved")
    seq_no = bits(16, "Sequence Number", DEC)


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


class Ipv4Rest(Header):
    """IPv4 minus its leading version nibble (already consumed as
    `MplsPayloadNibble` on the MPLS path)."""

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


class Ipv6(Header):
    version = bits(4, "Version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC, labels=IpProto)
    hop_limit = bits(8, "Hop Limit", DEC)
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class Ipv6Rest(Header):
    """IPv6 minus its leading version nibble (see `Ipv4Rest`)."""

    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC, labels=IpProto)
    hop_limit = bits(8, "Hop Limit", DEC)
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class Icmp(Header):
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    hdr_checksum = bits(16, "Checksum", HEX)


class Icmpv6(Header):
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


class Vxlan(Header):
    flags = bits(8, "Flags", HEX)
    reserved = bits(24, "Reserved")
    vni = bits(24, "VNI", DEC)
    reserved2 = bits(8, "Reserved")


class Sctp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    verif_tag = bits(32, "Verification Tag", HEX)
    checksum = bits(32, "Checksum", HEX)


class Gre(Header):
    """The source's case-distinct flag pair `S`/`s` becomes
    `s`/`strict` (Python attribute names are the IR field names)."""

    c = bits(1, "C (Checksum Present)")
    r = bits(1, "R (Routing Present)")
    k = bits(1, "K (Key Present)")
    s = bits(1, "S (Sequence Present)")
    strict = bits(1, "s (Strict Source Route)")
    recurse = bits(3, "Recursion Control")
    flags = bits(5, "Flags")
    ver = bits(3, "Version")
    proto = bits(16, "Protocol Type", HEX, labels=GreProto)


class NvGreInner(Header):
    tni = bits(24, "TNI", DEC)
    reserved = bits(8, "Reserved")


class IpsecEsp(Header):
    spi = bits(32, "SPI", HEX)
    seq_no = bits(32, "Sequence Number", DEC)


class IpsecAh(Header):
    next_hdr = bits(8, "Next Header", DEC, labels=IpProto)
    length = bits(8, "Length", DEC)
    zero = bits(16, "Reserved")
    spi = bits(32, "SPI", HEX)
    seq_no = bits(32, "Sequence Number", DEC)


class ArpRarp(Header):
    hw_type = bits(16, "Hardware Type", DEC)
    proto_type = bits(16, "Protocol Type", HEX)
    hw_addr_len = bits(8, "Hardware Address Length", DEC)
    proto_addr_len = bits(8, "Protocol Address Length", DEC)
    opcode = bits(16, "Opcode", DEC)


class ArpRarpIpv4(Header):
    src_hw_addr = bits(48, "Sender Hardware Address", ETHER)
    src_proto_addr = bits(32, "Sender Protocol Address", HEX)
    dst_hw_addr = bits(48, "Target Hardware Address", ETHER)
    dst_proto_addr = bits(32, "Target Protocol Address", HEX)


class GibbBigUnion(Parser):
    max_depth = 17

    # The IPv4 L4 fan-out keys on (frag_offset, protocol) concatenated
    # (the source's `map(fragOffset, protocol)`); the full and *Rest
    # variants carry the same map, built here once to stay in sync.
    def _ipv4_arms(self) -> dict[ArmKey, Target]:
        return {
            (0, IpProto.ICMP): self.parse_icmp,
            (0, IpProto.TCP): self.parse_tcp,
            (0, IpProto.UDP): self.parse_udp,
            (0, IpProto.GRE): self.parse_gre1,
            (0, IpProto.ESP): self.parse_ipsec_esp,
            (0, IpProto.AH): self.parse_ipsec_ah,
            (0, IpProto.SCTP): self.parse_sctp,
        }

    def _ipv6_arms(self) -> dict[ArmKey, Target]:
        return {
            IpProto.ICMPV6: self.parse_icmpv6,
            IpProto.TCP: self.parse_tcp,
            IpProto.UDP: self.parse_udp,
            IpProto.GRE: self.parse_gre1,
            IpProto.ESP: self.parse_ipsec_esp,
            IpProto.AH: self.parse_ipsec_ah,
            IpProto.SCTP: self.parse_sctp,
        }

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                vlan_tags(): self.parse_vlan_q1,
                EtherType.VLAN_AD: self.parse_vlan_ad,
                mpls_types(): self.parse_mpls1,
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
                arp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_vlan_q1(self) -> State:
        """First 802.1Q tag. 802.1Q and 802.1ad share one two-tag
        budget (the source's shared `max_var = vlan` counter), so a
        second tag of either entry continues at `parse_vlan_q2`."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {
                vlan_tags(): self.parse_vlan_q2,
                mpls_types(): self.parse_mpls1,
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
                arp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_vlan_ad(self) -> State:
        """First tag, 802.1ad entry: followed only by an 802.1Q tag
        (spending the shared budget's second slot) or 802.1ah/PBB."""
        return extract(Ieee8021Ad).select(
            Ieee8021Ad.ether_type,
            {
                vlan_tags(): self.parse_vlan_q2,
                EtherType.VLAN_AH: self.parse_ieee8021ah,
            },
            default=accept(),
        )

    def parse_vlan_q2(self) -> State:
        """Second tag (either entry): the shared budget is exhausted,
        so further VLAN TPIDs fall to the default."""
        return extract(Vlan).select(
            Vlan.ether_type,
            {
                mpls_types(): self.parse_mpls1,
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
                arp_types(): self.parse_arp_rarp,
            },
            default=accept(),
        )

    def parse_ieee8021ah(self) -> State:
        return extract(Ieee8021Ah).then(self.parse_ethernet2)

    def parse_mpls1(self) -> State:
        """First of the five bounded MPLS labels (`max = 5`)."""
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls2, 1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls2(self) -> State:
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls3, 1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls3(self) -> State:
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls4, 1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls4(self) -> State:
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls5, 1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls5(self) -> State:
        """Fifth label: the bound is exhausted, so bos=0 (a sixth
        label) falls to the default - not a recognized sequence."""
        return extract(Mpls).select(
            Mpls.bos,
            {1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls_payload(self) -> State:
        """Bottom of stack: the source's 4-bit pseudo-field, extracted
        here as a real header (see the module docstring)."""
        return extract(MplsPayloadNibble).select(
            MplsPayloadNibble.v,
            {
                PayloadNibble.EOMPLS: self.parse_eompls,
                PayloadNibble.IPV4: self.parse_ipv4_rest,
                PayloadNibble.IPV6: self.parse_ipv6_rest,
            },
            default=accept(),
        )

    def parse_eompls(self) -> State:
        return extract(EomplsRest).then(self.parse_ethernet2)

    def parse_ipv4(self) -> State:
        return extract(Ipv4).select(
            (Ipv4.frag_offset, Ipv4.protocol),
            self._ipv4_arms(),
            default=accept(),
        )

    def parse_ipv4_rest(self) -> State:
        return extract(Ipv4Rest).select(
            (Ipv4Rest.frag_offset, Ipv4Rest.protocol),
            self._ipv4_arms(),
            default=accept(),
        )

    def parse_ipv6(self) -> State:
        return extract(Ipv6).select(
            Ipv6.next_hdr,
            self._ipv6_arms(),
            default=accept(),
        )

    def parse_ipv6_rest(self) -> State:
        return extract(Ipv6Rest).select(
            Ipv6Rest.next_hdr,
            self._ipv6_arms(),
            default=accept(),
        )

    def parse_icmp(self) -> State:
        return extract(Icmp).accept()

    def parse_icmpv6(self) -> State:
        return extract(Icmpv6).accept()

    def parse_tcp(self) -> State:
        return extract(Tcp).accept()

    def parse_udp(self) -> State:
        """UDP dispatches VXLAN on dstPort 65535 - the source's
        made-up value (it predates the 4789 assignment) [sic]."""
        return extract(Udp).select(
            Udp.dst_port,
            {UdpPort.VXLAN: self.parse_vxlan},
            default=accept(),
        )

    def parse_vxlan(self) -> State:
        return extract(Vxlan).then(self.parse_ethernet2)

    def parse_sctp(self) -> State:
        return extract(Sctp).accept()

    def parse_gre1(self) -> State:
        """First of the three bounded GREs (`max = 3`); dispatch keys
        on (K, proto) concatenated, so both arms require K=1."""
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {
                (1, GreProto.TEB): self.parse_nv_gre_inner,
                (1, GreProto.NESTED_GRE): self.parse_gre2,
            },
            default=accept(),
        )

    def parse_gre2(self) -> State:
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {
                (1, GreProto.TEB): self.parse_nv_gre_inner,
                (1, GreProto.NESTED_GRE): self.parse_gre3,
            },
            default=accept(),
        )

    def parse_gre3(self) -> State:
        """Third GRE: the bound is exhausted, so the nested-GRE arm
        falls to the default."""
        return extract(Gre).select(
            (Gre.k, Gre.proto),
            {(1, GreProto.TEB): self.parse_nv_gre_inner},
            default=accept(),
        )

    def parse_nv_gre_inner(self) -> State:
        return extract(NvGreInner).then(self.parse_ethernet2)

    def parse_ipsec_esp(self) -> State:
        return extract(IpsecEsp).accept()

    def parse_ipsec_ah(self) -> State:
        """The source's AH map, transcribed as-is - it includes
        ICMPv6 even when AH was reached off the IPv4 path."""
        return extract(IpsecAh).select(
            IpsecAh.next_hdr,
            {
                IpProto.ICMP: self.parse_icmp,
                IpProto.TCP: self.parse_tcp,
                IpProto.UDP: self.parse_udp,
                IpProto.GRE: self.parse_gre1,
                IpProto.ICMPV6: self.parse_icmpv6,
                IpProto.SCTP: self.parse_sctp,
            },
            default=accept(),
        )

    def parse_arp_rarp(self) -> State:
        return extract(ArpRarp).select(
            ArpRarp.proto_type,
            {EtherType.IPV4: self.parse_arp_rarp_ipv4},
            default=accept(),
        )

    def parse_arp_rarp_ipv4(self) -> State:
        return extract(ArpRarpIpv4).accept()

    def parse_ethernet2(self) -> State:
        """The inner Ethernet every tunnel bottoms out in - terminal
        in the source (its `ethernet2` node has no dispatch map)."""
        return extract(Ethernet, "ethernet2").accept()


if __name__ == "__main__":
    print(GibbBigUnion.to_json())

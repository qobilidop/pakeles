"""Kangaroo's evaluation parse tree: the Cisco-router tree of INFOCOM 2010 SVII.

Transcribed from the prose of Kozanitis, Huber, Singh & Varghese,
"Leaping Multiple Headers in a Single Bound: Wire-Speed Parsing Using
the Kangaroo System" (IEEE INFOCOM 2010), SVII - the paper's single,
unnamed evaluation input ("We obtained the following parse tree
supported by several Cisco routers"). The prose names header
successors only - no field layouts, no dispatch values, no next-header
mechanisms - so this transcription supplies standard layouts and
registry values throughout and documents every such reading in the
README. Where the prose leaves the mechanism open (MPLS's successor,
the Cisco-internal recirc/service tag EtherTypes) the choices are
borrowed from the Gibb parse-graph suite or clearly marked as
placeholders.

Shape: Ethernet -> shims {802.1Q (nested once), recirc tag, service
tag, 802.1ah, 802.1ad} -> {MPLS(x4), ARP, RARP, IPv4, IPv6}; MPLS ->
{Ethernet, IPv4, IPv6}; IPv4/IPv6 -> {TCP, UDP, GRE, ESP, ICMP,
second IPv4}; IPv6 -> extension header -> {TCP, UDP, ESP, ICMPv6};
GRE -> {IPv4, IPv6}, one tunnel level.
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
    lookahead,
    oneof,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX


class EtherType(LabeledEnum):
    """Dispatch values are ours (the prose gives none): IEEE/IANA
    registry values where published, clearly-marked placeholders for
    the Cisco-internal tags."""

    VLAN_Q = 0x8100, "802.1Q"
    RECIRC = 0xF000, "recirc tag (PLACEHOLDER - Cisco-internal, unpublished)"
    SERVICE = 0xF100, "service tag (PLACEHOLDER - Cisco-internal, unpublished)"
    VLAN_AH = 0x88E7, "802.1ah"
    VLAN_AD = 0x88A8, "802.1ad"
    MPLS_UC = 0x8847, "MPLS (unicast)"
    MPLS_MC = 0x8848, "MPLS (multicast)"
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"
    ARP = 0x0806, "ARP"
    RARP = 0x8035, "RARP"


class IpProto(LabeledEnum):
    HOPOPT = 0, "IPv6 Hop-by-Hop Options"
    ICMP = 1
    IPIP = 4, "IPv4-in-IP"
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50, "IPsec ESP"
    ICMPV6 = 58, "ICMPv6"


class PayloadNibble(LabeledEnum):
    """First nibble of the MPLS payload (mechanism borrowed from the
    Gibb suite; the prose specifies only the successor set)."""

    ETHERNET = 0, "Ethernet (EoMPLS)"
    IPV4 = 4, "IPv4"
    IPV6 = 6, "IPv6"


def mpls_types():  # a fresh OneOf per select arm
    return oneof(EtherType.MPLS_UC, EtherType.MPLS_MC)


def arp_types():
    return oneof(EtherType.ARP, EtherType.RARP)


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class ShimTag(Header):
    """One 4-byte tag layout shared by five of the six shims (802.1Q
    x2, recirc tag, service tag, 802.1ad) - the prose gives no
    layouts, and all of these are 802.1Q-shaped on real wires (the
    recirc/service shape is an interpretive choice). The shim
    identity lives in the state path, not the header type."""

    pcp = bits(3, "PCP")
    cfi = bits(1, "CFI")
    vid = bits(12, "VLAN ID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Ieee8021Ah(Header):
    """802.1ah/PBB service tag. Unlike Gibb's PBB node (which runs
    straight into the inner Ethernet), the prose says every shim can
    be followed by MPLS/ARP/RARP/IPv4/IPv6 - so this tag ends in a
    16-bit EtherType and dispatches like the others (interpretive)."""

    pcp = bits(3, "PCP")
    dei = bits(1, "DEI")
    uca = bits(1, "UCA")
    reserved = bits(3, "Reserved")
    i_sid = bits(24, "I-SID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Mpls(Header):
    label = bits(20, "Label", DEC)
    tc = bits(3, "Traffic Class")
    bos = bits(1, "Bottom of Stack", DEC)
    ttl = bits(8, "TTL", DEC)


class MplsPayloadNibble(Header):
    """The Gibb suite's decision-only pseudo-field, extracted as a
    real 4-bit header once the label stack bottoms out."""

    v = bits(4, "Version Nibble", DEC, labels=PayloadNibble)


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


class Ipv6ExtHdr(Header):
    """The prose's single "IPv6 extension header": the standard
    two-byte prefix plus an 8-octet-unit body."""

    next_hdr = bits(8, "Next Header", DEC, labels=IpProto)
    hdr_ext_len = bits(8, "Hdr Ext Len", DEC, doc="in 8-octet units, excl. first 8")
    # option body: (1 + hdr_ext_len) * 8 total bytes, minus the 2-byte prefix.
    body = var_bytes(((1 + hdr_ext_len) << 3) - 2)


class Gre(Header):
    """RFC 1701 layout; the flag-driven optional fields cover all
    eight C/K/S length combinations natively (the paper's "eight
    different lengths"). The source's case-distinct `S`/`s` flag pair
    becomes `s`/`strict`."""

    c = bits(1, "C (Checksum Present)")
    r = bits(1, "R (Routing Present)")
    k = bits(1, "K (Key Present)")
    s = bits(1, "S (Sequence Present)")
    strict = bits(1, "s (Strict Source Route)")
    recurse = bits(3, "Recursion Control")
    flags = bits(5, "Flags")
    ver = bits(3, "Version")
    proto = bits(
        16, "Protocol Type", HEX, labels=[EtherType.IPV4, EtherType.IPV6]
    )
    opt = var_bytes(c * 4 + k * 4 + s * 4)


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


class Icmp(Header):
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    hdr_checksum = bits(16, "Checksum", HEX)


class Icmpv6(Header):
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    hdr_checksum = bits(16, "Checksum", HEX)


class IpsecEsp(Header):
    spi = bits(32, "SPI", HEX)
    seq_no = bits(32, "Sequence Number", DEC)


class ArpRarp(Header):
    """One node for the prose's separately-listed ARP and RARP (no
    layouts given; both are this standard shape, reached from both
    EtherTypes)."""

    hw_type = bits(16, "Hardware Type", DEC)
    proto_type = bits(16, "Protocol Type", HEX)
    hw_addr_len = bits(8, "Hardware Address Length", DEC)
    proto_addr_len = bits(8, "Protocol Address Length", DEC)
    opcode = bits(16, "Opcode", DEC)


class KangarooParseTree(Parser):
    max_depth = 13

    # "Ethernet and Shim headers can be followed by up to 4 MPLS
    # headers, ARP, RARP, IPv4, or IPv6" - one arm set, built here
    # once so every shim state stays in sync.
    def _after_shim_arms(self) -> dict[ArmKey, Target]:
        return {
            mpls_types(): self.parse_mpls1,
            arp_types(): self.parse_arp_rarp,
            EtherType.IPV4: self.parse_ipv4,
            EtherType.IPV6: self.parse_ipv6,
        }

    # "IPv4/IPv6 is followed by TCP, UDP, GRE, ESP, ICMP, or a second
    # IPv4 header"; the full and *Rest variants carry the same map.
    def _ipv4_arms(self) -> dict[ArmKey, Target]:
        return {
            IpProto.ICMP: self.parse_icmp,
            IpProto.IPIP: self.parse_ipv4_inner,
            IpProto.TCP: self.parse_tcp,
            IpProto.UDP: self.parse_udp,
            IpProto.GRE: self.parse_gre,
            IpProto.ESP: self.parse_ipsec_esp,
        }

    def _ipv6_arms(self) -> dict[ArmKey, Target]:
        return {
            IpProto.HOPOPT: self.parse_ipv6_ext,
            IpProto.ICMP: self.parse_icmp,
            IpProto.IPIP: self.parse_ipv4_inner,
            IpProto.TCP: self.parse_tcp,
            IpProto.UDP: self.parse_udp,
            IpProto.GRE: self.parse_gre,
            IpProto.ESP: self.parse_ipsec_esp,
        }

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                EtherType.VLAN_Q: self.parse_vlan_q1,
                EtherType.RECIRC: self.parse_recirc,
                EtherType.SERVICE: self.parse_service,
                EtherType.VLAN_AH: self.parse_ieee8021ah,
                EtherType.VLAN_AD: self.parse_vlan_ad,
                **self._after_shim_arms(),
            },
            default=accept(),
        )

    def parse_vlan_q1(self) -> State:
        """First 802.1Q tag; "nested 802.1q" is its own shim in the
        prose, so exactly one more 802.1Q may follow."""
        return extract(ShimTag).select(
            ShimTag.ether_type,
            {
                EtherType.VLAN_Q: self.parse_vlan_q2,
                **self._after_shim_arms(),
            },
            default=accept(),
        )

    def parse_vlan_q2(self) -> State:
        """The nested 802.1Q tag; a third is not in the prose's shim
        list and falls to the default."""
        return extract(ShimTag).select(
            ShimTag.ether_type,
            self._after_shim_arms(),
            default=accept(),
        )

    def parse_recirc(self) -> State:
        """Cisco-internal recirculation tag ("resirc" in the paper
        [sic]); reached via a placeholder EtherType."""
        return extract(ShimTag).select(
            ShimTag.ether_type,
            self._after_shim_arms(),
            default=accept(),
        )

    def parse_service(self) -> State:
        """Cisco-internal service tag; placeholder EtherType."""
        return extract(ShimTag).select(
            ShimTag.ether_type,
            self._after_shim_arms(),
            default=accept(),
        )

    def parse_vlan_ad(self) -> State:
        return extract(ShimTag).select(
            ShimTag.ether_type,
            self._after_shim_arms(),
            default=accept(),
        )

    def parse_ieee8021ah(self) -> State:
        return extract(Ieee8021Ah).select(
            Ieee8021Ah.ether_type,
            self._after_shim_arms(),
            default=accept(),
        )

    def parse_mpls1(self) -> State:
        """First of the four bounded MPLS labels ("up to 4 MPLS
        headers"); dispatch mechanism borrowed from the Gibb suite
        (bos select + payload-nibble header)."""
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
        """Fourth label: the bound is exhausted, so bos=0 (a fifth
        label) falls to the default - not a recognized sequence."""
        return extract(Mpls).select(
            Mpls.bos,
            {1: self.parse_mpls_payload},
            default=accept(),
        )

    def parse_mpls_payload(self) -> State:
        """Bottom of stack: "MPLS is followed by Ethernet, IPv4, or
        IPv6". Nibble 0 is the EoMPLS discriminator here (no control
        word in this tree, unlike Gibb - see README)."""
        return lookahead(MplsPayloadNibble).select(
            MplsPayloadNibble.v,
            {
                PayloadNibble.ETHERNET: self.parse_ethernet2,
                PayloadNibble.IPV4: self.parse_ipv4,
                PayloadNibble.IPV6: self.parse_ipv6,
            },
            default=accept(),
        )

    def parse_ethernet2(self) -> State:
        """The inner Ethernet after MPLS - terminal (the prose gives
        it no successors of its own)."""
        return extract(Ethernet, "ethernet2").accept()

    def parse_ipv4(self) -> State:
        """Single-key dispatch on protocol - the prose never mentions
        fragments (unlike the Gibb graphs' (fragOffset, protocol))."""
        return extract(Ipv4).select(
            Ipv4.protocol,
            self._ipv4_arms(),
            default=accept(),
        )

    def parse_ipv6(self) -> State:
        return extract(Ipv6).select(
            Ipv6.next_hdr,
            self._ipv6_arms(),
            default=accept(),
        )

    def parse_ipv6_ext(self) -> State:
        """"an IPv6 extension header which, in turn, is followed by
        TCP, UDP, ESP or ICMPv6" - one level."""
        return extract(Ipv6ExtHdr).select(
            Ipv6ExtHdr.next_hdr,
            {
                IpProto.TCP: self.parse_tcp,
                IpProto.UDP: self.parse_udp,
                IpProto.ESP: self.parse_ipsec_esp,
                IpProto.ICMPV6: self.parse_icmpv6,
            },
            default=accept(),
        )

    def parse_gre(self) -> State:
        """"GRE can also be followed by IPv4/IPv6" - a full inner IP
        header, one tunnel level."""
        return extract(Gre).select(
            Gre.proto,
            {
                EtherType.IPV4: self.parse_ipv4_inner,
                EtherType.IPV6: self.parse_ipv6_inner,
            },
            default=accept(),
        )

    def parse_ipv4_inner(self) -> State:
        """The "second IPv4 header" (and GRE's inner IPv4): one
        tunnel level, so it dispatches L4 only - no further GRE or
        IP-in-IP."""
        return extract(Ipv4).select(
            Ipv4.protocol,
            {
                IpProto.ICMP: self.parse_icmp,
                IpProto.TCP: self.parse_tcp,
                IpProto.UDP: self.parse_udp,
                IpProto.ESP: self.parse_ipsec_esp,
            },
            default=accept(),
        )

    def parse_ipv6_inner(self) -> State:
        """GRE's inner IPv6: L4 only, and no re-entry into the
        extension-header chain (one-level tunnel reading)."""
        return extract(Ipv6).select(
            Ipv6.next_hdr,
            {
                IpProto.ICMP: self.parse_icmp,
                IpProto.TCP: self.parse_tcp,
                IpProto.UDP: self.parse_udp,
                IpProto.ESP: self.parse_ipsec_esp,
            },
            default=accept(),
        )

    def parse_tcp(self) -> State:
        return extract(Tcp).accept()

    def parse_udp(self) -> State:
        return extract(Udp).accept()

    def parse_icmp(self) -> State:
        return extract(Icmp).accept()

    def parse_icmpv6(self) -> State:
        return extract(Icmpv6).accept()

    def parse_ipsec_esp(self) -> State:
        return extract(IpsecEsp).accept()

    def parse_arp_rarp(self) -> State:
        """Terminal - the prose lists ARP/RARP among the possible
        followers but gives them no successors (and no ARP body node,
        unlike the Gibb graphs)."""
        return extract(ArpRarp).accept()


if __name__ == "__main__":
    print(KangarooParseTree.to_json())

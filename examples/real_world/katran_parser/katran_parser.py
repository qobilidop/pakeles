"""A field-for-field model of Katran's default-build XDP parse path.

The third incumbent-agreement example (after `linux_flow_dissector` and
`dpdk_ptype`): the parse graph mirrors facebookincubator/katran's
`balancer.bpf.c` `process_packet` path (pinned commit dd915fd2), whose
parsed `packet_description` (flow tuple + flags + tos) and XDP verdict
are read back from an anchored capture-time observation patch and
compared by the example crate (`examples/real_world/katran_parser/src/lib.rs`) against goldens minted by katran
itself under BPF_PROG_TEST_RUN (`examples/real_world/katran_parser/factory/`).

Design doc: docs/superpowers/specs/2026-07-29-katran-design.md (binding).

Katran is XDP at the NIC, so the parse is bounded and flat — NO VLAN,
NO MPLS, NO IPv6 extension-header walk. Deliberate fidelity, all
harness-verified:

- IPv4 with `ihl != 5` is a hard **reject** (katran XDP_DROP — it does
  not support options), as is any fragment (`MF` set or offset != 0).
  The opposite of the kernel dissector (parses options) and DPDK
  (blind-skips them).
- IPv6: the fixed 40-byte header only; `next_header == Fragment (44)`
  is a hard reject; any non-Fragment, non-ICMPv6, non-TCP/UDP
  next_header is taken as the L4 proto directly and **accepts**
  (XDP_PASS "to the stack") — there is no extension-header parsing.
- ICMP/ICMPv6 echo request accepts (the projection maps it to the
  XDP_TX echo-reply verdict); DEST_UNREACH (v4) / {DEST_UNREACH,
  PKT_TOOBIG} (v6) parse the EMBEDDED inner IP packet (inner v4
  `ihl != 5` rejects), set the `is_icmp` metadata, and the projection
  reads the flow keys from the inner packet with src/dst AND ports
  SWAPPED (katran's error-affinity inversion); any other ICMP type
  accepts (XDP_PASS).
- TCP is the fixed 20 bytes (the projection lifts SYN/RST from the flag
  byte); UDP is 8 bytes; any other L4 proto accepted as XDP_PASS.

Out of scope (the config-gated / non-default-build tail, documented as
a boundary): QUIC (expressible but gated on a vip-map flag — not
packet-pure), IPIP/GUE decap and UDP-stable-routing / TCP-TPR option
routing (non-default #ifdef flavors), and sub-14-byte packets (XDP
TEST_RUN cannot deliver them).
"""

from pakeles import (
    Header,
    LabeledEnum,
    Metadata,
    Parser,
    State,
    accept,
    bits,
    extract,
    metadata_bits,
    oneof,
    reject,
    select,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX, IPV4


class EtherType(LabeledEnum):
    IPV4 = 0x0800, "IPv4"
    ARP = 0x0806
    IPV6 = 0x86DD, "IPv6"


class IPProto(LabeledEnum):
    """Kernel `IPPROTO_*` names; 41 (`IPPROTO_IPV6`) is IPv6-in-IP."""

    ICMP = 1
    IPIP = 4
    TCP = 6
    UDP = 17
    IPV6 = 41, "IPv6-in-IP"
    FRAGMENT = 44
    ICMPV6 = 58, "ICMPv6"


# The labeled slice of IPProto on protocol/next_header fields (FRAGMENT
# is dispatched — a reject arm — but not part of the display set).
_IP_PROTO_LABELS = [
    IPProto.ICMP,
    IPProto.IPIP,
    IPProto.TCP,
    IPProto.UDP,
    IPProto.IPV6,
    IPProto.ICMPV6,
]


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER)
    src = bits(48, "Source", ETHER)
    ethertype = bits(16, "Type", HEX, labels=EtherType)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "Header Length", DEC, doc="katran drops ihl != 5 (no options)")
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC, doc="pkt_bytes, never validated by katran")
    id = bits(16, "Identification", HEX)
    flags_res_df = bits(2, "Reserved/DF", HEX, doc="outside katran's 0x3FFF fragment mask")
    mf_frag_off = bits(14, "MF + Fragment Offset", HEX, doc="katran drops if != 0")
    ttl = bits(8, "Time to Live", DEC)
    protocol = bits(8, "Protocol", DEC, labels=_IP_PROTO_LABELS)
    checksum = bits(16, "Header Checksum", HEX)
    src = bits(32, "Source Address", IPV4)
    dst = bits(32, "Destination Address", IPV4)


inner_ipv4 = IPv4["inner_ipv4"]  # the ICMP-error embedded copy


class IPv6(Header):
    version = bits(4, "Version", DEC)
    traffic_class = bits(8, "Traffic Class", HEX, doc="katran tos = this byte")
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC)
    next_header = bits(8, "Next Header", DEC, labels=_IP_PROTO_LABELS)
    hop_limit = bits(8, "Hop Limit", DEC)
    src = var_bytes(16)
    dst = var_bytes(16)


class ICMP(Header):  # shared by ICMPv4 and ICMPv6 (8-byte base)
    type = bits(8, "Type", DEC)
    code = bits(8, "Code", DEC)
    checksum = bits(16, "Checksum", HEX)
    rest = bits(32, "Rest of Header", HEX)


icmp = ICMP["icmp"]  # one shared instance for both families


class TCP(Header):
    sport = bits(16, "Source Port", DEC)
    dport = bits(16, "Destination Port", DEC)
    seq = bits(32, "Sequence Number", DEC)
    ack = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4, "Data Offset", DEC)
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX, doc="katran lifts SYN (0x02) and RST (0x04)")
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent Pointer", DEC)


class UDP(Header):
    sport = bits(16, "Source Port", DEC)
    dport = bits(16, "Destination Port", DEC)
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class KatranMeta(Metadata):
    is_icmp = metadata_bits(
        1,
        "ICMP inner",
        DEC,
        doc="set on the ICMP error inner-packet path; drives the flow src/dst/port inversion",
    )


class KatranParser(Parser):
    max_depth = 8
    metadata = KatranMeta

    def parse_ethernet(self) -> State:
        """XDP entry: EtherType demux, no VLAN/MPLS. Non-IP (incl. ARP)
        accepts as XDP_PASS without entering the parser."""
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {EtherType.IPV4: self.parse_ipv4, EtherType.IPV6: self.parse_ipv6},
            default=accept(),
        )

    def parse_ipv4(self) -> State:
        """parse_l3_headers v4: ihl != 5 or any fragment -> XDP_DROP."""
        return extract(IPv4).select(
            (IPv4.ihl, IPv4.mf_frag_off),
            {(5, 0): self.parse_ipv4_proto},
            default=reject("ipv4 ihl!=5 or fragmented", info=False),
        )

    def parse_ipv4_proto(self) -> State:
        """Proto dispatch (no extract): ICMP inner, TCP, UDP, else PASS."""
        return select(
            IPv4.protocol,
            {
                IPProto.ICMP: self.parse_icmp,
                IPProto.TCP: self.parse_tcp,
                IPProto.UDP: self.parse_udp,
            },
            default=accept(),
        )

    def parse_ipv6(self) -> State:
        """parse_l3_headers v6: Fragment nexthdr -> DROP; ICMPv6 ->
        inner; no extension-header walk (any other nexthdr is the
        L4 proto). TCP/UDP dispatch, else PASS."""
        return extract(IPv6).select(
            IPv6.next_header,
            {
                IPProto.FRAGMENT: reject("ipv6 fragment", info=False),
                IPProto.ICMPV6: self.parse_icmp6,
                IPProto.TCP: self.parse_tcp,
                IPProto.UDP: self.parse_udp,
            },
            default=accept(),
        )

    def parse_icmp(self) -> State:
        """parse_icmp (v4): echo (8) accepts [-> XDP_TX]; DEST_UNREACH
        (3) parses the inner packet; any other type accepts [PASS]."""
        return extract(icmp).select(
            icmp.type,
            {3: self.parse_inner_ipv4},
            default=accept(),
        )

    def parse_icmp6(self) -> State:
        """parse_icmpv6: echo (128) accepts [TX]; DEST_UNREACH (1) /
        PKT_TOOBIG (2) parse inner; else PASS."""
        return extract(icmp).select(
            icmp.type,
            {oneof(1, 2): self.parse_inner_ipv6},
            default=accept(),
        )

    def parse_inner_ipv4(self) -> State:
        """Inner v4 (ICMP error payload): ihl != 5 -> DROP; no frag
        check (katran's parse_icmp doesn't). is_icmp marks the
        inversion for the projection."""
        return (
            extract(inner_ipv4)
            .assign(KatranMeta.is_icmp, 1)
            .select(
                inner_ipv4.ihl,
                {5: self.parse_inner_ipv4_proto},
                default=reject("inner ipv4 ihl!=5", info=False),
            )
        )

    def parse_inner_ipv4_proto(self) -> State:
        return select(
            inner_ipv4.protocol,
            {IPProto.TCP: self.parse_tcp, IPProto.UDP: self.parse_udp},
            default=accept(),
        )

    def parse_inner_ipv6(self) -> State:
        """Inner v6: nexthdr taken directly (no frag/ext check in
        parse_icmpv6). TCP/UDP else PASS. Reuses the `ipv6` instance
        (its 128-bit addresses are var_bytes, which the IR cannot carry
        under two instance names); the projection reads the LAST ipv6
        under `is_icmp`, so the inner addresses win on the ICMP path
        exactly as katran records them."""
        return (
            extract(IPv6)
            .assign(KatranMeta.is_icmp, 1)
            .select(
                IPv6.next_header,
                {IPProto.TCP: self.parse_tcp, IPProto.UDP: self.parse_udp},
                default=accept(),
            )
        )

    def parse_tcp(self) -> State:
        """Shared L4 terminal (outer or inner): the projection lifts
        ports (swapped under is_icmp) and TCP SYN/RST flags."""
        return extract(TCP).accept()

    def parse_udp(self) -> State:
        return extract(UDP).accept()


if __name__ == "__main__":
    print(KatranParser.to_json())

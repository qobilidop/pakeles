"""Gibb et al.'s "Edge" parse graph (ANCS 2013, Fig. 3c).

Ethernet, MPLS(x2) with the pseudo-wire first-nibble lookahead,
EoMPLS to an inner Ethernet, and terminal IPv4/IPv6 (no VLAN and no
L4 dispatch in this graph). Transcribed from Gibb, Varghese, Horowitz
& McKeown, "Design Principles for Packet Parsers" (ANCS 2013) - see
this example's README for the source citation, the graph's aliases in
the corpus, and every transcription choice (most notably the
nibble-split modeling of the source's MPLS pseudo-field).

Suite-wide transcription semantics (shared by all gibb_* examples):
unmatched dispatch ends the recognized sequence (`default=accept()` -
these graphs classify, they do not validate); bounded repetition
(MPLS <= 2 here) is unrolled into states, exactly as the paper draws
it; IPv4 options are `var_bytes(ihl*4 - 20)`, where sub-5 length
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
    """The dispatch values this graph recognizes (both MPLS
    EtherTypes map to the one MPLS node)."""

    MPLS_UC = 0x8847, "MPLS (unicast)"
    MPLS_MC = 0x8848, "MPLS (multicast)"
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"


class PayloadNibble(LabeledEnum):
    """The first four bits after the bottom-of-stack MPLS label - the
    source's 4-bit `next-header` pseudo-field."""

    EOMPLS = 0, "Ethernet-over-MPLS"
    IPV4 = 4, "IPv4"
    IPV6 = 6, "IPv6"


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Mpls(Header):
    label = bits(20, "Label", DEC)
    tc = bits(3, "Traffic Class")
    bos = bits(1, "Bottom of Stack")
    ttl = bits(8, "TTL", DEC)


class MplsPayloadNibble(Header):
    """The source's decision-only pseudo-field, carried as a real
    4-bit header; the `*Rest` continuations below are defined minus
    these four bits, so the split is bit-for-bit faithful."""

    v = bits(4, "First Nibble", DEC, labels=PayloadNibble)


class Ipv4(Header):
    """Full header - the direct (non-MPLS) entry from Ethernet.
    Terminal: this graph has no IP `next_header` map at all."""

    version = bits(4, "Version")
    ihl = bits(4, "IHL", DEC)
    diffserv = bits(8, "DiffServ", HEX)
    total_len = bits(16, "Total Length", DEC)
    identification = bits(16, "Identification", HEX)
    flags = bits(3, "Flags")
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "TTL", DEC)
    protocol = bits(8, "Protocol", DEC)
    hdr_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", HEX)
    dst_addr = bits(32, "Destination", HEX)
    options = var_bytes(ihl * 4 - 20)


class Ipv4Rest(Header):
    """`Ipv4` minus its leading 4-bit version field, which the
    nibble state has already consumed."""

    ihl = bits(4, "IHL", DEC)
    diffserv = bits(8, "DiffServ", HEX)
    total_len = bits(16, "Total Length", DEC)
    identification = bits(16, "Identification", HEX)
    flags = bits(3, "Flags")
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "TTL", DEC)
    protocol = bits(8, "Protocol", DEC)
    hdr_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", HEX)
    dst_addr = bits(32, "Destination", HEX)
    options = var_bytes(ihl * 4 - 20)


class Ipv6(Header):
    """Full header - the direct (non-MPLS) entry from Ethernet.
    Terminal, fixed 40 bytes."""

    version = bits(4, "Version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC)
    hop_limit = bits(8, "Hop Limit", DEC)
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class Ipv6Rest(Header):
    """`Ipv6` minus its leading 4-bit version field, which the
    nibble state has already consumed."""

    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC)
    hop_limit = bits(8, "Hop Limit", DEC)
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class EomplsRest(Header):
    """The source's `eompls` control word minus its leading `zero`
    nibble, which the nibble state has already consumed."""

    reserved = bits(12, "Reserved")
    seq_no = bits(16, "Sequence Number", DEC)


class GibbEdge(Parser):
    max_depth = 7

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                oneof(EtherType.MPLS_UC, EtherType.MPLS_MC): self.parse_mpls1,
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
            },
            default=accept(),
        )

    def parse_mpls1(self) -> State:
        """First of the two bounded MPLS labels (`max = 2` in the
        source). The source's `map(bos, next-header)` peeks a 4-bit
        pseudo-field from the NEXT header; transcribed by dispatching
        on `bos` alone - bos=0 continues the stack with nothing else
        consumed, bos=1 hands off to the nibble state."""
        return extract(Mpls).select(
            Mpls.bos,
            {
                0: self.parse_mpls2,
                1: self.parse_payload_nibble,
            },
            default=accept(),
        )

    def parse_mpls2(self) -> State:
        """Second MPLS label; a third (bos=0) falls to the default -
        beyond the graph's bound is simply not a recognized
        sequence."""
        return extract(Mpls).select(
            Mpls.bos,
            {1: self.parse_payload_nibble},
            default=accept(),
        )

    def parse_payload_nibble(self) -> State:
        """One shared state for both MPLS depths: extract the first
        nibble of the payload, then continue with the matching
        `*Rest` header (b10000/b10100/b10110 in the source's map)."""
        return extract(MplsPayloadNibble).select(
            MplsPayloadNibble.v,
            {
                PayloadNibble.EOMPLS: self.parse_eompls_rest,
                PayloadNibble.IPV4: self.parse_ipv4_rest,
                PayloadNibble.IPV6: self.parse_ipv6_rest,
            },
            default=accept(),
        )

    def parse_ipv4(self) -> State:
        return extract(Ipv4).accept()

    def parse_ipv4_rest(self) -> State:
        return extract(Ipv4Rest).accept()

    def parse_ipv6(self) -> State:
        return extract(Ipv6).accept()

    def parse_ipv6_rest(self) -> State:
        return extract(Ipv6Rest).accept()

    def parse_eompls_rest(self) -> State:
        return extract(EomplsRest).then(self.parse_ethernet2)

    def parse_ethernet2(self) -> State:
        """The source's `ethernet2`: the inner (pseudo-wire) Ethernet
        header, terminal. Same layout as `Ethernet` - reused as a
        second instance."""
        return extract(Ethernet, "ethernet2").accept()


if __name__ == "__main__":
    print(GibbEdge.to_json())

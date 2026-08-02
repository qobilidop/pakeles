"""Gibb et al.'s "Service provider" parse graph: Ethernet, MPLS(x5), IPv4, IPv6.

Transcribed from Fig. 3d of Gibb, Varghese, Horowitz & McKeown,
"Design Principles for Packet Parsers" (ANCS 2013), fixed-parser
variant (the artifact's `-prog` twin is a README note, not a member).

Suite-wide transcription semantics (shared by all gibb_* examples):
unmatched dispatch ends the recognized sequence (`default=accept()` -
these graphs classify, they do not validate); bounded repetition
(MPLS <= 5 here) is unrolled into states; IPv4 options are
`var_bytes(ihl*4 - 20)`.

This graph introduces the suite's MPLS lookahead pattern: the source
dispatches MPLS on (bos, 4-bit pseudo-field), where the pseudo-field
is the NEXT header's first nibble, used in decision only. Transcribed
by splitting the decision: each MPLS state selects on `bos` alone
(bos=0 -> next label state), and only on bos=1 is the nibble read —
with `lookahead()`, which binds it for the select WITHOUT consuming
it, so the continuations extract the real full `Ipv4`/`Ipv6` headers
over those same bits. That is the source's "decision only" verbatim.
"""

from pakeles import (
    Header,
    LabeledEnum,
    Parser,
    State,
    accept,
    bits,
    extract,
    lookahead,
    oneof,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX


class EtherType(LabeledEnum):
    MPLS_UC = 0x8847, "MPLS (unicast)"
    MPLS_MC = 0x8848, "MPLS (multicast)"
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"


class PayloadNibble(LabeledEnum):
    """First nibble of the MPLS payload (the source's 4-bit
    pseudo-field): an IP version number."""

    IPV4 = 4, "IPv4"
    IPV6 = 6, "IPv6"


def mpls_types():  # a fresh OneOf per select arm
    return oneof(EtherType.MPLS_UC, EtherType.MPLS_MC)


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Mpls(Header):
    label = bits(20, "Label", DEC)
    tc = bits(3, "Traffic Class")
    bos = bits(1, "Bottom of Stack", DEC)
    ttl = bits(8, "TTL", DEC)


class MplsPayloadNibble(Header):
    """The source's decision-only pseudo-field, extracted as a real
    4-bit header once the label stack bottoms out."""

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
    protocol = bits(8, "Protocol", DEC)
    hdr_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", HEX)
    dst_addr = bits(32, "Destination", HEX)
    options = var_bytes(ihl * 4 - 20)


class Ipv6(Header):
    version = bits(4, "Version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC)
    hop_limit = bits(8, "Hop Limit", DEC)
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class GibbServiceProvider(Parser):
    max_depth = 9

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                mpls_types(): self.parse_mpls1,
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
            },
            default=accept(),
        )

    def parse_mpls1(self) -> State:
        """First of the five bounded MPLS labels (`max = 5` in the
        source)."""
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
        here as a real header. This graph maps only 4/6 (no EoMPLS arm,
        unlike big-union); other nibbles end the sequence."""
        return lookahead(MplsPayloadNibble).select(
            MplsPayloadNibble.v,
            {
                PayloadNibble.IPV4: self.parse_ipv4,
                PayloadNibble.IPV6: self.parse_ipv6,
            },
            default=accept(),
        )

    def parse_ipv4(self) -> State:
        """Terminal - this graph has no L4 dispatch."""
        return extract(Ipv4).accept()

    def parse_ipv6(self) -> State:
        return extract(Ipv6).accept()


if __name__ == "__main__":
    print(GibbServiceProvider.to_json())

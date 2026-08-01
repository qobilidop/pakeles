"""A field-for-field model of the DASH BMv2 pipeline parser.

The seventh incumbent-agreement example: the parse graph mirrors
sonic-net/DASH `dash-pipeline/bmv2/dash_parser.p4` (pinned commit
d5c003dd7774) — the packet parser of Microsoft's Azure SmartNIC
data-plane pipeline — whose per-packet verdict (header-validity
bitmap, parser-error code, key parsed fields) is read back from the
instrumented incumbent run on `simple_switch` and compared by the
example crate (`examples/real_world/dash_parser/src/lib.rs`).

Two-layer structure straight from the source: u0 (underlay) Ethernet →
{IPv4 (IHL ladder incl. an options varbit), IPv6, the DASH
packet-metadata sentinel EtherType 0x876d} → u0 L4; a u0 UDP to
dst_port 4789 opens VXLAN and the customer (overlay) layer — customer
Ethernet → customer IPv4/IPv6 → customer TCP/UDP. Header instance
names are the source's `headers_t` member names verbatim.

Transcription choices (each mirrors the source exactly; see the
README's quirk catalog):

- The source's `start` extracts `u0_ethernet` (after pre-setting
  `packet_meta` valid with defaults); `start` is a reserved eDSL
  attribute, so the entry state is `parse_u0_ethernet` and the
  always-valid `packet_meta` default lives in the projection
  (src/lib.rs), not the parse graph.
- `verify()` calls become explicit select-to-reject chains, in source
  order (version before IHL), with the reject reason = the source's
  error name; the example projects those reasons onto the incumbent's
  `standard_metadata.parser_error` codes. Unlike the classify-only
  academic graphs, the rejects are the model — the incumbent really
  rejects.
- `parse_dash_hdr`'s statement-level `if` cascade (P4 parser
  conditionals) becomes select states: the subtype demux routes
  CREATE/UPDATE/DELETE through `flow_key`, DELETE on to `flow_data`,
  and the `flow_data.actions` bit tests (`!= 0`, `& ENCAP_U0`,
  `& ENCAP_U1`, where `dash_routing_actions_t` is upstream's typedef
  of `dash_flow_action_t`) become one first-match select with masked
  arms over the same truth table.
- 128-bit IPv6 addresses are hi/lo 64-bit halves: IR fixed fields cap
  at 64 bits, and `ipv6_t` is extracted under two instances, which
  rules out the `var_bytes(16)` spelling (single-instance-only for
  var-width header types). Single-instance 128-bit fields (flow_key,
  flow_overlay_data) do use `var_bytes(16)`.
- `u0_ipv4options` sizes its varbit exactly as the source:
  `(ihl - 5) * 4` bytes (the source writes `((ihl - 5) * 32)` bits),
  reached only for ihl > 5, so the subtraction never underflows.
"""

from pakeles import (
    Header,
    LabeledEnum,
    Parser,
    State,
    accept,
    bits,
    extract,
    masked,
    oneof,
    reject,
    select,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX, IPV4

# Wire vocabularies (the #define / enum slices dash_parser.p4 touches).


class EtherType(LabeledEnum):
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"
    DASH = 0x876D, "DASH packet metadata"


class IPProto(LabeledEnum):
    TCP = 6
    UDP = 17


class L4Port(LabeledEnum):
    VXLAN = 4789, "VXLAN"


class PacketSource(LabeledEnum):
    """`dash_packet_source_t` (set by the pipeline, not the demux)."""

    EXTERNAL = 0
    PIPELINE = 1
    DPAPP = 2
    PEER = 3


class PacketType(LabeledEnum):
    """`dash_packet_type_t` — carried but IGNORED by the parser's
    demux, which keys on packet_subtype only (a README quirk)."""

    REGULAR = 0
    FLOW_SYNC_REQ = 1
    FLOW_SYNC_ACK = 2
    DP_PROBE_REQ = 3
    DP_PROBE_ACK = 4


class PacketSubtype(LabeledEnum):
    """`dash_packet_subtype_t` — the parse_dash_hdr demux key."""

    NONE = 0
    FLOW_CREATE = 1
    FLOW_UPDATE = 2
    FLOW_DELETE = 3


class Encapsulation(LabeledEnum):
    """`dash_encapsulation_t` (encap_data_t's last field)."""

    INVALID = 0
    VXLAN = 1
    NVGRE = 2


# dash_flow_action_t bits the parser tests (via upstream's
# `typedef dash_flow_action_t dash_routing_actions_t`).
ACTION_ENCAP_U0 = 1 << 0
ACTION_ENCAP_U1 = 1 << 1


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "IHL", DEC)
    diffserv = bits(8, "Diffserv", HEX)
    total_len = bits(16, "Total Length", DEC)
    identification = bits(16, "Identification", HEX)
    flags = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "TTL", DEC)
    protocol = bits(8, "Protocol", DEC, labels=IPProto)
    hdr_checksum = bits(16, "Header Checksum", HEX)
    src_addr = bits(32, "Source", IPV4)
    dst_addr = bits(32, "Destination", IPV4)


class IPv4Options(Header, name="ipv4options"):
    """`ipv4options_t`: one varbit, sized by the enclosing IPv4's IHL
    exactly as the source extracts it — reached only when ihl > 5."""

    options = var_bytes((IPv4["u0_ipv4"].ihl - 5) * 4)


class IPv6(Header):
    version = bits(4, "Version", DEC)
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC)
    next_header = bits(8, "Next Header", DEC, labels=IPProto)
    hop_limit = bits(8, "Hop Limit", DEC)
    src_addr_hi = bits(64, "Source (hi)", HEX)
    src_addr_lo = bits(64, "Source (lo)", HEX)
    dst_addr_hi = bits(64, "Destination (hi)", HEX)
    dst_addr_lo = bits(64, "Destination (lo)", HEX)


class UDP(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC, labels=L4Port)
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class TCP(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    seq_no = bits(32, "Sequence", DEC)
    ack_no = bits(32, "Acknowledgment", DEC)
    data_offset = bits(4, "Data Offset", DEC)
    res = bits(3, "Reserved", HEX)
    ecn = bits(3, "ECN", HEX)
    flags = bits(6, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent_ptr = bits(16, "Urgent Pointer", DEC)


class VXLAN(Header):
    flags = bits(8, "Flags", HEX)
    reserved = bits(24, "Reserved", HEX)
    vni = bits(24, "VNI", DEC)
    reserved_2 = bits(8, "Reserved 2", HEX)


class DashPacketMeta(Header):
    """`dash_packet_meta_t`, on the wire after EtherType 0x876d. The
    source's `start` also pre-sets this instance valid with defaults
    on EVERY packet — that lives in the projection, not here."""

    packet_source = bits(8, "Packet Source", DEC, labels=PacketSource)
    packet_type = bits(4, "Packet Type", DEC, labels=PacketType)
    packet_subtype = bits(4, "Packet Subtype", DEC, labels=PacketSubtype)
    length = bits(16, "Length", DEC)


class FlowKey(Header):
    eni_mac = bits(48, "ENI MAC", ETHER)
    vnet_id = bits(16, "VNet ID", DEC)
    src_ip = var_bytes(16)
    dst_ip = var_bytes(16)
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    ip_proto = bits(8, "IP Protocol", DEC)
    reserved = bits(7, "Reserved", HEX)
    is_ip_v6 = bits(1, "Is IPv6", DEC)


class FlowData(Header):
    reserved = bits(7, "Reserved", HEX)
    is_unidirectional = bits(1, "Is Unidirectional", DEC)
    direction = bits(16, "Direction", DEC)
    version = bits(32, "Version", DEC)
    actions = bits(32, "Actions", HEX, doc="dash_flow_action_t bitmask")
    meter_class = bits(32, "Meter Class", DEC)
    idle_timeout_in_ms = bits(32, "Idle Timeout (ms)", DEC)


class OverlayRewriteData(Header):
    dmac = bits(48, "DMAC", ETHER)
    sip = var_bytes(16)
    dip = var_bytes(16)
    sip_mask = var_bytes(16)
    dip_mask = var_bytes(16)
    sport = bits(16, "Source Port", DEC)
    dport = bits(16, "Destination Port", DEC)
    reserved = bits(7, "Reserved", HEX)
    is_ipv6 = bits(1, "Is IPv6", DEC)


class EncapData(Header):
    vni = bits(24, "VNI", DEC)
    reserved = bits(8, "Reserved", HEX)
    underlay_sip = bits(32, "Underlay Source", IPV4)
    underlay_dip = bits(32, "Underlay Destination", IPV4)
    underlay_smac = bits(48, "Underlay SMAC", ETHER)
    underlay_dmac = bits(48, "Underlay DMAC", ETHER)
    dash_encapsulation = bits(16, "Encapsulation", DEC, labels=Encapsulation)


# The source's headers_t instance names, verbatim.
U0_ETHERNET = Ethernet["u0_ethernet"]
U0_IPV4 = IPv4["u0_ipv4"]
U0_IPV4OPTIONS = IPv4Options["u0_ipv4options"]
U0_IPV6 = IPv6["u0_ipv6"]
U0_UDP = UDP["u0_udp"]
U0_TCP = TCP["u0_tcp"]
U0_VXLAN = VXLAN["u0_vxlan"]
PACKET_META = DashPacketMeta["packet_meta"]
FLOW_OVERLAY_DATA = OverlayRewriteData["flow_overlay_data"]
FLOW_U0_ENCAP_DATA = EncapData["flow_u0_encap_data"]
FLOW_U1_ENCAP_DATA = EncapData["flow_u1_encap_data"]
CUSTOMER_ETHERNET = Ethernet["customer_ethernet"]
CUSTOMER_IPV4 = IPv4["customer_ipv4"]
CUSTOMER_IPV6 = IPv6["customer_ipv6"]
CUSTOMER_UDP = UDP["customer_udp"]
CUSTOMER_TCP = TCP["customer_tcp"]


class DashParser(Parser):
    # Deepest path (12 states: u0 eth -> IPv4 -> IHL -> options ->
    # protocol dispatch -> UDP -> VXLAN -> customer eth -> customer
    # IPv4 -> IHL -> protocol dispatch -> customer L4) + 1.
    max_depth = 13

    def parse_u0_ethernet(self) -> State:
        """The source's `start` state (the eDSL reserves that name):
        u0 EtherType demux, incl. the DASH packet-metadata sentinel
        0x876d; every miss accepts."""
        return extract(U0_ETHERNET).select(
            U0_ETHERNET.ether_type,
            {
                EtherType.IPV4: self.parse_u0_ipv4,
                EtherType.IPV6: self.parse_u0_ipv6,
                EtherType.DASH: self.parse_dash_hdr,
            },
            default=accept(),
        )

    def parse_dash_hdr(self) -> State:
        """The wire packet_meta overwrites start's defaults; the
        subtype demux routes FLOW_{CREATE,UPDATE,DELETE} through
        flow_key (the source's first parser `if`), everything else
        straight to the customer layer."""
        return extract(PACKET_META).select(
            PACKET_META.packet_subtype,
            {
                oneof(
                    PacketSubtype.FLOW_CREATE,
                    PacketSubtype.FLOW_UPDATE,
                    PacketSubtype.FLOW_DELETE,
                ): self.parse_flow_key,
            },
            default=self.parse_customer_ethernet,
        )

    def parse_flow_key(self) -> State:
        """CREATE/UPDATE stop at the key; DELETE carries flow_data
        (the source's second parser `if`, re-keyed on the already-
        extracted subtype)."""
        return extract(FlowKey).select(
            PACKET_META.packet_subtype,
            {PacketSubtype.FLOW_DELETE: self.parse_flow_data},
            default=self.parse_customer_ethernet,
        )

    def parse_flow_data(self) -> State:
        """The DELETE `if` cascade over flow_data.actions as one
        first-match select: actions == 0 -> nothing extra; otherwise
        flow_overlay_data always, plus the encap header per ENCAP_U0/
        ENCAP_U1 bit (masked arms over the low two bits)."""
        return extract(FlowData).select(
            FlowData.actions,
            {
                0: self.parse_customer_ethernet,
                masked(
                    ACTION_ENCAP_U0 | ACTION_ENCAP_U1,
                    ACTION_ENCAP_U0 | ACTION_ENCAP_U1,
                ): self.parse_flow_encap_u0_u1,
                masked(
                    ACTION_ENCAP_U0, ACTION_ENCAP_U0 | ACTION_ENCAP_U1
                ): self.parse_flow_encap_u0,
                masked(
                    ACTION_ENCAP_U1, ACTION_ENCAP_U0 | ACTION_ENCAP_U1
                ): self.parse_flow_encap_u1,
            },
            default=self.parse_flow_overlay_data,
        )

    def parse_flow_overlay_data(self) -> State:
        """actions != 0 with neither encap bit: overlay data only."""
        return extract(FLOW_OVERLAY_DATA).then(self.parse_customer_ethernet)

    def parse_flow_encap_u0(self) -> State:
        return (
            extract(FLOW_OVERLAY_DATA)
            .extract(FLOW_U0_ENCAP_DATA)
            .then(self.parse_customer_ethernet)
        )

    def parse_flow_encap_u1(self) -> State:
        return (
            extract(FLOW_OVERLAY_DATA)
            .extract(FLOW_U1_ENCAP_DATA)
            .then(self.parse_customer_ethernet)
        )

    def parse_flow_encap_u0_u1(self) -> State:
        return (
            extract(FLOW_OVERLAY_DATA)
            .extract(FLOW_U0_ENCAP_DATA)
            .extract(FLOW_U1_ENCAP_DATA)
            .then(self.parse_customer_ethernet)
        )

    def parse_u0_ipv4(self) -> State:
        """verify(version == 4, IPv4IncorrectVersion) — the source
        checks version before IHL, so a bad version wins."""
        return extract(U0_IPV4).select(
            U0_IPV4.version,
            {4: self.parse_u0_ipv4_ihl},
            default=reject("IPv4IncorrectVersion"),
        )

    def parse_u0_ipv4_ihl(self) -> State:
        """verify(ihl >= 5, InvalidIPv4Header), then the source's IHL
        select: 5 -> dispatch, > 5 -> the options varbit."""
        return select(
            U0_IPV4.ihl,
            {
                range(5): reject("InvalidIPv4Header"),
                5: self.dispatch_on_u0_protocol,
            },
            default=self.parse_u0_ipv4options,
        )

    def parse_u0_ipv4options(self) -> State:
        return extract(U0_IPV4OPTIONS).then(self.dispatch_on_u0_protocol)

    def dispatch_on_u0_protocol(self) -> State:
        """The source's own dispatch state (shared by the ihl=5 and
        options paths); a protocol miss accepts."""
        return select(
            U0_IPV4.protocol,
            {IPProto.UDP: self.parse_u0_udp, IPProto.TCP: self.parse_u0_tcp},
            default=accept(),
        )

    def parse_u0_ipv6(self) -> State:
        """next_header straight to L4 — no extension-header walk."""
        return extract(U0_IPV6).select(
            U0_IPV6.next_header,
            {IPProto.UDP: self.parse_u0_udp, IPProto.TCP: self.parse_u0_tcp},
            default=accept(),
        )

    def parse_u0_udp(self) -> State:
        """dst_port 4789 opens VXLAN — on UDP only (TCP port 4789
        stays plain TCP), and only at the u0 layer."""
        return extract(U0_UDP).select(
            U0_UDP.dst_port,
            {L4Port.VXLAN: self.parse_u0_vxlan},
            default=accept(),
        )

    def parse_u0_tcp(self) -> State:
        return extract(U0_TCP).accept()

    def parse_u0_vxlan(self) -> State:
        return extract(U0_VXLAN).then(self.parse_customer_ethernet)

    def parse_customer_ethernet(self) -> State:
        """The customer layer has no DASH-sentinel and no VXLAN arm:
        0x876d or a nested encap inside the overlay just accepts."""
        return extract(CUSTOMER_ETHERNET).select(
            CUSTOMER_ETHERNET.ether_type,
            {
                EtherType.IPV4: self.parse_customer_ipv4,
                EtherType.IPV6: self.parse_customer_ipv6,
            },
            default=accept(),
        )

    def parse_customer_ipv4(self) -> State:
        return extract(CUSTOMER_IPV4).select(
            CUSTOMER_IPV4.version,
            {4: self.parse_customer_ipv4_ihl},
            default=reject("IPv4IncorrectVersion"),
        )

    def parse_customer_ipv4_ihl(self) -> State:
        """verify(ihl == 5, IPv4OptionsNotSupported): the customer
        layer refuses options outright (unlike u0's varbit)."""
        return select(
            CUSTOMER_IPV4.ihl,
            {5: self.dispatch_on_customer_protocol},
            default=reject("IPv4OptionsNotSupported"),
        )

    def dispatch_on_customer_protocol(self) -> State:
        return select(
            CUSTOMER_IPV4.protocol,
            {
                IPProto.UDP: self.parse_customer_udp,
                IPProto.TCP: self.parse_customer_tcp,
            },
            default=accept(),
        )

    def parse_customer_ipv6(self) -> State:
        return extract(CUSTOMER_IPV6).select(
            CUSTOMER_IPV6.next_header,
            {
                IPProto.UDP: self.parse_customer_udp,
                IPProto.TCP: self.parse_customer_tcp,
            },
            default=accept(),
        )

    def parse_customer_udp(self) -> State:
        return extract(CUSTOMER_UDP).accept()

    def parse_customer_tcp(self) -> State:
        return extract(CUSTOMER_TCP).accept()


if __name__ == "__main__":
    print(DashParser.to_json())

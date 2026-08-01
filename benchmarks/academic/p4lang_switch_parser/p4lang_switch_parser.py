"""The parser of classic switch.p4, the most-cited P4 program.

Transcribed from `p4src/includes/parser.p4` + `headers.p4` of
`p4lang/switch` @ 7874f565 (the repo's final commit, 2020-10-29),
preprocessed with the SHIPPED feature defaults (`p4features.h`
untouched: FABRIC_ENABLE, INT_EP_ENABLE + INT_TRANSIT_ENABLE,
SFLOW_ENABLE all on; ADV_FEATURES off) plus `__TARGET_BMV2__`. That
configuration yields 63 parser states over 57 header types and 56
header instances, including the stacks `vlan_tag_[2]`, `mpls[3]` and
`int_val[24]`.

Transcription shape (every choice detailed in README.md):

- The source's `start` state is a bare `return parse_ethernet`;
  `start` is a reserved attribute of the eDSL `Parser` class (the
  start-override hook), so the entry is `parse_ethernet` directly.
- `mpls[3]` is unrolled into three states over one `mpls` instance
  (`parse_mpls`, `parse_mpls_2`, `parse_mpls_3` — the latter two
  names are unroll-invented); `int_val[24]` stays ONE cyclic state,
  bounded by `max_depth`, not by 24.
- The two `current(0, 4)` sites (`parse_mpls_bos`, `parse_lisp`) are
  `lookahead()` of a 4-bit `IpVersionNibble` — the IR's peek, 1:1
  with the source; their continuations extract the real full inner
  types over the peeked bits.
- `ingress` (the match-action control) and the source's
  metadata-only terminal states end parsing: `accept()`. All
  `set_metadata` statements are dropped — parse-time lookup-field
  copies, tunnel-type codes and priorities are match-action
  interface state, not parse structure.
- Several states are unreachable under the shipped defaults (their
  entry arms are compiled out by feature flags) but remain in the
  source and are transcribed: parse_roce, parse_fcoe, parse_roce_v2,
  parse_sctp, parse_inner_sctp, parse_udp_v6, parse_gre_v6,
  parse_vpls, parse_pw, parse_nsh, parse_lisp, parse_trill,
  parse_vntag, parse_bfd.
"""

from pakeles import (
    ArmKey,
    FieldSpec,
    Header,
    LabeledEnum,
    Parser,
    State,
    Target,
    accept,
    bits,
    extract,
    goto,
    lookahead,
    masked,
    reject,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX


class EtherType(LabeledEnum):
    """The EtherType slice this configuration dispatches on (member
    names follow the source's ETHERTYPE_* defines; ETHERNET is the
    source's name for 0x6558, Transparent Ethernet Bridging)."""

    BF_FABRIC = 0x9000, "internal fabric header (source: BF_FABRIC)"
    VLAN = 0x8100, "802.1Q"
    QINQ = 0x9100, "QinQ (legacy 0x9100)"
    MPLS = 0x8847, "MPLS (unicast)"
    IPV4 = 0x0800, "IPv4"
    IPV6 = 0x86DD, "IPv6"
    ARP = 0x0806, "ARP"
    LLDP = 0x88CC, "LLDP"
    LACP = 0x8809, "Slow Protocols (source: LACP)"
    ETHERNET = 0x6558, "Transparent Ethernet Bridging"
    ERSPAN_T3 = 0x22EB, "ERSPAN type III"


class IpProto(LabeledEnum):
    """IP protocol numbers (the source's IP_PROTOCOLS_* defines)."""

    ICMP = 1
    IGMP = 2
    IPV4 = 4, "IPv4-in-IP"
    TCP = 6
    UDP = 17
    IPV6 = 41, "IPv6-in-IP"
    GRE = 47
    ICMPV6 = 58, "ICMPv6"
    EIGRP = 88
    OSPF = 89
    PIM = 103
    VRRP = 112


class UdpPort(LabeledEnum):
    """UDP destination ports (the source's UDP_PORT_* defines)."""

    BOOTPS = 67, "DHCP (server)"
    BOOTPC = 68, "DHCP (client)"
    RIP = 520
    RIPNG = 521, "RIPng"
    DHCPV6_CLIENT = 546, "DHCPv6 (client)"
    DHCPV6_SERVER = 547, "DHCPv6 (server)"
    HSRP = 1985
    VXLAN = 4789
    VXLAN_GPE = 4790, "VXLAN-GPE"
    GENV = 6081, "Geneve"
    SFLOW = 6343, "sFlow"


class TcpPort(LabeledEnum):
    """TCP destination ports (the source's TCP_PORT_* defines)."""

    BGP = 179
    MSDP = 639


class FabricPacketType(LabeledEnum):
    """fabric_header.packetType (FABRIC_HEADER_TYPE_*; CONTROL=4 is
    defined by the source but never dispatched)."""

    UNICAST = 1
    MULTICAST = 2
    MIRROR = 3
    CPU = 5


class CpuReason(LabeledEnum):
    """fabric_header_cpu.reasonCode values the parser dispatches on
    (the source's CPU_REASON_CODE_SFLOW)."""

    SFLOW = 0x4, "sFlow sample"


class IpVersion(LabeledEnum):
    """The `current(0, 4)` lookahead vocabulary: an IP version
    nibble."""

    IPV4 = 4, "IPv4"
    IPV6 = 6, "IPv6"


# --- header types (source: headers.p4; camelCase snake-cased) ---


class Ethernet(Header):
    dst_addr = bits(48, "Destination", ETHER)
    src_addr = bits(48, "Source", ETHER)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class LlcHeader(Header):
    dsap = bits(8, "DSAP", HEX)
    ssap = bits(8, "SSAP", HEX)
    control_ = bits(8, "Control", HEX)


class SnapHeader(Header):
    oui = bits(24, "OUI", HEX)
    type_ = bits(16, "Type", HEX, labels=EtherType)


class RoceHeader(Header):
    """The source's 320-bit ib_grh and 96-bit ib_bth exceed the
    fixed-`bits` ceiling (64). The `var_bytes` idiom needs a
    statically known byte alignment at the extract site, which this
    unreachable state does not have — so they are carried as fixed
    64/32-bit words instead."""

    ib_grh_0 = bits(64, "IB GRH (bits 0-63)", HEX)
    ib_grh_1 = bits(64, "IB GRH (bits 64-127)", HEX)
    ib_grh_2 = bits(64, "IB GRH (bits 128-191)", HEX)
    ib_grh_3 = bits(64, "IB GRH (bits 192-255)", HEX)
    ib_grh_4 = bits(64, "IB GRH (bits 256-319)", HEX)
    ib_bth_0 = bits(64, "IB BTH (bits 0-63)", HEX)
    ib_bth_1 = bits(32, "IB BTH (bits 64-95)", HEX)


class RoceV2Header(Header):
    """See `RoceHeader` for the 96-bit ib_bth word split."""

    ib_bth_0 = bits(64, "IB BTH (bits 0-63)", HEX)
    ib_bth_1 = bits(32, "IB BTH (bits 64-95)", HEX)


class FcoeHeader(Header):
    version = bits(4, "Version")
    type_ = bits(4, "Type")
    sof = bits(8, "SOF", HEX)
    rsvd1 = bits(32, "Reserved")
    ts_upper = bits(32, "Timestamp (upper)", DEC)
    ts_lower = bits(32, "Timestamp (lower)", DEC)
    size_ = bits(32, "Size", DEC)
    eof = bits(8, "EOF", HEX)
    rsvd2 = bits(24, "Reserved")


class VlanTag(Header):
    pcp = bits(3, "PCP")
    cfi = bits(1, "CFI")
    vid = bits(12, "VLAN ID", DEC)
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class Mpls(Header):
    label = bits(20, "Label", DEC)
    exp = bits(3, "EXP")
    bos = bits(1, "Bottom of Stack", DEC)
    ttl = bits(8, "TTL", DEC)


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


class InnerIpv6(Header):
    """Layout twin of `Ipv6` for the `inner_ipv6` instance: a header
    type carrying variable-length fields may be extracted under only
    one instance name in the eDSL, so the source's single ipv6_t
    becomes two identical types here."""

    version = bits(4, "Version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_len = bits(16, "Payload Length", DEC)
    next_hdr = bits(8, "Next Header", DEC, labels=IpProto)
    hop_limit = bits(8, "Hop Limit", DEC)
    src_addr = var_bytes(16)
    dst_addr = var_bytes(16)


class Icmp(Header):
    type_code = bits(16, "Type/Code", HEX)
    hdr_checksum = bits(16, "Checksum", HEX)


class Tcp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC, labels=TcpPort)
    seq_no = bits(32, "Sequence Number", DEC)
    ack_no = bits(32, "Ack Number", DEC)
    data_offset = bits(4, "Data Offset", DEC)
    res = bits(4, "Reserved")
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent_ptr = bits(16, "Urgent Pointer", DEC)


class Udp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC, labels=UdpPort)
    length_ = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class Sctp(Header):
    src_port = bits(16, "Source Port", DEC)
    dst_port = bits(16, "Destination Port", DEC)
    verif_tag = bits(32, "Verification Tag", HEX)
    checksum = bits(32, "Checksum", HEX)


class Gre(Header):
    """The source's case-distinct flag pair `S`/`s` becomes
    `s`/`strict` (the gibb_* convention; display names keep the
    source's letters)."""

    c = bits(1, "C (Checksum Present)")
    r = bits(1, "R (Routing Present)")
    k = bits(1, "K (Key Present)")
    s = bits(1, "S (Sequence Present)")
    strict = bits(1, "s (Strict Source Route)")
    recurse = bits(3, "Recursion Control")
    flags = bits(5, "Flags")
    ver = bits(3, "Version")
    proto = bits(
        16,
        "Protocol Type",
        HEX,
        labels=[
            EtherType.ETHERNET,
            EtherType.IPV4,
            EtherType.IPV6,
            EtherType.ERSPAN_T3,
        ],
    )


class Nvgre(Header):
    tni = bits(24, "TNI", DEC)
    flow_id = bits(8, "Flow ID", HEX)


class ErspanHeaderT3(Header):
    version = bits(4, "Version")
    vlan = bits(12, "VLAN", DEC)
    priority = bits(6, "Priority")
    span_id = bits(10, "Span ID", DEC)
    timestamp = bits(32, "Timestamp", DEC)
    sgt = bits(16, "SGT", HEX)
    ft_d_other = bits(16, "Ft/D/Other", HEX)


class Vxlan(Header):
    flags = bits(8, "Flags", HEX)
    reserved = bits(24, "Reserved")
    vni = bits(24, "VNI", DEC)
    reserved2 = bits(8, "Reserved")


class VxlanGpe(Header):
    flags = bits(8, "Flags", HEX)
    reserved = bits(16, "Reserved")
    next_proto = bits(8, "Next Protocol", HEX)
    vni = bits(24, "VNI", DEC)
    reserved2 = bits(8, "Reserved")


class VxlanGpeIntHeader(Header):
    int_type = bits(8, "INT Type", HEX)
    rsvd = bits(8, "Reserved")
    len = bits(8, "Length", DEC)
    next_proto = bits(8, "Next Protocol", HEX)


class Genv(Header):
    ver = bits(2, "Version")
    opt_len = bits(6, "Option Length", DEC)
    oam = bits(1, "OAM")
    critical = bits(1, "Critical")
    reserved = bits(6, "Reserved")
    proto_type = bits(16, "Protocol Type", HEX, labels=[EtherType.ETHERNET])
    vni = bits(24, "VNI", DEC)
    reserved2 = bits(8, "Reserved")


class Nsh(Header):
    oam = bits(1, "OAM")
    context = bits(1, "Context")
    flags = bits(6, "Flags")
    reserved = bits(8, "Reserved")
    proto_type = bits(
        16,
        "Protocol Type",
        HEX,
        labels=[EtherType.IPV4, EtherType.IPV6, EtherType.ETHERNET],
    )
    spath = bits(24, "Service Path", DEC)
    sindex = bits(8, "Service Index", DEC)


class NshContext(Header):
    network_platform = bits(32, "Network Platform", HEX)
    network_shared = bits(32, "Network Shared", HEX)
    service_platform = bits(32, "Service Platform", HEX)
    service_shared = bits(32, "Service Shared", HEX)


class Lisp(Header):
    flags = bits(8, "Flags", HEX)
    nonce = bits(24, "Nonce", HEX)
    lsbs_instance_id = bits(32, "LSBs/Instance ID", HEX)


class Trill(Header):
    version = bits(2, "Version")
    reserved = bits(2, "Reserved")
    multi_destination = bits(1, "Multi-Destination")
    opt_length = bits(5, "Option Length", DEC)
    hop_count = bits(6, "Hop Count", DEC)
    egress_rbridge = bits(16, "Egress RBridge", DEC)
    ingress_rbridge = bits(16, "Ingress RBridge", DEC)


class Vntag(Header):
    direction = bits(1, "Direction")
    pointer = bits(1, "Pointer")
    dest_vif = bits(14, "Destination VIF", DEC)
    looped = bits(1, "Looped")
    reserved = bits(1, "Reserved")
    version = bits(2, "Version")
    src_vif = bits(12, "Source VIF", DEC)


class Bfd(Header):
    version = bits(3, "Version")
    diag = bits(5, "Diagnostic")
    state = bits(2, "State")
    p = bits(1, "P")
    f = bits(1, "F")
    c = bits(1, "C")
    a = bits(1, "A")
    d = bits(1, "D")
    m = bits(1, "M")
    detect_mult = bits(8, "Detect Multiplier", DEC)
    len = bits(8, "Length", DEC)
    my_discriminator = bits(32, "My Discriminator", HEX)
    your_discriminator = bits(32, "Your Discriminator", HEX)
    desired_min_tx_interval = bits(32, "Desired Min TX Interval", DEC)
    required_min_rx_interval = bits(32, "Required Min RX Interval", DEC)
    required_min_echo_rx_interval = bits(32, "Required Min Echo RX Interval", DEC)


class SflowHdr(Header):
    version = bits(32, "Version", DEC)
    addr_type = bits(32, "Address Type", DEC)
    ip_address = bits(32, "IP Address", HEX)
    sub_agent_id = bits(32, "Sub-Agent ID", DEC)
    seq_number = bits(32, "Sequence Number", DEC)
    uptime = bits(32, "Uptime", DEC)
    num_samples = bits(32, "Sample Count", DEC)


class FabricHeader(Header):
    packet_type = bits(3, "Packet Type", DEC, labels=FabricPacketType)
    header_version = bits(2, "Header Version")
    packet_version = bits(2, "Packet Version")
    pad1 = bits(1, "Pad")
    fabric_color = bits(3, "Fabric Color")
    fabric_qos = bits(5, "Fabric QoS")
    dst_device = bits(8, "Destination Device", DEC)
    dst_port_or_group = bits(16, "Destination Port/Group", DEC)


class FabricHeaderUnicast(Header):
    routed = bits(1, "Routed")
    outer_routed = bits(1, "Outer Routed")
    tunnel_terminate = bits(1, "Tunnel Terminate")
    ingress_tunnel_type = bits(5, "Ingress Tunnel Type", DEC)
    nexthop_index = bits(16, "Nexthop Index", DEC)


class FabricHeaderMulticast(Header):
    routed = bits(1, "Routed")
    outer_routed = bits(1, "Outer Routed")
    tunnel_terminate = bits(1, "Tunnel Terminate")
    ingress_tunnel_type = bits(5, "Ingress Tunnel Type", DEC)
    ingress_ifindex = bits(16, "Ingress IfIndex", DEC)
    ingress_bd = bits(16, "Ingress BD", DEC)
    mcast_grp = bits(16, "Multicast Group", DEC)


class FabricHeaderMirror(Header):
    rewrite_index = bits(16, "Rewrite Index", DEC)
    egress_port = bits(10, "Egress Port", DEC)
    egress_queue = bits(5, "Egress Queue", DEC)
    pad = bits(1, "Pad")


class FabricHeaderCpu(Header):
    egress_queue = bits(5, "Egress Queue", DEC)
    tx_bypass = bits(1, "TX Bypass")
    reserved = bits(2, "Reserved")
    ingress_port = bits(16, "Ingress Port", DEC)
    ingress_ifindex = bits(16, "Ingress IfIndex", DEC)
    ingress_bd = bits(16, "Ingress BD", DEC)
    reason_code = bits(16, "Reason Code", HEX, labels=CpuReason)
    mcast_grp = bits(16, "Multicast Group", DEC)


class FabricHeaderSflow(Header):
    sflow_session_id = bits(16, "sFlow Session ID", DEC)
    sflow_egress_ifindex = bits(16, "sFlow Egress IfIndex", DEC)


class FabricPayloadHeader(Header):
    ether_type = bits(16, "EtherType", HEX, labels=EtherType)


class IntHeader(Header):
    ver = bits(2, "Version")
    rep = bits(2, "Replication")
    c = bits(1, "Copy")
    e = bits(1, "Max Hop Count Exceeded")
    rsvd1 = bits(5, "Reserved")
    ins_cnt = bits(5, "Instruction Count", DEC)
    max_hop_cnt = bits(8, "Max Hop Count", DEC)
    total_hop_cnt = bits(8, "Total Hop Count", DEC)
    instruction_mask_0003 = bits(4, "Instruction Mask 0-3")
    instruction_mask_0407 = bits(4, "Instruction Mask 4-7")
    instruction_mask_0811 = bits(4, "Instruction Mask 8-11")
    instruction_mask_1215 = bits(4, "Instruction Mask 12-15")
    rsvd2 = bits(16, "Reserved")


class IntSwitchIdHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    switch_id = bits(31, "Switch ID", DEC)


class IntIngressPortIdHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    ingress_port_id_1 = bits(15, "Ingress Port ID (high)", DEC)
    ingress_port_id_0 = bits(16, "Ingress Port ID (low)", DEC)


class IntHopLatencyHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    hop_latency = bits(31, "Hop Latency", DEC)


class IntQOccupancyHeader(Header, name="int_q_occupancy_header"):
    bos = bits(1, "Bottom of Stack", DEC)
    q_occupancy1 = bits(7, "Queue Occupancy (high)", DEC)
    q_occupancy0 = bits(24, "Queue Occupancy (low)", DEC)


class IntIngressTstampHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    ingress_tstamp = bits(31, "Ingress Timestamp", DEC)


class IntEgressPortIdHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    egress_port_id = bits(31, "Egress Port ID", DEC)


class IntQCongestionHeader(Header, name="int_q_congestion_header"):
    bos = bits(1, "Bottom of Stack", DEC)
    q_congestion = bits(31, "Queue Congestion", DEC)


class IntEgressPortTxUtilizationHeader(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    egress_port_tx_utilization = bits(31, "Egress Port TX Utilization", DEC)


class IntValue(Header):
    bos = bits(1, "Bottom of Stack", DEC)
    val = bits(31, "Value", HEX)


# --- the lookahead vocabulary (the source's anonymous `current(0, 4)`) ---


class IpVersionNibble(Header):
    """The source's `current(0, 4)`: peeked with `lookahead()` — bound
    and dispatched on without consuming, exactly like the original.
    (P4_14's current() is anonymous; the IR peeks a named 4-bit
    header, and its continuations extract the REAL full types over
    the same bits.)"""

    v = bits(4, "Version Nibble", DEC, labels=IpVersion)


# --- named instances used in selects ---

VLAN_TAG = VlanTag["vlan_tag_"]
INNER_ETHERNET = Ethernet["inner_ethernet"]
INNER_IPV4 = Ipv4["inner_ipv4"]
INT_VAL = IntValue["int_val"]


def _gre_arm(proto: int, *, k: int = 0) -> tuple[int, ...]:
    """One arm of the source's 32-bit concatenated GRE select
    (C,R,K,S,s,recurse,flags,ver,proto), split per key width:
    0x20006558 = K=1 ++ proto 0x6558; the rest are bare proto."""
    return (0, 0, k, 0, 0, 0, 0, 0, proto)


class P4langSwitchParser(Parser):
    """The parser of classic switch.p4: `p4lang/switch` @ 7874f565,
    as-shipped feature defaults (p4features.h) + __TARGET_BMV2__.
    Two layers (outer + inner_* twins after tunnel decap), the
    fabric-header family, INT over VXLAN-GPE, and sFlow."""

    max_depth = 43

    # The common EtherType dispatch tail (parse_ethernet order:
    # 0x8100, 0x9100, 0x8847, 0x0800, 0x86dd, 0x0806, 0x88cc, 0x8809).
    def _ethertype_arms(self) -> dict[ArmKey, Target]:
        return {
            EtherType.VLAN: self.parse_vlan,
            EtherType.QINQ: self.parse_qinq,
            **self._post_vlan_arms(),
        }

    # The dispatch a VLAN tag continues with (no further VLAN arms).
    def _post_vlan_arms(self) -> dict[ArmKey, Target]:
        return {
            EtherType.MPLS: self.parse_mpls,
            EtherType.IPV4: self.parse_ipv4,
            EtherType.IPV6: self.parse_ipv6,
            EtherType.ARP: self.parse_arp_rarp,
            EtherType.LLDP: self.parse_set_prio_high,
            EtherType.LACP: self.parse_set_prio_high,
        }

    # The two LLC arms of parse_ethernet / parse_fabric_payload_header
    # (`0 mask 0xfe00` then `0 mask 0xfa00`, in source order).
    def _llc_arms(self) -> dict[ArmKey, Target]:
        return {
            masked(0, 0xFE00): self.parse_llc_header,
            masked(0, 0xFA00): self.parse_llc_header,
        }

    # The inner-IPv4 dispatch: the same (fragOffset, ihl, protocol)
    # concatenation as parse_ipv4, ICMP/TCP/UDP arms only.
    def _inner_ipv4_arms(self) -> dict[ArmKey, Target]:
        return {
            (0, 5, IpProto.ICMP): self.parse_inner_icmp,
            (0, 5, IpProto.TCP): self.parse_inner_tcp,
            (0, 5, IpProto.UDP): self.parse_inner_udp,
        }

    def _inner_ipv6_arms(self) -> dict[ArmKey, Target]:
        return {
            IpProto.ICMPV6: self.parse_inner_icmp,
            IpProto.TCP: self.parse_inner_tcp,
            IpProto.UDP: self.parse_inner_udp,
        }

    def _dhcp_rip_hsrp_arms(self) -> dict[ArmKey, Target]:
        """The routing/bootstrap UDP ports both UDP states raise
        priority for, in source order."""
        return {
            UdpPort.BOOTPS: self.parse_set_prio_med,
            UdpPort.BOOTPC: self.parse_set_prio_med,
            UdpPort.DHCPV6_CLIENT: self.parse_set_prio_med,
            UdpPort.DHCPV6_SERVER: self.parse_set_prio_med,
            UdpPort.RIP: self.parse_set_prio_med,
            UdpPort.RIPNG: self.parse_set_prio_med,
            UdpPort.HSRP: self.parse_set_prio_med,
        }

    def _gre_keys(self) -> tuple[FieldSpec, ...]:
        return (
            Gre.c,
            Gre.r,
            Gre.k,
            Gre.s,
            Gre.strict,
            Gre.recurse,
            Gre.flags,
            Gre.ver,
            Gre.proto,
        )

    # --- L2 ---

    def parse_ethernet(self) -> State:
        """The entry state. The source's `start` is a bare `return
        parse_ethernet`; `start` is a reserved eDSL attribute, so the
        entry lands here directly."""
        return extract(Ethernet).select(
            Ethernet.ether_type,
            {
                **self._llc_arms(),
                EtherType.BF_FABRIC: self.parse_fabric_header,
                **self._ethertype_arms(),
            },
            default=accept(),
        )

    def parse_llc_header(self) -> State:
        """The source selects on (dsap, ssap) with the concatenated
        literals 0xAAAA (SNAP) and 0xFEFE (CLNS/IS-IS), split here
        per 8-bit key."""
        return extract(LlcHeader).select(
            (LlcHeader.dsap, LlcHeader.ssap),
            {
                (0xAA, 0xAA): self.parse_snap_header,
                (0xFE, 0xFE): self.parse_set_prio_med,
            },
            default=accept(),
        )

    def parse_snap_header(self) -> State:
        return extract(SnapHeader).select(
            SnapHeader.type_,
            self._ethertype_arms(),
            default=accept(),
        )

    def parse_roce(self) -> State:
        """Unreachable under shipped defaults (its EtherType arm is
        compiled out); transcribed as the source keeps it."""
        return extract(RoceHeader, "roce").accept()

    def parse_fcoe(self) -> State:
        """Unreachable under shipped defaults (see parse_roce)."""
        return extract(FcoeHeader, "fcoe").accept()

    def parse_vlan(self) -> State:
        """First 802.1Q tag: extracts vlan_tag_[0]. All three VLAN
        states share one `vlan_tag_` instance (the gibb stack
        pattern: a later extract overwrites)."""
        return extract(VLAN_TAG).select(
            VLAN_TAG.ether_type,
            self._post_vlan_arms(),
            default=accept(),
        )

    def parse_qinq(self) -> State:
        return extract(VLAN_TAG).select(
            VLAN_TAG.ether_type,
            {EtherType.VLAN: self.parse_qinq_vlan},
            default=accept(),
        )

    def parse_qinq_vlan(self) -> State:
        """The inner 0x8100 tag of a QinQ pair: vlan_tag_[1] in the
        source, the shared `vlan_tag_` instance here."""
        return extract(VLAN_TAG).select(
            VLAN_TAG.ether_type,
            self._post_vlan_arms(),
            default=accept(),
        )

    # --- MPLS (mpls[3], unrolled over one `mpls` instance) ---

    def parse_mpls(self) -> State:
        """First label of the source's `mpls[3]` stack. The source is
        one self-looping state extracting `mpls[next]`; the 3-entry
        stack bound is transcribed by unrolling (parse_mpls_2 and
        parse_mpls_3 are unroll-invented names)."""
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls_2, 1: self.parse_mpls_bos},
            default=accept(),
        )

    def parse_mpls_2(self) -> State:
        return extract(Mpls).select(
            Mpls.bos,
            {0: self.parse_mpls_3, 1: self.parse_mpls_bos},
            default=accept(),
        )

    def parse_mpls_3(self) -> State:
        """Third label: the stack is full. A fourth label (bos=0)
        would overflow `mpls[3]` — a P4_14 parse exception,
        transcribed as an explicit reject."""
        return extract(Mpls).select(
            Mpls.bos,
            {
                0: reject("a fourth MPLS label overflows the source's mpls[3] stack"),
                1: self.parse_mpls_bos,
            },
            default=accept(),
        )

    def parse_mpls_bos(self) -> State:
        """Bottom of stack: the source peeks `current(0, 4)` —
        transcribed 1:1 as a `lookahead()`; the continuations extract
        the real full inner types over the peeked bits."""
        return lookahead(IpVersionNibble).select(
            IpVersionNibble.v,
            {
                IpVersion.IPV4: self.parse_mpls_inner_ipv4,
                IpVersion.IPV6: self.parse_mpls_inner_ipv6,
            },
            default=self.parse_eompls,
        )

    def parse_mpls_inner_ipv4(self) -> State:
        """Metadata-only in the source (tunnel type 9 = MPLS L3VPN),
        then parse_inner_ipv4."""
        return goto(self.parse_inner_ipv4)

    def parse_mpls_inner_ipv6(self) -> State:
        """Metadata-only in the source (tunnel type 12), then
        parse_inner_ipv6."""
        return goto(self.parse_inner_ipv6)

    def parse_vpls(self) -> State:
        """Unreachable, extract-less `return ingress` in the source."""
        return goto(accept())

    def parse_pw(self) -> State:
        """Unreachable, extract-less `return ingress` in the source."""
        return goto(accept())

    # --- outer L3/L4 ---

    def parse_ipv4(self) -> State:
        """The source keys on (fragOffset, ihl, protocol) with
        concatenated literals (0x501 = frag 0 ++ ihl 5 ++ proto 1),
        split here per key width. The bare literals 2/88/89/103/112
        decompose to ihl=0 — the routing-protocol arms match only
        ihl==0 packets (a known switch.p4 quirk, kept). IPv4 is a
        fixed 20-byte extract: options are never consumed."""
        return extract(Ipv4).select(
            (Ipv4.frag_offset, Ipv4.ihl, Ipv4.protocol),
            {
                (0, 5, IpProto.ICMP): self.parse_icmp,
                (0, 5, IpProto.TCP): self.parse_tcp,
                (0, 5, IpProto.UDP): self.parse_udp,
                (0, 5, IpProto.GRE): self.parse_gre,
                (0, 5, IpProto.IPV4): self.parse_ipv4_in_ip,
                (0, 5, IpProto.IPV6): self.parse_ipv6_in_ip,
                (0, 0, IpProto.IGMP): self.parse_set_prio_med,
                (0, 0, IpProto.EIGRP): self.parse_set_prio_med,
                (0, 0, IpProto.OSPF): self.parse_set_prio_med,
                (0, 0, IpProto.PIM): self.parse_set_prio_med,
                (0, 0, IpProto.VRRP): self.parse_set_prio_med,
            },
            default=accept(),
        )

    def parse_ipv4_in_ip(self) -> State:
        """Metadata-only in the source (tunnel type 3 = IP-in-IP)."""
        return goto(self.parse_inner_ipv4)

    def parse_ipv6_in_ip(self) -> State:
        return goto(self.parse_inner_ipv6)

    def parse_udp_v6(self) -> State:
        """Unreachable under shipped defaults (parse_ipv6 dispatches
        UDP to parse_udp); extracts into the shared `udp` instance,
        as the source does."""
        return extract(Udp).select(
            Udp.dst_port,
            self._dhcp_rip_hsrp_arms(),
            default=accept(),
        )

    def parse_gre_v6(self) -> State:
        """Unreachable twin of parse_gre with a single IPv4 arm."""
        return extract(Gre).select(
            self._gre_keys(),
            {_gre_arm(0x0800): self.parse_gre_ipv4},
            default=accept(),
        )

    def parse_ipv6(self) -> State:
        return extract(Ipv6).select(
            Ipv6.next_hdr,
            {
                IpProto.ICMPV6: self.parse_icmp,
                IpProto.TCP: self.parse_tcp,
                IpProto.IPV4: self.parse_ipv4_in_ip,
                IpProto.UDP: self.parse_udp,
                IpProto.GRE: self.parse_gre,
                IpProto.IPV6: self.parse_ipv6_in_ip,
                IpProto.EIGRP: self.parse_set_prio_med,
                IpProto.OSPF: self.parse_set_prio_med,
                IpProto.PIM: self.parse_set_prio_med,
                IpProto.VRRP: self.parse_set_prio_med,
            },
            default=accept(),
        )

    def parse_icmp(self) -> State:
        """Shared by IPv4 (proto 1) and IPv6 (proto 58). The masked
        typeCode arms raise priority for ICMPv6 MLD and neighbor
        discovery."""
        return extract(Icmp).select(
            Icmp.type_code,
            {
                masked(0x8200, 0xFE00): self.parse_set_prio_med,
                masked(0x8400, 0xFC00): self.parse_set_prio_med,
                masked(0x8800, 0xFF00): self.parse_set_prio_med,
            },
            default=accept(),
        )

    def parse_tcp(self) -> State:
        """A fixed 20-byte extract: dataOffset is read but no options
        are consumed (source behavior)."""
        return extract(Tcp).select(
            Tcp.dst_port,
            {
                TcpPort.BGP: self.parse_set_prio_med,
                TcpPort.MSDP: self.parse_set_prio_med,
            },
            default=accept(),
        )

    def parse_roce_v2(self) -> State:
        """Unreachable under shipped defaults (no 4791 arm in
        parse_udp)."""
        return extract(RoceV2Header, "roce_v2").accept()

    def parse_udp(self) -> State:
        return extract(Udp).select(
            Udp.dst_port,
            {
                UdpPort.VXLAN: self.parse_vxlan,
                UdpPort.GENV: self.parse_geneve,
                UdpPort.VXLAN_GPE: self.parse_vxlan_gpe,
                **self._dhcp_rip_hsrp_arms(),
                UdpPort.SFLOW: self.parse_sflow,
            },
            default=accept(),
        )

    # --- INT (in-band network telemetry over VXLAN-GPE) ---

    def parse_gpe_int_header(self) -> State:
        return extract(VxlanGpeIntHeader).then(self.parse_int_header)

    def parse_int_header(self) -> State:
        """The source keys on (rsvd1, total_hop_cnt): exact 0x000
        accepts (no hops added yet), `0x000 mask 0xf00` (= rsvd1's
        low four bits zero) enters the value stack, and a `0 mask 0`
        catch-all accepts — deliberately shadowing the default, whose
        target parse_all_int_meta_value_heders the source keeps as a
        deparser-graph aid ("never transition to the following
        state")."""
        return extract(IntHeader).select(
            (IntHeader.rsvd1, IntHeader.total_hop_cnt),
            {
                (0, 0): accept(),
                (masked(0, 0x0F), masked(0, 0x00)): self.parse_int_val,
                (masked(0, 0x00), masked(0, 0x00)): accept(),
            },
            default=self.parse_all_int_meta_value_heders,
        )

    def parse_int_val(self) -> State:
        """The source's `int_val[24]` stack loop, kept as one cyclic
        state: `max_depth` (not the stack size) bounds it here, so
        the 24-entry cap is a depth budget, not a hard count."""
        return extract(INT_VAL).select(
            INT_VAL.bos,
            {0: self.parse_int_val, 1: self.parse_inner_ethernet},
            default=accept(),
        )

    def parse_all_int_meta_value_heders(self) -> State:
        """Semantically unreachable (see parse_int_header); the state
        name keeps the source's spelling, typo included."""
        return (
            extract(IntSwitchIdHeader)
            .extract(IntIngressPortIdHeader)
            .extract(IntHopLatencyHeader)
            .extract(IntQOccupancyHeader)
            .extract(IntIngressTstampHeader)
            .extract(IntEgressPortIdHeader)
            .extract(IntQCongestionHeader)
            .extract(IntEgressPortTxUtilizationHeader)
            .then(self.parse_int_val)
        )

    def parse_sctp(self) -> State:
        """Unreachable under shipped defaults (no proto-132 arm)."""
        return extract(Sctp).accept()

    # --- GRE and tunnels ---

    def parse_gre(self) -> State:
        """The source selects on all nine GRE fields concatenated
        (32 bits); 0x20006558 splits to K=1 ++ proto 0x6558 (NVGRE),
        the other arms are flagless proto values."""
        return extract(Gre).select(
            self._gre_keys(),
            {
                _gre_arm(EtherType.ETHERNET, k=1): self.parse_nvgre,
                _gre_arm(EtherType.IPV4): self.parse_gre_ipv4,
                _gre_arm(EtherType.IPV6): self.parse_gre_ipv6,
                _gre_arm(EtherType.ERSPAN_T3): self.parse_erspan_t3,
            },
            default=accept(),
        )

    def parse_gre_ipv4(self) -> State:
        """Metadata-only in the source (tunnel type 2 = GRE)."""
        return goto(self.parse_inner_ipv4)

    def parse_gre_ipv6(self) -> State:
        return goto(self.parse_inner_ipv6)

    def parse_nvgre(self) -> State:
        return extract(Nvgre).then(self.parse_inner_ethernet)

    def parse_erspan_t3(self) -> State:
        return extract(ErspanHeaderT3, "erspan_t3_header").then(
            self.parse_inner_ethernet
        )

    def parse_arp_rarp(self) -> State:
        """Extract-less in this configuration: ARP raises priority
        and parsing ends (the ARP header extract is compiled out)."""
        return goto(self.parse_set_prio_med)

    def parse_eompls(self) -> State:
        """The source's eompls extract is commented out; the state
        jumps straight to parse_inner_ethernet (the peeked nibble was
        never consumed, so nothing needs re-assembling)."""
        return goto(self.parse_inner_ethernet)

    def parse_vxlan(self) -> State:
        return extract(Vxlan).then(self.parse_inner_ethernet)

    def parse_vxlan_gpe(self) -> State:
        """next_proto 5 (INT shim) is written `0x05 mask 0xff` in the
        source; kept as a masked arm."""
        return extract(VxlanGpe).select(
            VxlanGpe.next_proto,
            {masked(0x05, 0xFF): self.parse_gpe_int_header},
            default=self.parse_inner_ethernet,
        )

    def parse_geneve(self) -> State:
        """The source keys on (ver, optLen, protoType) with the single
        concatenated arm 0x6558 (= 0 ++ 0 ++ TEB) and NO default: any
        other value is a P4_14 parse exception, transcribed as an
        explicit reject."""
        return extract(Genv).select(
            (Genv.ver, Genv.opt_len, Genv.proto_type),
            {(0, 0, EtherType.ETHERNET): self.parse_inner_ethernet},
            default=reject(
                "genv: only ver=0, optLen=0, protoType=TEB is parseable"
            ),
        )

    def parse_nsh(self) -> State:
        """Unreachable under shipped defaults; extracts the NSH base
        and context headers back to back, as the source does."""
        return (
            extract(Nsh)
            .extract(NshContext)
            .select(
                Nsh.proto_type,
                {
                    EtherType.IPV4: self.parse_inner_ipv4,
                    EtherType.IPV6: self.parse_inner_ipv6,
                    EtherType.ETHERNET: self.parse_inner_ethernet,
                },
                default=accept(),
            )
        )

    def parse_lisp(self) -> State:
        """Unreachable under shipped defaults. The source's second
        `current(0, 4)` site, transcribed 1:1: extract-then-peek in
        one state, routing straight to the real inner-IP states."""
        return (
            extract(Lisp)
            .lookahead(IpVersionNibble)
            .select(
                IpVersionNibble.v,
                {
                    IpVersion.IPV4: self.parse_inner_ipv4,
                    IpVersion.IPV6: self.parse_inner_ipv6,
                },
                default=accept(),
            )
        )

    # --- the inner layer (after tunnel decap) ---

    def parse_inner_ipv4(self) -> State:
        return extract(INNER_IPV4).select(
            (INNER_IPV4.frag_offset, INNER_IPV4.ihl, INNER_IPV4.protocol),
            self._inner_ipv4_arms(),
            default=accept(),
        )

    def parse_inner_icmp(self) -> State:
        return extract(Icmp, "inner_icmp").accept()

    def parse_inner_tcp(self) -> State:
        return extract(Tcp, "inner_tcp").accept()

    def parse_inner_udp(self) -> State:
        return extract(Udp, "inner_udp").accept()

    def parse_inner_sctp(self) -> State:
        """Unreachable under shipped defaults (see parse_sctp)."""
        return extract(Sctp, "inner_sctp").accept()

    def parse_inner_ipv6(self) -> State:
        return extract(InnerIpv6).select(
            InnerIpv6.next_hdr,
            self._inner_ipv6_arms(),
            default=accept(),
        )

    def parse_inner_ethernet(self) -> State:
        return extract(INNER_ETHERNET).select(
            INNER_ETHERNET.ether_type,
            {
                EtherType.IPV4: self.parse_inner_ipv4,
                EtherType.IPV6: self.parse_inner_ipv6,
            },
            default=accept(),
        )

    def parse_trill(self) -> State:
        """Unreachable under shipped defaults."""
        return extract(Trill).then(self.parse_inner_ethernet)

    def parse_vntag(self) -> State:
        """Unreachable under shipped defaults."""
        return extract(Vntag).then(self.parse_inner_ethernet)

    def parse_bfd(self) -> State:
        """Unreachable under shipped defaults."""
        return extract(Bfd).then(self.parse_set_prio_max)

    def parse_sflow(self) -> State:
        return extract(SflowHdr, "sflow").accept()

    # --- the fabric-header family ---

    def parse_fabric_header(self) -> State:
        return extract(FabricHeader).select(
            FabricHeader.packet_type,
            {
                FabricPacketType.UNICAST: self.parse_fabric_header_unicast,
                FabricPacketType.MULTICAST: self.parse_fabric_header_multicast,
                FabricPacketType.MIRROR: self.parse_fabric_header_mirror,
                FabricPacketType.CPU: self.parse_fabric_header_cpu,
            },
            default=accept(),
        )

    def parse_fabric_header_unicast(self) -> State:
        return extract(FabricHeaderUnicast).then(self.parse_fabric_payload_header)

    def parse_fabric_header_multicast(self) -> State:
        return extract(FabricHeaderMulticast).then(self.parse_fabric_payload_header)

    def parse_fabric_header_mirror(self) -> State:
        return extract(FabricHeaderMirror).then(self.parse_fabric_payload_header)

    def parse_fabric_header_cpu(self) -> State:
        return extract(FabricHeaderCpu).select(
            FabricHeaderCpu.reason_code,
            {CpuReason.SFLOW: self.parse_fabric_sflow_header},
            default=self.parse_fabric_payload_header,
        )

    def parse_fabric_sflow_header(self) -> State:
        return extract(FabricHeaderSflow).then(self.parse_fabric_payload_header)

    def parse_fabric_payload_header(self) -> State:
        """The fabric payload re-enters the L2 dispatch — the same
        map as parse_ethernet minus the fabric arm (no nesting)."""
        return extract(FabricPayloadHeader).select(
            FabricPayloadHeader.ether_type,
            {**self._llc_arms(), **self._ethertype_arms()},
            default=accept(),
        )

    # --- priority terminals (metadata-only in the source) ---

    def parse_set_prio_med(self) -> State:
        """`intrinsic_metadata.priority = 3` in the source, then
        ingress: parsing ends."""
        return goto(accept())

    def parse_set_prio_high(self) -> State:
        """`intrinsic_metadata.priority = 5` in the source."""
        return goto(accept())

    def parse_set_prio_max(self) -> State:
        """`intrinsic_metadata.priority = 7` in the source."""
        return goto(accept())


if __name__ == "__main__":
    print(P4langSwitchParser.to_json())

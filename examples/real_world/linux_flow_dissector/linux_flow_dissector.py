"""Ethernet -> {VLAN | MPLS | IPv4 (with options) | IPv6} -> {TCP | UDP}.

The flow-dissector target: the permanent home the flow-dissector
initiative grows in. Rung 0 mirrored `eth_ipvx_l4` — plain EtherType
demux to IPv4 or IPv6, each IP header demuxing to a shared TCP or UDP
successor (a join in the parse DAG). Rung 1 adds kernel-faithful VLAN
and MPLS handling, agreeing with upstream `bpf_flow.c`:

- VLAN is unrolled to depth <=2 to mirror upstream `PROG(VLAN)`'s
  position-dependent rules: an 802.1AD (QinQ) outer tag must be followed
  by exactly one 802.1Q tag (`parse_vlan_ad` -> `parse_vlan_q` only); a
  bare 802.1Q tag is the common tail (`parse_vlan_q`) and demuxes to
  IPv4/IPv6/MPLS; a third tag of either kind is a kernel drop (no triple
  tagging, no double-Q).
- MPLS is a single-entry read-and-stop state (`parse_mpls`) mirroring
  upstream `PROG(MPLS)`: read one label entry and accept, regardless of
  the bottom-of-stack bit.

A field-for-field port of the Rust builder description (src/examples.rs)
for the rung-0 subset; the conformance test asserts proto equality with
the committed gallery `ir.json`.

IPv6 addresses are 128-bit, above the fixed-`bits` ceiling, so they are
`var_bytes` opaque runs (rendered as hex; not tshark-diffed).

Rung 4a adds IPIP (proto 4) and IPv6-in-IP (proto 41) tunnel re-entrancy
mirroring upstream `parse_ip_proto`'s encap arms: two pass-through states
(`parse_ipip`, `parse_ip6ip`) set the declared `FlowMeta.is_encap` bit and
re-enter the matching IP state — encap is "more back edges", bounded like
every cycle by `max_depth` (10: covers the deepest golden chain, 7 state
entries, and rung 4b's TEB chains; measured symex cost rules out a more
generous budget). The kernel reaches its encap arms from three
places (IPv4's protocol, IPv6's next_header, and the ext-header chain's
last link), so all three demux selects grow the two tunnel arms; a
Fragment header still stops unconditionally (kernel PROG(IPV6FR)).

Rung 4b adds GRE (proto 47) mirroring upstream's `IPPROTO_GRE` arm, whose
ordering is the crux: read the 4-byte base, and if version != 0 accept
immediately (no thoff advance, no is_encap, optionals never read) — so the
base and the C/K/S-sized optional region are separate headers/states
(`parse_gre` -> `parse_gre_opt`). Only after the version gate does the
optional region get skipped and `is_encap` set; the proto then dispatches
0x0800/0x86DD into the IP states, and TEB (0x6558) re-enters
`parse_ethernet` itself — the kernel reads the inner Ethernet and calls
its full `parse_eth_proto` dispatcher, so inner VLAN/MPLS/IPvX all live.
The kernel ignores the R bit (masks only C/K/S/version), so routing-present
packets are plain version-0 GRE on both sides — faithful by construction.
"""

from pakeles import (
    ArmKey,
    Header,
    LabeledEnum,
    Metadata,
    Parser,
    State,
    Target,
    accept,
    assign,
    bits,
    extract,
    metadata_bits,
    oneof,
    reject,
    var_bytes,
)
from pakeles.fmt import DEC, ETHER, HEX, IPV4


class EtherType(LabeledEnum):
    """The EtherType registry slice the dissector touches — one
    vocabulary for the select arms and the fields' display labels."""

    IPV4 = 0x0800, "IPv4"
    ARP = 0x0806
    TEB = 0x6558
    VLAN_Q = 0x8100, "802.1Q VLAN"
    IPV6 = 0x86DD, "IPv6"
    MPLS_UC = 0x8847, "MPLS unicast"
    MPLS_MC = 0x8848, "MPLS multicast"
    VLAN_AD = 0x88A8, "802.1AD (QinQ)"


class IPProto(LabeledEnum):
    """IP protocol numbers, kernel `IPPROTO_*` names — 41 is
    `IPPROTO_IPV6`, the IPv6-in-IP encapsulation next-header."""

    HOPOPTS = 0
    ICMP = 1
    IPIP = 4
    TCP = 6
    UDP = 17
    IPV6 = 41, "IPv6-in-IP"
    FRAGMENT = 44
    GRE = 47
    DSTOPTS = 60


class Ethernet(Header):
    dst = bits(48, "Destination", ETHER, tshark="eth.dst")
    src = bits(48, "Source", ETHER, tshark="eth.src")
    ethertype = bits(
        16,
        "Type",
        HEX,
        tshark="eth.type",
        labels=[
            EtherType.IPV4,
            EtherType.IPV6,
            EtherType.ARP,
            EtherType.VLAN_Q,
            EtherType.VLAN_AD,
            EtherType.MPLS_UC,
            EtherType.MPLS_MC,
        ],
    )


class VLAN(Header):
    pcp = bits(3, "Priority", DEC, tshark="vlan.priority")
    dei = bits(1, "DEI", DEC, tshark="vlan.dei")
    vid = bits(12, "VLAN ID", DEC, tshark="vlan.id")
    encapsulated_proto = bits(
        16,
        "Type",
        HEX,
        tshark="vlan.etype",
        labels=[
            EtherType.IPV4,
            EtherType.IPV6,
            EtherType.MPLS_UC,
            EtherType.MPLS_MC,
        ],
    )


vlan_ad = VLAN["vlan_ad"]  # the outer 802.1AD S-tag
vlan_q = VLAN["vlan_q"]  # the final (or only) 802.1Q tag


class MPLS(Header):
    label = bits(20, "Label", DEC, tshark="mpls.label")
    tc = bits(3, "Traffic Class", DEC, tshark="mpls.exp")
    s = bits(1, "Bottom of Stack", DEC, tshark="mpls.bottom")
    ttl = bits(8, "TTL", DEC, tshark="mpls.ttl")


class IPv4(Header):
    version = bits(4, "Version", DEC, tshark="ip.version")
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    dscp = bits(6, "DSCP", DEC)
    ecn = bits(2, "ECN", DEC)
    total_len = bits(16, "Total Length", DEC, tshark="ip.len")
    id = bits(16, "Identification", HEX)
    flags = bits(3, "Flags", HEX)
    frag_offset = bits(13, "Fragment Offset", DEC)
    ttl = bits(8, "Time to Live", DEC, tshark="ip.ttl")
    protocol = bits(
        8,
        "Protocol",
        DEC,
        tshark="ip.proto",
        labels=[
            IPProto.ICMP,
            IPProto.IPIP,
            IPProto.TCP,
            IPProto.UDP,
            IPProto.IPV6,
            IPProto.GRE,
        ],
    )
    checksum = bits(16, "Header Checksum", HEX, tshark="ip.checksum")
    src = bits(32, "Source Address", IPV4, tshark="ip.src")
    dst = bits(32, "Destination Address", IPV4, tshark="ip.dst")
    options = var_bytes(ihl * 4 - 20)


class IPv6(Header):
    version = bits(4, "Version", DEC, tshark="ipv6.version")
    traffic_class = bits(8, "Traffic Class", HEX)
    flow_label = bits(20, "Flow Label", HEX)
    payload_length = bits(16, "Payload Length", DEC, tshark="ipv6.plen")
    next_header = bits(
        8,
        "Next Header",
        DEC,
        tshark="ipv6.nxt",
        labels=[
            IPProto.ICMP,
            IPProto.IPIP,
            IPProto.TCP,
            IPProto.UDP,
            IPProto.IPV6,
            IPProto.GRE,
        ],
    )
    hop_limit = bits(8, "Hop Limit", DEC, tshark="ipv6.hlim")
    # 128-bit addresses exceed the fixed-`bits` ceiling: opaque 16-byte runs.
    src = var_bytes(16)
    dst = var_bytes(16)


class IPv6ExtOpt(Header):  # HopByHop (0) / DestOpts (60) option header
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.opt.nxt")
    hdr_ext_len = bits(8, "Hdr Ext Len", DEC, doc="in 8-octet units, excl. first 8")
    # option body: (1 + hdr_ext_len) * 8 total bytes, minus the 2-byte prefix.
    body = var_bytes(((1 + hdr_ext_len) << 3) - 2)


ext_opt = IPv6ExtOpt["ext_opt"]


class IPv6Frag(Header):  # fragment header (nexthdr 44)
    next_header = bits(8, "Next Header", DEC, tshark="ipv6.frag.nxt")
    reserved = bits(8, "Reserved", HEX)
    frag_off = bits(13, "Fragment Offset", DEC, doc="in 8-octet units")
    res2 = bits(2, "Res", HEX)
    m_flag = bits(1, "More Fragments", DEC)
    identification = bits(32, "Identification", HEX)


ext_frag = IPv6Frag["ext_frag"]


class GRE(Header):  # 4-byte base; the kernel masks only C/K/S/version
    c = bits(1, "Checksum Present", DEC)
    routing = bits(1, "Routing Present", DEC, doc="ignored by the kernel (not masked)")
    key_flag = bits(1, "Key Present", DEC)
    seq_flag = bits(1, "Sequence Present", DEC)
    reserved = bits(9, "Reserved0", HEX, doc="unchecked by the kernel — never a reject")
    version = bits(3, "Version", DEC)
    proto = bits(
        16,
        "Protocol Type",
        HEX,
        labels=[EtherType.IPV4, EtherType.IPV6, EtherType.TEB],
    )


class GREOpt(Header):  # C/K/S optional region, skipped opaquely
    # C (csum+pad), K (key), S (seq) contribute 4 bytes each; cross-header
    # byte_len is legal — the definite-extraction analysis admits refs to
    # any instance must-extracted on every path here.
    body = var_bytes(GRE.c * 4 + GRE.key_flag * 4 + GRE.seq_flag * 4)


gre_opt = GREOpt["gre_opt"]


class TCP(Header):
    sport = bits(16, "Source Port", DEC, tshark="tcp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="tcp.dstport")
    seq = bits(32, "Sequence Number", DEC)
    ack = bits(32, "Acknowledgment Number", DEC)
    data_offset = bits(4, "Data Offset", DEC, doc="in 32-bit words")
    reserved = bits(4, "Reserved", HEX)
    flags = bits(8, "Flags", HEX)
    window = bits(16, "Window", DEC)
    checksum = bits(16, "Checksum", HEX)
    urgent = bits(16, "Urgent Pointer", DEC)
    # TCP options, a doff-sized region (data_offset counts 32-bit words).
    # doff<5 wraps -> oob reject == kernel `tcp->doff < 5` DROP; a truncated
    # region == kernel `tcp+doff*4 > data_end` DROP. Mirrors IPv4 options.
    options = var_bytes(data_offset * 4 - 20)


class UDP(Header):
    sport = bits(16, "Source Port", DEC, tshark="udp.srcport")
    dport = bits(16, "Destination Port", DEC, tshark="udp.dstport")
    length = bits(16, "Length", DEC)
    checksum = bits(16, "Checksum", HEX)


class FlowMeta(Metadata):
    is_encap = metadata_bits(
        1,
        "Encapsulated",
        DEC,
        doc="set on tunnel re-entry (IPIP / IPv6-in-IP), mirroring bpf_flow_keys.is_encap",
    )


class LinuxFlowDissector(Parser):
    max_depth = 10
    metadata = FlowMeta

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
                EtherType.VLAN_Q: self.parse_vlan_q,
                EtherType.VLAN_AD: self.parse_vlan_ad,
                oneof(EtherType.MPLS_UC, EtherType.MPLS_MC): self.parse_mpls,
            },
            default=reject("unsupported ethertype", info=True),
        )

    def parse_vlan_ad(self) -> State:
        """Upstream PROG(VLAN), 802.1AD arm: the outer S-tag must be
        followed by exactly one 802.1Q C-tag."""
        return extract(vlan_ad).select(
            vlan_ad.encapsulated_proto,
            {EtherType.VLAN_Q: self.parse_vlan_q},
            default=reject("802.1AD must be followed by 802.1Q"),
        )

    def parse_vlan_q(self) -> State:
        """Upstream PROG(VLAN), common tail: the final (or only) tag;
        a further Q/AD tag is a kernel drop (no triple tagging, no
        double-Q)."""
        return extract(vlan_q).select(
            vlan_q.encapsulated_proto,
            {
                EtherType.IPV4: self.parse_ipv4,
                EtherType.IPV6: self.parse_ipv6,
                oneof(EtherType.MPLS_UC, EtherType.MPLS_MC): self.parse_mpls,
                oneof(EtherType.VLAN_Q, EtherType.VLAN_AD): reject(
                    "vlan stacking beyond kernel depth"
                ),
            },
            default=reject("unsupported ethertype", info=True),
        )

    def _ip_proto_arms(self) -> dict[ArmKey, Target]:
        """The kernel's parse_ip_proto dispatch, shared by the IPv4,
        IPv6, and IPv6-extension-option states."""
        return {
            IPProto.IPIP: self.parse_ipip,
            IPProto.TCP: self.parse_tcp,
            IPProto.UDP: self.parse_udp,
            IPProto.IPV6: self.parse_ip6ip,
            IPProto.GRE: self.parse_gre,
        }

    def _ipv6_arms(self) -> dict[ArmKey, Target]:
        """parse_ip_proto plus the extension-header arms."""
        return {
            IPProto.HOPOPTS: self.parse_ipv6_opt,
            IPProto.DSTOPTS: self.parse_ipv6_opt,
            IPProto.FRAGMENT: self.parse_ipv6_frag,
            **self._ip_proto_arms(),
        }

    def parse_ipv4(self) -> State:
        return extract(IPv4).select(
            IPv4.protocol,
            self._ip_proto_arms(),
            default=reject("unsupported ip protocol", info=True),
        )

    def parse_ipv6(self) -> State:
        return extract(IPv6).select(
            IPv6.next_header,
            self._ipv6_arms(),
            default=reject("unsupported ip protocol", info=True),
        )

    def parse_ipv6_opt(self) -> State:
        """Kernel PROG(IPV6OP): walk the option, dispatch on its own
        next_header — HopByHop/DestOpts loop back (self-edge)."""
        return extract(ext_opt).select(
            ext_opt.next_header,
            self._ipv6_arms(),
            default=reject("unsupported ip protocol", info=True),
        )

    def parse_ipip(self) -> State:
        """Kernel parse_ip_proto encap arms (IPPROTO_IPIP / IPPROTO_IPV6,
        default flags: STOP_AT_ENCAP off): mark is_encap and re-enter
        the state machine as the inner family — pure back edges, no
        header read; the max_depth budget bounds the nesting."""
        return assign(FlowMeta.is_encap, 1).then(self.parse_ipv4)

    def parse_ip6ip(self) -> State:
        return assign(FlowMeta.is_encap, 1).then(self.parse_ipv6)

    def parse_gre(self) -> State:
        """Kernel IPPROTO_GRE arm, step order is the crux: version != 0
        is an immediate BPF_OK — no thoff advance, no is_encap, the
        optional region never read. Only version 0 walks the C/K/S
        optionals (parse_gre_opt), sets is_encap, and dispatches."""
        return extract(GRE).select(
            GRE.version,
            {0: self.parse_gre_opt},
            default=accept(),
        )

    def parse_gre_opt(self) -> State:
        """TEB (0x6558) re-enters parse_ethernet itself: the kernel reads
        the inner Ethernet and runs its full parse_eth_proto dispatcher,
        so inner VLAN/MPLS/IPvX all live."""
        return (
            extract(gre_opt)
            .assign(FlowMeta.is_encap, 1)
            .select(
                GRE.proto,
                {
                    EtherType.IPV4: self.parse_ipv4,
                    EtherType.IPV6: self.parse_ipv6,
                    EtherType.TEB: self.parse_ethernet,
                },
                default=reject("unsupported gre proto", info=True),
            )
        )

    def parse_ipv6_frag(self) -> State:
        """Kernel PROG(IPV6FR) under default flags: read the fragment
        header and stop (BPF_OK), always."""
        return extract(ext_frag).accept()

    def parse_mpls(self) -> State:
        """Upstream PROG(MPLS): read one label entry, stop, BPF_OK."""
        return extract(MPLS).accept()

    def parse_tcp(self) -> State:
        return extract(TCP).accept()

    def parse_udp(self) -> State:
        return extract(UDP).accept()


if __name__ == "__main__":
    print(LinuxFlowDissector.to_json())

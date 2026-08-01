#!/usr/bin/env python3
"""Generate corpus.txt: the dash_parser golden corpus.

Fully deterministic (no randomness anywhere). Sections mirror the
charter's quirk grounds (docs/plans/2026-07-31-dash-parser-charter.md):

  1. u0 basics: IPv4/IPv6 x TCP/UDP/other-proto, unknown EtherType.
  2. The IHL ladder: ihl 5 (no options), 6 and 15 (options varbit),
     <5 (verify InvalidIPv4Header), version != 4 (verify
     IPv4IncorrectVersion, and its precedence over the IHL check).
  3. VXLAN: u0_udp dst_port 4789 opens the customer layer (v4 and v6
     inner, both L4s); dst_port 4789 on TCP does NOT (the quirk);
     src_port 4789 does not; no VXLAN recursion; the customer IPv4
     verify rejects (ihl != 5 -> IPv4OptionsNotSupported).
  4. The DASH packet-metadata ether-type sentinel (0x876d): every
     packet_subtype demux arm incl. the FLOW_DELETE actions-bitmask
     ladder (0 / ENCAP_U0 / ENCAP_U1 / both / nonzero-no-encap), and
     packet_type being ignored by the demux.
  5. Truncation ladder: a cut at every state boundary, plus mid-header
     cuts, on both layers and the DASH path.
  6. Adversarial: empty, 1-byte, garbage.

A lone "-" line means the EMPTY packet (blank lines are skipped as
formatting by the factory; "-" is the explicit marker).

Regenerate: python3 mk_corpus.py > corpus.txt
"""

import sys

U16 = lambda v: v.to_bytes(2, "big")
U24 = lambda v: v.to_bytes(3, "big")
U32 = lambda v: v.to_bytes(4, "big")

ETH_V4 = 0x0800
ETH_V6 = 0x86DD
ETH_DASH = 0x876D
PROTO_TCP = 6
PROTO_UDP = 17
VXLAN_PORT = 4789

V4_SRC = bytes.fromhex("0a000001")
V4_DST = bytes.fromhex("0a000002")
V6_SRC = bytes.fromhex("20010db8000000000000000000000001")
V6_DST = bytes.fromhex("20010db8000000000000000000000002")


def eth(ethertype: int, dst: str = "aabbccddeeff", src: str = "112233445566") -> bytes:
    return bytes.fromhex(dst) + bytes.fromhex(src) + U16(ethertype)


def customer_eth(ethertype: int) -> bytes:
    return eth(ethertype, dst="c0ffee000001", src="c0ffee000002")


def ipv4(
    proto: int,
    *,
    version: int = 4,
    ihl: int = 5,
    options: bytes = b"",
    payload_len: int = 0,
    src: bytes = V4_SRC,
    dst: bytes = V4_DST,
) -> bytes:
    assert len(options) == 0 or ihl > 5
    return (
        bytes([(version << 4) | ihl, 0])
        + U16(20 + len(options) + payload_len)
        + U16(0x1234)
        + U16(0x4000)
        + bytes([64, proto])
        + U16(0xDEAD)
        + src
        + dst
        + options
    )


def ipv6(nh: int, *, payload_len: int = 0) -> bytes:
    return (
        U32(0x60000000) + U16(payload_len) + bytes([nh, 64]) + V6_SRC + V6_DST
    )


def udp(dst: int, *, src: int = 0x3039, payload_len: int = 0) -> bytes:
    return U16(src) + U16(dst) + U16(8 + payload_len) + U16(0)


def tcp(dst: int = 0x01BB, *, src: int = 0x3039) -> bytes:
    return (
        U16(src) + U16(dst) + U32(1) + U32(0)
        + bytes([0x50, 0x10]) + U16(0xFFFF) + U16(0) + U16(0)
    )


def vxlan(vni: int = 100) -> bytes:
    return bytes([0x08]) + U24(0) + U24(vni) + bytes([0])


def packet_meta(subtype: int, *, source: int = 0, ptype: int = 0) -> bytes:
    return bytes([source, (ptype << 4) | subtype]) + U16(4)


def flow_key() -> bytes:
    return (
        bytes.fromhex("020000000001")  # eni_mac
        + U16(1)                       # vnet_id
        + V4_SRC.rjust(16, b"\x00")    # src_ip (v4 in the 128-bit slot)
        + V4_DST.rjust(16, b"\x00")    # dst_ip
        + U16(1000) + U16(2000)        # src/dst_port
        + bytes([PROTO_TCP, 0])        # ip_proto, reserved+is_ip_v6
    )


def flow_data(actions: int) -> bytes:
    return (
        bytes([0])       # reserved + is_unidirectional
        + U16(1)         # direction = OUTBOUND
        + U32(1)         # version
        + U32(actions)
        + U32(0)         # meter_class
        + U32(0)         # idle_timeout_in_ms
    )


def overlay_data() -> bytes:
    return (
        bytes.fromhex("020000000002")            # dmac
        + V4_SRC.rjust(16, b"\x00")              # sip
        + V4_DST.rjust(16, b"\x00")              # dip
        + b"\xff" * 16 + b"\xff" * 16            # sip_mask, dip_mask
        + U16(3000) + U16(4000)                  # sport, dport
        + bytes([0])                             # reserved + is_ipv6
    )


def encap_data(vni: int) -> bytes:
    return (
        U24(vni)
        + bytes([0])
        + bytes.fromhex("c0a80001") + bytes.fromhex("c0a80002")
        + bytes.fromhex("02000000000a") + bytes.fromhex("02000000000b")
        + U16(1)  # dash_encapsulation = VXLAN
    )


LINES: list[tuple[str, str]] = []


def add(desc: str, pkt: bytes | str) -> None:
    if isinstance(pkt, bytes):
        pkt = pkt.hex() if pkt else "-"
    LINES.append((desc, pkt))


# --- 1. u0 basics ---------------------------------------------------
add("eth/IPv4/TCP", eth(ETH_V4) + ipv4(PROTO_TCP, payload_len=20) + tcp())
add("eth/IPv4/UDP dst 443 (not VXLAN)", eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=8) + udp(443))
add("eth/IPv4/other-proto 89 (accept, no L4)", eth(ETH_V4) + ipv4(89))
add("eth/IPv6/TCP", eth(ETH_V6) + ipv6(PROTO_TCP, payload_len=20) + tcp())
add("eth/IPv6/UDP dst 443", eth(ETH_V6) + ipv6(PROTO_UDP, payload_len=8) + udp(443))
add("eth/IPv6/other-nexthdr 89 (accept)", eth(ETH_V6) + ipv6(89))
add("eth/unknown ethertype 0x88b5 (accept, eth only)", eth(0x88B5) + b"\x00" * 20)

# --- 2. the IHL ladder ----------------------------------------------
add(
    "IPv4 ihl=6 (4B options)/TCP",
    eth(ETH_V4) + ipv4(PROTO_TCP, ihl=6, options=b"\x01" * 4, payload_len=20) + tcp(),
)
add(
    "IPv4 ihl=15 (40B options, the varbit max)/UDP dst 443",
    eth(ETH_V4) + ipv4(PROTO_UDP, ihl=15, options=b"\x02" * 40, payload_len=8) + udp(443),
)
add(
    "IPv4 ihl=6, options then other-proto 61 (accept after options)",
    eth(ETH_V4) + ipv4(61, ihl=6, options=b"\x03" * 4),
)
add("IPv4 ihl=4 (verify InvalidIPv4Header)", eth(ETH_V4) + ipv4(PROTO_TCP, ihl=4))
add("IPv4 ihl=0 (verify InvalidIPv4Header)", eth(ETH_V4) + ipv4(PROTO_TCP, ihl=0))
add("IPv4 version=6 (verify IPv4IncorrectVersion)", eth(ETH_V4) + ipv4(PROTO_TCP, version=6))
add(
    "IPv4 version=5 AND ihl=4 (version verify wins)",
    eth(ETH_V4) + ipv4(PROTO_TCP, version=5, ihl=4),
)
add(
    "IPv4 ihl=6 but only 2 of 4 option bytes (PacketTooShort in options)",
    (eth(ETH_V4) + ipv4(61, ihl=6, options=b"\x04" * 4))[:-2],
)

# --- 3. VXLAN -------------------------------------------------------
def vxlan_outer_v4() -> bytes:
    return eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=100) + udp(VXLAN_PORT, payload_len=92) + vxlan()


add(
    "VXLAN/customer eth/IPv4/TCP",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_TCP, payload_len=20) + tcp(),
)
add(
    "VXLAN/customer eth/IPv4/UDP dst 443",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=8) + udp(443),
)
add(
    "VXLAN/customer eth/IPv6/TCP",
    vxlan_outer_v4() + customer_eth(ETH_V6) + ipv6(PROTO_TCP, payload_len=20) + tcp(),
)
add(
    "VXLAN/customer eth/IPv6/UDP dst 443",
    vxlan_outer_v4() + customer_eth(ETH_V6) + ipv6(PROTO_UDP, payload_len=8) + udp(443),
)
add(
    "IPv6 outer/UDP 4789/VXLAN/customer eth/IPv4/UDP dst 443",
    eth(ETH_V6) + ipv6(PROTO_UDP, payload_len=100) + udp(VXLAN_PORT, payload_len=92)
    + vxlan() + customer_eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=8) + udp(443),
)
add(
    "VXLAN/customer eth unknown ethertype (accept)",
    vxlan_outer_v4() + customer_eth(0x88B5) + b"\x00" * 8,
)
add(
    "VXLAN/customer eth DASH sentinel 0x876d (NOT honored inner: accept)",
    vxlan_outer_v4() + customer_eth(ETH_DASH) + packet_meta(1),
)
add(
    "VXLAN/customer IPv4 ihl=6 (verify IPv4OptionsNotSupported)",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_TCP, ihl=6, options=b"\x05" * 4),
)
add(
    "VXLAN/customer IPv4 version=6 (verify IPv4IncorrectVersion)",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_TCP, version=6),
)
add(
    "VXLAN/customer UDP dst 4789 (no recursion: customer_udp accepts)",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=8)
    + udp(VXLAN_PORT),
)
add(
    "UDP src 4789, dst 443 (src port does not open VXLAN)",
    eth(ETH_V4) + ipv4(PROTO_UDP, payload_len=8) + udp(443, src=VXLAN_PORT),
)
add(
    "TCP dst 4789 (the quirk: VXLAN port on TCP stays plain TCP)",
    eth(ETH_V4) + ipv4(PROTO_TCP, payload_len=20) + tcp(dst=VXLAN_PORT),
)

# --- 4. the DASH packet-metadata sentinel ---------------------------
def dash(subtype: int, tail: bytes, *, source: int = 0, ptype: int = 0) -> bytes:
    return eth(ETH_DASH) + packet_meta(subtype, source=source, ptype=ptype) + tail


CUST_V4_TCP = customer_eth(ETH_V4) + ipv4(PROTO_TCP, payload_len=20) + tcp()
add("DASH subtype NONE/customer eth/IPv4/TCP", dash(0, CUST_V4_TCP))
add(
    "DASH subtype FLOW_CREATE: flow_key then customer",
    dash(1, flow_key() + CUST_V4_TCP),
)
add(
    "DASH subtype FLOW_UPDATE: flow_key then customer IPv6/UDP dst 443",
    dash(2, flow_key() + customer_eth(ETH_V6) + ipv6(PROTO_UDP, payload_len=8) + udp(443)),
)
add(
    "DASH FLOW_DELETE actions=0 (flow_data only)",
    dash(3, flow_key() + flow_data(0) + CUST_V4_TCP),
)
add(
    "DASH FLOW_DELETE actions=ENCAP_U0 (overlay + u0 encap)",
    dash(3, flow_key() + flow_data(1) + overlay_data() + encap_data(101) + CUST_V4_TCP),
)
add(
    "DASH FLOW_DELETE actions=ENCAP_U1 (overlay + u1 encap)",
    dash(3, flow_key() + flow_data(2) + overlay_data() + encap_data(102) + CUST_V4_TCP),
)
add(
    "DASH FLOW_DELETE actions=ENCAP_U0|ENCAP_U1 (overlay + both encaps)",
    dash(
        3,
        flow_key() + flow_data(3) + overlay_data() + encap_data(101) + encap_data(102)
        + CUST_V4_TCP,
    ),
)
add(
    "DASH FLOW_DELETE actions=SNAT (nonzero, no encap bits: overlay only)",
    dash(3, flow_key() + flow_data(1 << 4) + overlay_data() + CUST_V4_TCP),
)
add(
    "DASH subtype 7 (unknown: no flow headers, straight to customer)",
    dash(7, CUST_V4_TCP),
)
add(
    "DASH packet_type FLOW_SYNC_REQ, subtype NONE (type ignored by demux)",
    dash(0, CUST_V4_TCP, source=1, ptype=1),
)

# --- 5. the truncation ladder ---------------------------------------
add("eth cut mid-address (8B)", eth(ETH_V4)[:8])
add("eth cut before ethertype (13B)", eth(ETH_V4)[:13])
add("eth exact, IPv4 ethertype, zero L3 bytes", eth(ETH_V4))
add("IPv4 cut mid-header (10 of 20B)", eth(ETH_V4) + ipv4(PROTO_TCP)[:10])
add("IPv4 exact, proto TCP, zero L4 bytes", eth(ETH_V4) + ipv4(PROTO_TCP))
add("TCP cut (10 of 20B)", eth(ETH_V4) + ipv4(PROTO_TCP) + tcp()[:10])
add("UDP cut (4 of 8B)", eth(ETH_V4) + ipv4(PROTO_UDP) + udp(443)[:4])
add(
    "UDP exact dst 4789, zero VXLAN bytes",
    eth(ETH_V4) + ipv4(PROTO_UDP) + udp(VXLAN_PORT),
)
add(
    "VXLAN cut (5 of 8B)",
    eth(ETH_V4) + ipv4(PROTO_UDP) + udp(VXLAN_PORT) + vxlan()[:5],
)
add(
    "VXLAN exact, zero customer-eth bytes",
    eth(ETH_V4) + ipv4(PROTO_UDP) + udp(VXLAN_PORT) + vxlan(),
)
add("customer eth cut (6B)", vxlan_outer_v4() + customer_eth(ETH_V4)[:6])
add(
    "customer IPv4 cut (12 of 20B)",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_TCP)[:12],
)
add(
    "customer TCP cut (8 of 20B)",
    vxlan_outer_v4() + customer_eth(ETH_V4) + ipv4(PROTO_TCP) + tcp()[:8],
)
add(
    "customer IPv6 cut (20 of 40B)",
    vxlan_outer_v4() + customer_eth(ETH_V6) + ipv6(PROTO_TCP)[:20],
)
add("IPv6 cut (20 of 40B)", eth(ETH_V6) + ipv6(PROTO_TCP)[:20])
add("DASH packet_meta cut (2 of 4B)", eth(ETH_DASH) + packet_meta(0)[:2])
add("DASH packet_meta exact FLOW_CREATE, zero flow_key bytes", eth(ETH_DASH) + packet_meta(1))
add("DASH flow_key cut (20 of 46B)", eth(ETH_DASH) + packet_meta(1) + flow_key()[:20])
add(
    "DASH FLOW_DELETE flow_data cut (10 of 19B)",
    eth(ETH_DASH) + packet_meta(3) + flow_key() + flow_data(0)[:10],
)
add(
    "DASH FLOW_DELETE actions=3, overlay cut (30 of 75B)",
    eth(ETH_DASH) + packet_meta(3) + flow_key() + flow_data(3) + overlay_data()[:30],
)
add(
    "DASH FLOW_DELETE actions=3, u0 encap cut (10 of 26B)",
    eth(ETH_DASH) + packet_meta(3) + flow_key() + flow_data(3) + overlay_data()
    + encap_data(101)[:10],
)
add(
    "DASH FLOW_DELETE actions=3, u1 encap cut (12 of 26B)",
    eth(ETH_DASH) + packet_meta(3) + flow_key() + flow_data(3) + overlay_data()
    + encap_data(101) + encap_data(102)[:12],
)

# --- 6. adversarial -------------------------------------------------
add("empty packet", b"")
add("1-byte packet", b"\x00")
add("garbage (8B)", "deadbeefdeadbeef")
add("garbage (64B, unknown ethertype 0x1d1e)", bytes(range(0x11, 0x51)))

print("# dash_parser golden corpus — replayed through the instrumented DASH")
print("# BMv2 parser (sonic-net/DASH @ d5c003dd7774) on simple_switch by")
print("# benchmarks/industry/dash_parser/factory/capture.sh. Sections mirror")
print("# the charter's quirk grounds. A lone '-' line is the EMPTY packet.")
print("# Generated by mk_corpus.py (do not hand-edit).")
for desc, hexline in LINES:
    print(f"# --- {desc} ---")
    print(hexline)

print(f"{len(LINES)} entries", file=sys.stderr)

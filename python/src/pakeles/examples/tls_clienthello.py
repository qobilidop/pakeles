"""TLS ClientHello / SNI: the TLV flagship example.

One complete ClientHello in one TLS record in one contiguous buffer —
the assumption nginx ssl_preread and every eBPF SNI parser also makes.
Three nested sized regions (record -> handshake -> extensions) plus
two more inside the SNI extension (extension data -> server_name
list), a TLV loop over extensions driven by `remaining()`, and full
structural checks: an inner length lying about an outer one is a
structural reject, a buffer that simply ends early is a truncation
(rustls: `incomplete`).

Modeled checks mirror rustls's PARSE layer (the oracle,
examples/real_world/tls_clienthello/factory/): session_id > 32, empty/odd
cipher_suites, empty compressions, duplicate SNI, non-host_name SNI
entries, partial TLV headers, trailing bytes in any region. rustls's
POST-DECODE policy layer (missing signature_algorithms, ...) is
deliberately NOT modeled — those fire after a successful parse and
project as accept-class (see the design doc's laxness matrix).

Design: docs/superpowers/specs/2026-07-29-tls-clienthello-design.md.
"""

from pakeles import (
    Header,
    Meta,
    Parser,
    StateChain,
    assign,
    bits,
    const,
    extract,
    meta_bits,
    parser,
    reject,
    remaining,
    var_bytes,
)
from pakeles.fmt import DEC, HEX


class RecordHdr(Header):
    ctype = bits(8, "Content Type", HEX, labels={0x16: "handshake"})
    # Split major/minor so an exact select can express rustls's rule:
    # it accepts any 0x03xx record version and rejects everything else
    # (probed empirically — 0x0305 accepts, 0x0400 does not).
    ver_major = bits(8, "Legacy Record Version (major)", HEX)
    ver_minor = bits(8, "Legacy Record Version (minor)", HEX)
    rlen = bits(16, "Record Length", DEC)


class HandshakeHdr(Header):
    typ = bits(8, "Handshake Type", HEX, labels={0x01: "client_hello"})
    hlen = bits(24, "Handshake Length", DEC)


class BodyFixed(Header):
    ver = bits(16, "Legacy Version", HEX)
    random = var_bytes(const(32))


class SidLen(Header):
    slen = bits(8, "Session ID Length", DEC)


class Sid(Header):
    body = var_bytes(SidLen.slen)


class CsLen(Header):
    clen = bits(16, "Cipher Suites Length", DEC)


class Cs(Header):
    body = var_bytes(CsLen.clen)


class CompLen(Header):
    plen = bits(8, "Compression Methods Length", DEC)


class Comp(Header):
    body = var_bytes(CompLen.plen)


class ExtLen(Header):
    total = bits(16, "Extensions Length", DEC)


class Ext(Header):
    typ = bits(16, "Extension Type", HEX, labels={0: "server_name"})
    elen = bits(16, "Extension Length", DEC)


class Skip(Header):
    body = var_bytes(Ext.elen)


class SniList(Header):
    list_len = bits(16, "Server Name List Length", DEC)


class SniEntry(Header):
    ntype = bits(8, "Name Type", HEX, labels={0: "host_name"})
    hlen = bits(16, "Host Name Length", DEC)


class Host(Header):
    name = var_bytes(SniEntry.hlen)


class ChMeta(Meta):
    seen_sni = meta_bits(1, "SNI Seen", DEC, doc="duplicate-SNI detection")
    cs_odd = meta_bits(1, "Odd Cipher Length", DEC, doc="cipher_suites parity")


def tls_clienthello() -> Parser:
    return parser(
        "tls_clienthello",
        max_depth=96,
        metadata=ChMeta,
        start="s_record",
        states={
            # Record layer: 0x16 = handshake; the record length bounds
            # everything (pushed before the select fires, harmlessly so
            # on the reject arm).
            "s_record": extract(RecordHdr)
            .push_region(RecordHdr.rlen)
            .select(
                RecordHdr.ctype,
                {0x16: "s_recver"},
                default=reject("not a handshake record"),
            ),
            # rustls validates the record-layer version at parse time
            # (InvalidMessage(UnknownProtocolVersion)); found by symex
            # witness replay, not by the hand-written corpus.
            "s_recver": StateChain().select(
                RecordHdr.ver_major,
                {0x03: "s_hs"},
                default=reject("unsupported record version"),
            ),
            # Handshake header: 0x01 = client_hello; hlen must fit the
            # record (structural push check).
            "s_hs": extract(HandshakeHdr)
            .push_region(HandshakeHdr.hlen)
            .select(HandshakeHdr.typ, {0x01: "s_fixed"}, default=reject("not a client hello")),
            "s_fixed": extract(BodyFixed).then("s_sid_len"),
            # legacy_session_id: opaque <0..32>.
            "s_sid_len": extract(SidLen).select(
                SidLen.slen,
                {i: "s_sid" for i in range(33)},
                default=reject("session id too long"),
            ),
            "s_sid": extract(Sid).then("s_cs_len"),
            # cipher_suites: <2..2^16-2>, u16 list: nonzero and even.
            "s_cs_len": extract(CsLen)
            .assign(ChMeta.cs_odd, CsLen.clen & 1)
            .select(CsLen.clen, {0: reject("empty cipher suites")}, default="s_cs_parity"),
            "s_cs_parity": StateChain().select(
                ChMeta.cs_odd,
                {1: reject("odd cipher suites length")},
                default="s_cs",
            ),
            "s_cs": extract(Cs).then("s_comp_len"),
            # legacy_compression_methods: <1..2^8-1>.
            "s_comp_len": extract(CompLen).select(
                CompLen.plen, {0: reject("empty compressions")}, default="s_comp"
            ),
            "s_comp": extract(Comp).then("s_ext_check"),
            # Extensions are OPTIONAL: a handshake body ending here is a
            # legal pre-TLS-1.2 ClientHello. One stray byte cannot hold
            # the u16 extensions length.
            "s_ext_check": StateChain().select(
                remaining(),
                {0: "s_done_noext", 1: reject("partial extensions length")},
                default="s_ext_len",
            ),
            "s_ext_len": extract(ExtLen).push_region(ExtLen.total).then("s_tlv"),
            # The TLV loop head: bounded by max_depth (sole termination
            # authority); 1..3 bytes cannot hold a type+length header.
            "s_tlv": StateChain().select(
                remaining(),
                {
                    0: "s_done",
                    1: reject("partial extension header"),
                    2: reject("partial extension header"),
                    3: reject("partial extension header"),
                },
                default="s_ext",
            ),
            "s_ext": extract(Ext).select(
                (Ext.typ, ChMeta.seen_sni),
                {(0, 0): "s_sni", (0, 1): reject("duplicate sni")},
                default="s_skip",
            ),
            "s_skip": extract(Skip).then("s_tlv"),
            # SNI descends two more regions deep: extension data, then
            # the server_name list — every length is checked exactly.
            "s_sni": assign(ChMeta.seen_sni, 1)
            .push_region(Ext.elen)
            .then("s_sni_list"),
            "s_sni_list": extract(SniList).push_region(SniList.list_len).then("s_sni_entry"),
            "s_sni_entry": extract(SniEntry).select(
                SniEntry.ntype,
                {0: "s_host"},
                default=reject("unsupported sni name type"),
            ),
            # Exact pops: hostname must fill the list AND the extension.
            "s_host": extract(Host).pop_region().pop_region().then("s_tlv"),
            # Exact pops: extensions block, handshake body, record.
            "s_done": StateChain().pop_region().pop_region().pop_region().accept(),
            "s_done_noext": StateChain().pop_region().pop_region().accept(),
        },
    )


if __name__ == "__main__":
    print(tls_clienthello().to_json())

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
    ParserDef,
    StateChain,
    assign,
    bits,
    const,
    extract,
    meta_bits,
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


class TlsClienthello(ParserDef):
    max_depth = 96
    metadata = ChMeta

    def s_record(self) -> StateChain:
        """Record layer: 0x16 = handshake; the record length bounds
        everything (pushed before the select fires, harmlessly so on
        the reject arm)."""
        return (
            extract(RecordHdr)
            .push_region(RecordHdr.rlen)
            .select(
                RecordHdr.ctype,
                {0x16: self.s_recver},
                default=reject("not a handshake record"),
            )
        )

    def s_recver(self) -> StateChain:
        """rustls validates the record-layer version at parse time
        (InvalidMessage(UnknownProtocolVersion)); found by symex
        witness replay, not by the hand-written corpus."""
        return StateChain().select(
            RecordHdr.ver_major,
            {0x03: self.s_hs},
            default=reject("unsupported record version"),
        )

    def s_hs(self) -> StateChain:
        """Handshake header: 0x01 = client_hello; hlen must fit the
        record (structural push check)."""
        return (
            extract(HandshakeHdr)
            .push_region(HandshakeHdr.hlen)
            .select(HandshakeHdr.typ, {0x01: self.s_fixed}, default=reject("not a client hello"))
        )

    def s_fixed(self) -> StateChain:
        return extract(BodyFixed).then(self.s_sid_len)

    def s_sid_len(self) -> StateChain:
        """legacy_session_id: opaque <0..32>."""
        return extract(SidLen).select(
            SidLen.slen,
            {i: self.s_sid for i in range(33)},
            default=reject("session id too long"),
        )

    def s_sid(self) -> StateChain:
        return extract(Sid).then(self.s_cs_len)

    def s_cs_len(self) -> StateChain:
        """cipher_suites: <2..2^16-2>, u16 list: nonzero and even."""
        return (
            extract(CsLen)
            .assign(ChMeta.cs_odd, CsLen.clen & 1)
            .select(CsLen.clen, {0: reject("empty cipher suites")}, default=self.s_cs_parity)
        )

    def s_cs_parity(self) -> StateChain:
        return StateChain().select(
            ChMeta.cs_odd,
            {1: reject("odd cipher suites length")},
            default=self.s_cs,
        )

    def s_cs(self) -> StateChain:
        return extract(Cs).then(self.s_comp_len)

    def s_comp_len(self) -> StateChain:
        """legacy_compression_methods: <1..2^8-1>."""
        return extract(CompLen).select(
            CompLen.plen, {0: reject("empty compressions")}, default=self.s_comp
        )

    def s_comp(self) -> StateChain:
        return extract(Comp).then(self.s_ext_check)

    def s_ext_check(self) -> StateChain:
        """Extensions are OPTIONAL: a handshake body ending here is a
        legal pre-TLS-1.2 ClientHello. One stray byte cannot hold the
        u16 extensions length."""
        return StateChain().select(
            remaining(),
            {0: self.s_done_noext, 1: reject("partial extensions length")},
            default=self.s_ext_len,
        )

    def s_ext_len(self) -> StateChain:
        return extract(ExtLen).push_region(ExtLen.total).then(self.s_tlv)

    def s_tlv(self) -> StateChain:
        """The TLV loop head: bounded by max_depth (sole termination
        authority); 1..3 bytes cannot hold a type+length header."""
        return StateChain().select(
            remaining(),
            {
                0: self.s_done,
                1: reject("partial extension header"),
                2: reject("partial extension header"),
                3: reject("partial extension header"),
            },
            default=self.s_ext,
        )

    def s_ext(self) -> StateChain:
        return extract(Ext).select(
            (Ext.typ, ChMeta.seen_sni),
            {(0, 0): self.s_sni, (0, 1): reject("duplicate sni")},
            default=self.s_skip,
        )

    def s_skip(self) -> StateChain:
        return extract(Skip).then(self.s_tlv)

    def s_sni(self) -> StateChain:
        """SNI descends two more regions deep: extension data, then the
        server_name list — every length is checked exactly."""
        return assign(ChMeta.seen_sni, 1).push_region(Ext.elen).then(self.s_sni_list)

    def s_sni_list(self) -> StateChain:
        return extract(SniList).push_region(SniList.list_len).then(self.s_sni_entry)

    def s_sni_entry(self) -> StateChain:
        return extract(SniEntry).select(
            SniEntry.ntype,
            {0: self.s_host},
            default=reject("unsupported sni name type"),
        )

    def s_host(self) -> StateChain:
        """Exact pops: hostname must fill the list AND the extension."""
        return extract(Host).pop_region().pop_region().then(self.s_tlv)

    def s_done(self) -> StateChain:
        """Exact pops: extensions block, handshake body, record."""
        return StateChain().pop_region().pop_region().pop_region().accept()

    def s_done_noext(self) -> StateChain:
        return StateChain().pop_region().pop_region().accept()


if __name__ == "__main__":
    print(TlsClienthello.build().to_json())

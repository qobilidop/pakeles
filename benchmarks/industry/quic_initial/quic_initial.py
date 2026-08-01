"""QUIC v1 Initial long header: the varint example.

Models the cleartext part of the RFC 9000 §17.2 long header — first
byte, version, connection IDs, and for Initial packets the token
(varint length + bytes) and payload-length varint. Header protection
(RFC 9001 §5.4) covers only the first byte's low 4 bits and the packet
number, so everything modeled here is honestly observable on the wire;
the protected low bits are extracted but excluded from any agreement
claim. Referees: quiche (`Header::from_slice`, primary) and
quinn-proto (`ProtectedHeader::decode`, secondary) — see the design
doc and this example's README for the two-lane laxness matrix.

The reason this example exists: **QUIC varints size themselves** — the
top 2 bits of the first varint byte encode the total width (1/2/4/8
bytes). That sounds like new IR, but it reduces to existing
primitives: extract the 2-bit prefix as its own field, select into
four width arms, and compose the value `(v6 << k) | tail` inline
where it is needed (a `var_bytes` length for the token bytes, a
metadata assign for the observable value). No engine change — see
docs/plans/2026-07-31-quic-initial-charter.md for why that finding is
the point.

Boundaries (documented, not modeled): short-header DCID length is
out-of-band LB configuration; the Retry token ("rest minus 16-byte
tag") would need `remaining()-16` as a byte length, banned in v1;
version-negotiation lists are classified but not walked; QUIC v2.
"""

from pakeles import (
    Header,
    LabeledEnum,
    Metadata,
    Parser,
    State,
    assign,
    bits,
    extract,
    metadata_bits,
    reject,
    var_bytes,
)
from pakeles.fmt import DEC, HEX


class HeaderForm(LabeledEnum):
    SHORT = 0, "Short (1-RTT)"
    LONG = 1, "Long"


class LongType(LabeledEnum):
    """v1 long-header packet types (first byte bits 4-5)."""

    INITIAL = 0, "Initial"
    ZERO_RTT = 1, "0-RTT"
    HANDSHAKE = 2, "Handshake"
    RETRY = 3, "Retry"


class QuicVersion(LabeledEnum):
    NEGOTIATION = 0, "Version Negotiation"
    V1 = 1, "QUIC v1"


class VarintWidth(LabeledEnum):
    """Varint total width, encoded in the top 2 bits of its first byte."""

    W1 = 0, "1-byte"
    W2 = 1, "2-byte"
    W4 = 2, "4-byte"
    W8 = 3, "8-byte"


class PacketKind(LabeledEnum):
    """Classification recorded in metadata; 0 = never assigned."""

    UNCLASSIFIED = 0
    INITIAL = 1
    ZERO_RTT = 2
    HANDSHAKE = 3
    RETRY = 4
    VERSION_NEGOTIATION = 5
    UNKNOWN_VERSION = 6
    SHORT = 7


class FirstByte(Header):
    form = bits(1, "Header Form", labels=HeaderForm)
    fixed = bits(1, "Fixed Bit", doc="not enforced (quiche's stance; quinn rejects 0)")
    ty = bits(2, "Long Packet Type", labels=LongType, doc="meaningful when form=1")
    low = bits(4, "Type-Specific Bits", doc="under header protection - out of claim")


class Version(Header):
    v = bits(32, "Version", HEX, labels=QuicVersion)


class DcidLen(Header):
    ln = bits(8, "DCID Length", DEC, doc="v1 caps at 20 (RFC 9000 §17.2)")


class Dcid(Header):
    cid = var_bytes(DcidLen.ln)


class ScidLen(Header):
    ln = bits(8, "SCID Length", DEC, doc="v1 caps at 20 (RFC 9000 §17.2)")


class Scid(Header):
    cid = var_bytes(ScidLen.ln)


class OtherCids(Header):
    """Uncapped CIDs for non-v1 versions (quiche caps supported versions
    only; one header keeps the instance count at the verdict-bitmap
    16)."""

    dcid_len = bits(8, "DCID Length", DEC)
    dcid = var_bytes(dcid_len)
    scid_len = bits(8, "SCID Length", DEC)
    scid = var_bytes(scid_len)


class TokLead(Header):
    """First byte of the token-length varint (Initial only)."""

    prefix = bits(2, "Token Varint Width", labels=VarintWidth)
    v6 = bits(6, "Token Varint High Bits")


class Tok0(Header):
    body = var_bytes(TokLead.v6)


class Tok1(Header):
    t = bits(8, "Token Varint Tail")
    body = var_bytes((TokLead.v6 << 8) | t)


class Tok2(Header):
    t = bits(24, "Token Varint Tail")
    body = var_bytes((TokLead.v6 << 24) | t)


class Tok3(Header):
    t = bits(56, "Token Varint Tail")
    body = var_bytes((TokLead.v6 << 56) | t)


class LenLead(Header):
    """First byte of the payload-length varint."""

    prefix = bits(2, "Length Varint Width", labels=VarintWidth)
    v6 = bits(6, "Length Varint High Bits")


class Len1(Header):
    t = bits(8, "Length Varint Tail")


class Len2(Header):
    t = bits(24, "Length Varint Tail")


class Len3(Header):
    t = bits(56, "Length Varint Tail")


class QuicMeta(Metadata):
    kind = metadata_bits(3, "Packet Kind", doc="a PacketKind value")
    token_len = metadata_bits(64, "Token Length", DEC)
    length = metadata_bits(64, "Payload Length", DEC)


class QuicInitial(Parser):
    max_depth = 12
    metadata = QuicMeta

    def parse_first(self) -> State:
        """Header form bit routes short vs long; the rest of the first
        byte rides along (type bits meaningful only for long headers)."""
        return extract(FirstByte).select(
            FirstByte.form,
            {
                HeaderForm.SHORT: self.short_accept,
                HeaderForm.LONG: self.parse_version,
            },
            default=reject("unreachable: 1-bit key"),
        )

    def short_accept(self) -> State:
        """Classify-only: the short-header DCID length is out-of-band
        LB configuration (the katran-config-gate analog)."""
        return assign(QuicMeta.kind, PacketKind.SHORT).accept()

    def parse_version(self) -> State:
        """Version routes v1 (deep parse) vs VN vs unknown; RFC 8999
        invariants guarantee CIDs follow in every case."""
        return extract(Version).select(
            Version.v,
            {
                QuicVersion.V1: self.parse_dcid_len,
                QuicVersion.NEGOTIATION: self.vn_mark,
            },
            default=self.unknown_mark,
        )

    def vn_mark(self) -> State:
        """Version list deliberately not walked (quinn's stance; quiche
        walks it - documented divergence)."""
        return assign(QuicMeta.kind, PacketKind.VERSION_NEGOTIATION).then(
            self.parse_other_cids
        )

    def unknown_mark(self) -> State:
        """Unknown versions parse through (quiche's stance; quinn
        rejects with UnsupportedVersion after the CIDs)."""
        return assign(QuicMeta.kind, PacketKind.UNKNOWN_VERSION).then(
            self.parse_other_cids
        )

    def parse_other_cids(self) -> State:
        """Non-v1 CIDs are uncapped: quiche enforces the 20-byte cap
        only for versions it supports."""
        return extract(OtherCids).accept()

    def parse_dcid_len(self) -> State:
        """The v1 cap check sits between the length byte and the CID
        bytes, mirroring quiche's check-before-read order."""
        return extract(DcidLen).select(
            DcidLen.ln,
            {range(21): self.parse_dcid},
            default=reject("dcid too long for v1"),
        )

    def parse_dcid(self) -> State:
        return extract(Dcid).then(self.parse_scid_len)

    def parse_scid_len(self) -> State:
        return extract(ScidLen).select(
            ScidLen.ln,
            {range(21): self.parse_scid},
            default=reject("scid too long for v1"),
        )

    def parse_scid(self) -> State:
        """CIDs done; the long-type bits pick the tail grammar."""
        return extract(Scid).select(
            FirstByte.ty,
            {
                LongType.INITIAL: self.initial_mark,
                LongType.ZERO_RTT: self.zero_rtt_mark,
                LongType.HANDSHAKE: self.handshake_mark,
                LongType.RETRY: self.retry_accept,
            },
            default=reject("unreachable: 2-bit key"),
        )

    def initial_mark(self) -> State:
        return assign(QuicMeta.kind, PacketKind.INITIAL).then(self.parse_tok_lead)

    def zero_rtt_mark(self) -> State:
        """No token by grammar; straight to the length varint (quinn's
        parse extent - quiche stops after the SCID here)."""
        return assign(QuicMeta.kind, PacketKind.ZERO_RTT).then(self.parse_len_lead)

    def handshake_mark(self) -> State:
        return assign(QuicMeta.kind, PacketKind.HANDSHAKE).then(self.parse_len_lead)

    def retry_accept(self) -> State:
        """Classify-only: the Retry token is 'rest minus 16-byte tag',
        which needs remaining()-16 as a byte length - banned in v1
        (named boundary, see the charter)."""
        return assign(QuicMeta.kind, PacketKind.RETRY).accept()

    def parse_tok_lead(self) -> State:
        """The self-sizing varint, arm 1 of 2: token length. The 2-bit
        prefix is an ordinary fixed field; each width arm re-composes
        the value inline because var-width fields cannot cross the
        arms' join (see the design doc's three walls)."""
        return extract(TokLead).select(
            TokLead.prefix,
            {
                VarintWidth.W1: self.tok_w1,
                VarintWidth.W2: self.tok_w2,
                VarintWidth.W4: self.tok_w4,
                VarintWidth.W8: self.tok_w8,
            },
            default=reject("unreachable: 2-bit key"),
        )

    def tok_w1(self) -> State:
        return (
            extract(Tok0)
            .assign(QuicMeta.token_len, TokLead.v6)
            .then(self.parse_len_lead)
        )

    def tok_w2(self) -> State:
        return (
            extract(Tok1)
            .assign(QuicMeta.token_len, (TokLead.v6 << 8) | Tok1.t)
            .then(self.parse_len_lead)
        )

    def tok_w4(self) -> State:
        return (
            extract(Tok2)
            .assign(QuicMeta.token_len, (TokLead.v6 << 24) | Tok2.t)
            .then(self.parse_len_lead)
        )

    def tok_w8(self) -> State:
        return (
            extract(Tok3)
            .assign(QuicMeta.token_len, (TokLead.v6 << 56) | Tok3.t)
            .then(self.parse_len_lead)
        )

    def parse_len_lead(self) -> State:
        """The self-sizing varint, arm 2 of 2: payload length. Shared
        by Initial, 0-RTT, and Handshake (kind already in metadata);
        the value is observed, not consumed - parsing stops before the
        protected packet number."""
        return extract(LenLead).select(
            LenLead.prefix,
            {
                VarintWidth.W1: self.len_w1,
                VarintWidth.W2: self.len_w2,
                VarintWidth.W4: self.len_w4,
                VarintWidth.W8: self.len_w8,
            },
            default=reject("unreachable: 2-bit key"),
        )

    def len_w1(self) -> State:
        return assign(QuicMeta.length, LenLead.v6).accept()

    def len_w2(self) -> State:
        return (
            extract(Len1)
            .assign(QuicMeta.length, (LenLead.v6 << 8) | Len1.t)
            .accept()
        )

    def len_w4(self) -> State:
        return (
            extract(Len2)
            .assign(QuicMeta.length, (LenLead.v6 << 24) | Len2.t)
            .accept()
        )

    def len_w8(self) -> State:
        return (
            extract(Len3)
            .assign(QuicMeta.length, (LenLead.v6 << 56) | Len3.t)
            .accept()
        )


if __name__ == "__main__":
    print(QuicInitial.to_json())

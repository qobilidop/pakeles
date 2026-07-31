#!/usr/bin/env python3
"""Generate corpus.txt: the quic_initial golden corpus.

Fully deterministic (no randomness anywhere). Sections mirror the
design doc's corpus matrix
(docs/designs/2026-07-31-quic-initial-design.md):

  1. RFC 9001 Appendix A "Client Initial" — the real-world anchor
     (the full 1200-byte protected datagram, embedded verbatim).
  2. The Initial grid: dcid_len {0,8,20} x scid_len {0,5} x token_len
     varint width {1,2,4,8} x length varint width {1,2,4,8}. Widths
     >1 for the small canonical values (token 5, length 18) are the
     NON-minimal encodings the design wants exercised; width 1 is the
     minimal one. Minimal-at-width and token-value-0 get their own
     sweeps below.
  3. Kind sweep: Handshake, 0-RTT, Retry (>=16 and <16 tail bytes),
     VN (list of 2, empty list, trailing-not-div-4), Short.
  4. Version cases: 0xdeadbeef, draft-29 0xff00001d (unknown to
     quiche 0.29.3 — verified at mint), fixed-bit-clear.
  5. CID cap: dcid_len/scid_len 21 (full buffer AND truncated),
     for v1 and for uncapped versions (VN / unknown).
  6. Truncation ladder over a canonical Initial: cut at every field
     boundary and inside every varint.
  7. Adversarial: garbage, empty, 1-byte packets.

A lone "-" line means the EMPTY packet (blank lines are skipped as
formatting by the factory; "-" is the explicit marker).

Regenerate: python3 mk_corpus.py > corpus.txt
"""

# RFC 9001 Appendix A.2, "The resulting protected packet is:" — the
# 1200-byte protected client Initial (unprotected header fields:
# version 1, dcid 8394c8f03e515708, scid empty, token empty,
# length 1182 = 0x449e). Header parsing needs no key material.
RFC9001_CLIENT_INITIAL = (
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123"
    "dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b3"
    "1f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1f"
    "c8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89"
    "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf"
    "012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5"
    "a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7ba"
    "d1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e8"
    "46d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63"
    "ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d50"
    "8b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7"
    "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec"
    "281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c481"
    "9e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699d"
    "bfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef"
    "2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f254101"
    "0ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f71"
    "9595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd"
    "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705"
    "769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d06"
    "9fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb"
    "5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f35"
    "5e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db"
    "82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8f"
    "a9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723"
    "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b627"
    "9ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852"
    "44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f"
    "5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44"
    "860018ab0856972e194cd934"
)
assert len(RFC9001_CLIENT_INITIAL) == 2400  # 1200 bytes


def varint(value: int, width: int | None = None) -> bytes:
    """RFC 9000 §16 variable-length integer. `width` in {1,2,4,8}
    forces the encoding width (non-minimal when the value would fit a
    narrower one — legal, and deliberately exercised)."""
    if width is None:
        width = next(w for w in (1, 2, 4, 8) if value < 1 << (8 * w - 2))
    assert width in (1, 2, 4, 8) and value < 1 << (8 * width - 2)
    prefix = {1: 0b00, 2: 0b01, 4: 0b10, 8: 0b11}[width]
    b = bytearray(value.to_bytes(width, "big"))
    b[0] |= prefix << 6
    return bytes(b)


def long_hdr(
    ty: int,
    version: int = 1,
    dcid: bytes = b"\x11" * 8,
    scid: bytes = b"\x22" * 5,
    first: int | None = None,
    dcid_len: int | None = None,
    scid_len: int | None = None,
) -> bytes:
    """Long-header spine: first byte (form|fixed|ty; low bits 0),
    version, dcid_len+dcid, scid_len+scid. `first` overrides the
    whole first byte; `dcid_len`/`scid_len` override the length BYTES
    (for cap/truncation lies)."""
    if first is None:
        first = 0x80 | 0x40 | (ty << 4)
    out = bytes([first]) + version.to_bytes(4, "big")
    out += bytes([len(dcid) if dcid_len is None else dcid_len]) + dcid
    out += bytes([len(scid) if scid_len is None else scid_len]) + scid
    return out


def initial(
    dcid: bytes = b"\x11" * 8,
    scid: bytes = b"\x22" * 5,
    token: bytes = b"\x33" * 5,
    tok_w: int | None = None,
    length: int = 18,
    len_w: int | None = None,
    payload: bytes | None = None,
    version: int = 1,
    first: int | None = None,
) -> bytes:
    """Initial = spine + token varint + token bytes + length varint +
    payload (defaults to `length` bytes of 0x00 — pn/ciphertext
    stand-in; header validity needs no crypto)."""
    if payload is None:
        payload = b"\x00" * length
    return (
        long_hdr(0x0, version=version, dcid=dcid, scid=scid, first=first)
        + varint(len(token), tok_w)
        + token
        + varint(length, len_w)
        + payload
    )


LINES: list[tuple[str, str]] = []


def add(desc: str, pkt: bytes | str) -> None:
    if isinstance(pkt, bytes):
        pkt = pkt.hex() if pkt else "-"
    LINES.append((desc, pkt))


# --- 1. real-world anchor -------------------------------------------
add(
    "RFC 9001 Appendix A client Initial (protected datagram, 1200 B)",
    RFC9001_CLIENT_INITIAL,
)

# --- 2. the Initial grid --------------------------------------------
# token value fixed at 5 bytes, length fixed at 18 (+18 payload);
# widths >1 are therefore non-minimal encodings of those values.
for dlen in (0, 8, 20):
    for slen in (0, 5):
        for tok_w in (1, 2, 4, 8):
            for len_w in (1, 2, 4, 8):
                add(
                    f"grid Initial dcid={dlen} scid={slen} "
                    f"tok_w={tok_w}{'(min)' if tok_w == 1 else '(nonmin)'} "
                    f"len_w={len_w}{'(min)' if len_w == 1 else '(nonmin)'}",
                    initial(
                        dcid=b"\x11" * dlen,
                        scid=b"\x22" * slen,
                        tok_w=tok_w,
                        len_w=len_w,
                    ),
                )

# token value 0 at every width (design: "incl. value 0"; widths >1
# are non-minimal zero).
for tok_w in (1, 2, 4, 8):
    add(
        f"Initial token_len=0 at width {tok_w}",
        initial(token=b"", tok_w=tok_w),
    )

# minimal-at-width contrast: width-2 varints whose values REQUIRE
# width 2 (>= 64), for both positions.
add("Initial token_len=64 minimal width-2", initial(token=b"\x44" * 64, tok_w=2))
add("Initial length=64 minimal width-2", initial(length=64, len_w=2))
# minimal width-4 length (16384) with payload ABSENT: neither oracle
# checks the length value against the remaining buffer at header-parse
# time (quiche never reads length; quinn reads the varint only).
add("Initial length=16384 minimal width-4, payload absent", initial(length=16384, len_w=4, payload=b""))

# --- 3. kind sweep --------------------------------------------------
# Handshake / 0-RTT: no token by grammar; length + payload follow.
add("Handshake, length=18", long_hdr(0x2) + varint(18) + b"\x00" * 18)
add("Handshake, length=18 non-minimal width-4", long_hdr(0x2) + varint(18, 4) + b"\x00" * 18)
add("0-RTT, length=18", long_hdr(0x1) + varint(18) + b"\x00" * 18)
add("0-RTT, length=18 non-minimal width-2", long_hdr(0x1) + varint(18, 2) + b"\x00" * 18)
# Retry: tail = token + 16-byte integrity tag (quiche splits it;
# quinn exposes neither).
add("Retry, 7-byte token + 16-byte tag", long_hdr(0x3) + b"\x55" * 7 + b"\x66" * 16)
add("Retry, tail exactly 16 (empty token)", long_hdr(0x3) + b"\x66" * 16)
add("Retry, tail 10 (<16: quiche InvalidPacket; quinn still Ok)", long_hdr(0x3) + b"\x66" * 10)
# VN: version 0; quiche walks the list, quinn does not.
add(
    "VN, list [v1, draft-29]",
    long_hdr(0x0, version=0) + bytes.fromhex("00000001") + bytes.fromhex("ff00001d"),
)
add("VN, empty list", long_hdr(0x0, version=0))
add(
    "VN, trailing 2 bytes (list not div-4: quiche BufferTooShort)",
    long_hdr(0x0, version=0) + bytes.fromhex("00000001") + b"\xaa\xbb",
)
add("VN, type nibble 3 (ignored: version 0 wins)", long_hdr(0x3, version=0) + bytes.fromhex("00000001"))
# Short: classify-only (dcid_len is out-of-band config; factory uses 0).
add("Short header, fixed bit set, 8 tail bytes", b"\x40" + b"\x77" * 8)
add("Short header, spin bit set", b"\x60" + b"\x77" * 8)

# --- 4. version cases -----------------------------------------------
add("Initial-type nibble, version 0xdeadbeef", initial(version=0xDEADBEEF))
add(
    "Initial-type nibble, version draft-29 0xff00001d (unknown to quiche 0.29.3)",
    initial(version=0xFF00001D),
)
add(
    "Handshake-type nibble, version 0xdeadbeef (quiche stops after scid)",
    long_hdr(0x2, version=0xDEADBEEF) + varint(18) + b"\x00" * 18,
)
add(
    "Retry-type nibble, version 0xdeadbeef",
    long_hdr(0x3, version=0xDEADBEEF) + b"\x55" * 7 + b"\x66" * 16,
)
add("fixed-bit-clear Initial (first=0x80: quiche Ok, quinn err)", initial(first=0x80))
add("fixed-bit-clear Short (first=0x00)", b"\x00" + b"\x77" * 8)

# --- 5. CID caps ----------------------------------------------------
add(
    "v1 dcid_len=21, full buffer",
    initial(dcid=b"\x11" * 21),
)
add(
    "v1 dcid_len=21, truncated (only 4 cid bytes present)",
    long_hdr(0x0, dcid=b"\x11" * 4, dcid_len=21, scid=b""),
)
add("v1 scid_len=21, full buffer", initial(scid=b"\x22" * 21))
add(
    "VN dcid_len=21 (uncapped in quiche; quinn caps all versions)",
    long_hdr(0x0, version=0, dcid=b"\x11" * 21, scid=b"") + bytes.fromhex("00000001"),
)
add(
    "unknown-version dcid_len=21 + empty token (uncapped in quiche)",
    long_hdr(0x0, version=0xDEADBEEF, dcid=b"\x11" * 21, scid=b"") + varint(0),
)

# --- 6. truncation ladder -------------------------------------------
# Canonical Initial: dcid 8, scid 5, token varint WIDTH 2 (value 5) +
# 5 token bytes, length varint width 2 (value 18) + 18 payload bytes.
# Offsets: first 0 | version 1..5 | dcid_len 5 | dcid 6..14 |
# scid_len 14 | scid 15..20 | tok varint 20..22 | token 22..27 |
# len varint 27..29 | payload 29..47.
CANON = initial(tok_w=2, len_w=2)
assert len(CANON) == 47
for cut, what in [
    (1, "after first byte (version absent)"),
    (3, "inside version"),
    (5, "after version (dcid_len absent)"),
    (6, "after dcid_len (dcid bytes absent)"),
    (10, "inside dcid"),
    (14, "after dcid (scid_len absent)"),
    (15, "after scid_len (scid bytes absent)"),
    (17, "inside scid"),
    (20, "after scid (token varint absent)"),
    (21, "inside token-length varint (lead byte only)"),
    (22, "after token varint (token bytes absent)"),
    (24, "inside token bytes"),
    (27, "after token (length varint absent)"),
    (28, "inside length varint (lead byte only)"),
    (29, "after length varint (payload absent — header complete)"),
    (34, "inside payload (header complete)"),
]:
    add(f"ladder cut@{cut}: {what}", CANON[:cut])

# --- 7. adversarial -------------------------------------------------
add("empty packet", b"")
add("1-byte long-form 0xc0 (version absent)", b"\xc0")
add("1-byte long-form 0x80 (fixed clear: quiche BufferTooShort, quinn fixed-bit err)", b"\x80")
add("1-byte short-form 0x40 (both Ok at dcid_len 0)", b"\x40")
add("1-byte 0x00 (short, fixed clear)", b"\x00")
add("garbage", "deadbeefdeadbeef")
add("all-zeros 16 bytes (short, fixed clear)", b"\x00" * 16)

print("# quic_initial golden corpus — replayed against quiche (primary) and")
print("# quinn-proto (secondary) by examples/real_world/quic_initial/factory/")
print("# capture.sh. Sections mirror the design doc's corpus matrix")
print("# (docs/designs/2026-07-31-quic-initial-design.md). A lone '-' line is")
print("# the EMPTY packet. Generated by mk_corpus.py (do not hand-edit).")
for desc, hexline in LINES:
    print(f"# --- {desc} ---")
    print(hexline)
import sys

print(f"{len(LINES)} entries", file=sys.stderr)

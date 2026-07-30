#!/usr/bin/env python3
"""Generate corpus.txt: the tls_clienthello golden corpus.

Deterministic except for MINTED_TLS13 (a genuine rustls first flight,
minted once via `cargo run -- mint pakeles.example` at rustls 0.23.43
and embedded here — key_share/random make minting non-reproducible).
Sections mirror the design doc's corpus matrix
(docs/superpowers/specs/2026-07-29-tls-clienthello-design.md); several
lines are byte-identical twins of src/oracle/tls_clienthello.rs
project_tests.

Regenerate: python3 mk_corpus.py > corpus.txt
"""

MINTED_TLS13 = (
    "16030100ed010000e903030ae7377d7158fd3544eede42ecc3749325c30a32bf08ab2226"
    "b026a3c25c553d20efcc5bfa7a0581addc7f3c27826c1bfedef3164583f62a54f7ed018a"
    "d64f04d10014130213011303c02cc02bcca9c030c02fcca800ff0100008c000d00140012"
    "05030403080708060805080406010501040100000014001200000f70616b656c65732e65"
    "78616d706c65003300260024001d0020dd361189c93756458d763831a6d6aefbbea50810"
    "ae38eeb8d077a5c8fb60c76200230000002b00050403040303000500050100000000000a"
    "00080006001d00170018002d00020101000b0002010000170000"
)


def ch(
    suites,
    exts,
    compression=b"\x00",
    sid=b"",
    ver=b"\x03\x03",
    cs_raw: bytes | None = None,
    ext_raw: bytes | None = None,
):
    """Assemble a ClientHello. `exts` = list of (type, data) or None for
    the extensionless wire form; `cs_raw`/`ext_raw` override the
    cipher_suites vector / extensions block verbatim (length included)
    for malformed cases."""
    body = ver + b"\x11" * 32
    body += bytes([len(sid)]) + sid
    if cs_raw is not None:
        body += cs_raw
    else:
        cs = b"".join(s.to_bytes(2, "big") for s in suites)
        body += len(cs).to_bytes(2, "big") + cs
    body += bytes([len(compression)]) + compression
    if ext_raw is not None:
        body += ext_raw
    elif exts is not None:
        eb = b"".join(
            t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in exts
        )
        body += len(eb).to_bytes(2, "big") + eb
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def sni(host):
    entry = b"\x00" + len(host).to_bytes(2, "big") + host.encode()
    return (0, len(entry).to_bytes(2, "big") + entry)


def sig_algs():
    schemes = [0x0403, 0x0804, 0x0401]
    body = b"".join(s.to_bytes(2, "big") for s in schemes)
    return (0x000D, len(body).to_bytes(2, "big") + body)


def with_record_len_delta(pkt: bytes, delta: int, tail: bytes = b"") -> bytes:
    """Rewrite the record length by `delta` and append `tail`."""
    return pkt[:3] + (len(pkt) - 5 + delta).to_bytes(2, "big") + pkt[5:] + tail


def with_ext_block_len_delta(pkt: bytes, delta: int) -> bytes:
    """Rewrite the extensions-block length field (fixed offset 50 for
    the empty-sid, one-suite shape used below)."""
    b = bytearray(pkt)
    off = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1  # = 50
    b[off : off + 2] = (int.from_bytes(b[off : off + 2], "big") + delta).to_bytes(
        2, "big"
    )
    return bytes(b)


BASE = ch([0xC02F], [sni("a.test"), sig_algs()])
MINIMAL = ch([0xC02F], [sni("a.test")])
NOEXT = ch([0xC02F], None)

LINES: list[tuple[str, str]] = []


def add(desc: str, pkt: bytes | str) -> None:
    LINES.append((desc, pkt if isinstance(pkt, str) else pkt.hex()))


# --- accepts (parse-level; some are rustls policy rejects -> the
# --- PeerIncompatible laxness cell of the matrix) ---
add("policy-complete TLS1.2 CH: SNI + signature_algorithms", BASE)
add(
    "GREASE cipher 0x0a0a + GREASE ext 0x1a1a + SNI + sig_algs",
    ch([0x0A0A, 0xC02F], [(0x1A1A, b""), sni("a.test"), sig_algs()]),
)
add("policy-complete, NO SNI", ch([0xC02F], [sig_algs()]))
add("rustls-minted TLS1.3 first flight (SNI pakeles.example)", MINTED_TLS13)
# NB: rustls DECODES the bodies of extensions it knows (a zero-filled
# supported_versions is TrailingData) — a quirk-catalog fact. The
# filler here is therefore GREASE/unknown types (skipped raw) plus
# padding (type 21), whose all-zero body is genuinely valid.
add(
    "browser-shaped: 17 extensions, SNI in the middle, GREASE, padding",
    ch(
        [0x0A0A, 0x1301, 0x1302, 0xC02F, 0xC030],
        [(0x3A3A, b"")]
        + [
            (t, b"\x00" * 4)
            for t in (0x2A2A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A)
        ]
        + [sni("browser.example"), sig_algs()]
        + [(t, b"\x01" * 6) for t in (0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA)]
        + [(0x0015, b"\x00" * 64)],
    ),
)
add("empty extensions block (len 0)", ch([0xC02F], []))
add("extensions block ABSENT (legal pre-TLS-1.2 wire form)", NOEXT)
add(
    "session_id exactly 32 bytes",
    ch([0xC02F], [sni("a.test"), sig_algs()], sid=b"\x22" * 32),
)
add("one-byte SNI hostname", ch([0xC02F], [sni("a"), sig_algs()]))

# --- structural rejects ---
add("garbage", "deadbeefdeadbeef")
add("content type 0x17 (application data)", b"\x17" + BASE[1:])
add("handshake type 0x02 (server hello)", BASE[:5] + b"\x02" + BASE[6:])
add(
    "duplicate SNI extension",
    ch([0xC02F], [sni("a.test"), sni("b.test"), sig_algs()]),
)
add(
    "session_id length 33",
    ch([0xC02F], [sni("a.test"), sig_algs()], sid=b"\x22" * 33),
)
add(
    "SNI entry name_type=1",
    ch([0xC02F], [(0, b"\x00\x09\x01\x00\x06" + b"a.test"), sig_algs()]),
)
add(
    "SNI list_len lies short (hostname crosses the list end)",
    ch([0xC02F], [(0, b"\x00\x05\x00\x00\x06" + b"a.test"), sig_algs()]),
)
add(
    "last ext len claims more than the extensions block holds",
    # sig_algs header claims 0x0009 data bytes; the block ends after 8.
    BASE[:-12] + b"\x00\x0d\x00\x09" + BASE[-8:],
)
add(
    "extensions block shorter than the handshake body (trailing bytes)",
    # Block length shrunk by sig_algs's 12 bytes: they become trailing
    # content inside the handshake body.
    with_ext_block_len_delta(BASE, -12),
)
add(
    "record trailing byte (record len +1, stray 0xff)",
    with_record_len_delta(MINIMAL, 1, b"\xff"),
)
add(
    "odd cipher_suites length",
    ch([], [sni("a.test")], cs_raw=b"\x00\x03\xc0\x2f\xee"),
)
add("zero cipher_suites length", ch([], [sni("a.test"), sig_algs()]))
add(
    "empty compressions",
    ch([0xC02F], [sni("a.test"), sig_algs()], compression=b""),
)
add(
    "one stray byte where the extensions length should start",
    # hs body ends one byte after compressions: remaining()==1.
    ch([0xC02F], None, ext_raw=b"\xaa"),
)
add(
    "partial TLV header: 2 bytes left in the extensions block",
    ch([0xC02F], None, ext_raw=b"\x00\x02\xaa\xbb"),
)

# --- truncations (rustls: incomplete) ---
add("cut inside the record header", BASE[:3])
add("cut inside the handshake header", BASE[:7])
add("cut inside random", BASE[:20])
# Offsets: rec(5) + hs(4) + ver(2) + random(32) = 43; sid_len at 43.
add(
    "cut inside session_id body",
    ch([0xC02F], [sni("a.test")], sid=b"\x22" * 8)[:48],
)
add("cut inside cipher_suites body", BASE[:47])
add("cut inside the SNI hostname", BASE[: len(BASE) - 14])
add(
    "record len declares 2 more bytes than sent",
    with_record_len_delta(MINIMAL, 2),
)

print("# tls_clienthello golden corpus — replayed against rustls's Acceptor by")
print("# oracle/tls_clienthello/factory/capture.sh. Sections mirror the design")
print("# doc's matrix; several lines are twins of src/oracle/tls_clienthello.rs")
print("# project_tests. Generated by mk_corpus.py (do not hand-edit).")
for desc, hexline in LINES:
    print(f"# --- {desc} ---")
    print(hexline)

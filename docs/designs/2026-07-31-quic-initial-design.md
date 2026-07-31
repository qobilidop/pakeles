# quic_initial design-lite (binding)

Companion to `docs/plans/2026-07-31-quic-initial-charter.md`. The
Phase-2 spike passed: the two-field varint split runs through
validator + lint + interp + symex (19 path vectors, all four width
arms) + C/eBPF codegen with zero engine changes. This doc fixes the
state map, projection, and laxness before the example is built.

## State map

Shared spine, then per-kind arms. `M.kind` (metadata, LabeledEnum
`PacketKind`) carries the classification so shallow arms can share
states.

```
parse_first:    extract FirstByte{form:1, fixed:1, ty:2, low:4}
                select form: 0 -> short_accept ; 1 -> parse_version
parse_version:  extract Version{v:32}
                select v: 1 -> v1_dcid_len
                          0 -> vn_mark        (assign kind=VN)
                          default -> unk_mark (assign kind=UNKNOWN_VERSION)
vn_mark/unk_mark: -> other_dcid  (shared uncapped path)
other_dcid:     extract OtherDcid{ln:8, cid:var_bytes(ln)} -> other_scid
other_scid:     extract OtherScid{ln:8, cid:var_bytes(ln)} -> accept
v1_dcid_len:    extract DcidLen{ln:8}
                select ln: 0..=20 -> v1_dcid ; default -> reject (cid cap)
v1_dcid:        extract Dcid{cid:var_bytes(DcidLen.ln)} -> v1_scid_len
v1_scid_len:    extract ScidLen{ln:8}
                select ln: 0..=20 -> v1_scid ; default -> reject (cid cap)
v1_scid:        extract Scid{cid:var_bytes(ScidLen.ln)}
                select FirstByte.ty: 0 -> initial_mark
                                     1 -> zrtt_mark   (kind=ZERO_RTT)
                                     2 -> hs_mark     (kind=HANDSHAKE)
                                     3 -> retry_accept(kind=RETRY)
initial_mark:   assign kind=INITIAL -> tok_lead
tok_lead:       extract TokLead{prefix:2, v6:6}
                select prefix -> tok_arm0..3
tok_arm0:       extract Tok0{body:var_bytes(TokLead.v6)}
                assign token_len=TokLead.v6            -> len_lead
tok_armK (K=1,2,3): extract TokK{t:8/24/56,
                    body:var_bytes((TokLead.v6<<8K)|t)}
                assign token_len=(TokLead.v6<<8K)|t    -> len_lead
zrtt_mark/hs_mark: assign kind -> len_lead   (shared length cluster)
len_lead:       extract LenLead{prefix:2, v6:6}
                select prefix -> len_arm0..3
len_armK:       extract LenK{t} ; assign length=value  -> accept
```

~24 states; deepest path (Initial) enters 11 states → `max_depth = 12`.
Well inside the eBPF unroll budget (tls_clienthello: 96 states,
clean ≤ depth 22).

Decisions locked:

- **v1 CID cap modeled with split len/cid headers** (check between
  length byte and cid bytes) so a `ln>20` packet rejects structurally
  before reading cid bytes, mirroring quiche's check order.
- **VN + unknown versions parse CIDs uncapped** on a shared path
  (quiche caps only supported versions; v1 is its only supported
  version at the pin). VN's version list is NOT walked (quinn's
  stance; quiche divergence documented in the quirk catalog).
- **Handshake / 0-RTT route into the shared length cluster** (matches
  quinn's parse extent; quiche stops after SCID for these — union
  extent per charter). Their token is absent by grammar, correct.
- **Retry is classify-only** (`retry_accept` directly after SCID):
  its token is "rest minus 16-byte tag", which needs `remaining()-16`
  as a byte length — v1-banned in `byte_len`. Named boundary; quiche's
  parsed Retry token is NOT compared (laxness row).
- **Short header is classify-only** (form bit): DCID length is LB
  config, the katran-config-gate analog.
- **Fixed bit extracted, not enforced** (quiche's stance; quinn lane
  expected-divergence).
- **First-byte low 4 bits** (reserved + pn-len for long headers)
  extracted as `low:4` but excluded from projection — under header
  protection (RFC 9001 §5.4); neither oracle exposes them.
- **Both varint values land in metadata** (`token_len`, `length`);
  token BYTES are additionally consumed as `var_bytes` so the cursor
  is honest and the bytes are comparable against quiche's token.
- **Non-minimal varints accepted** (RFC 9000 §16 permits them except
  where a spec says otherwise; octets/quiche/quinn all accept them
  in these positions). Corpus exercises them.

## Projection & laxness

```rust
enum OurClass {
  Parsed { kind, version: u32, dcid: Vec<u8>, scid: Vec<u8>,
           token: Option<Vec<u8>>, length: Option<u64> },
  Truncation,        // interp reject "out of bounds"
  Structural(String) // any other reject (cid cap, unreachable arms)
}
```

`kind` from `M.kind`; `dcid`/`scid` from whichever cid instance the
path extracted; `token` only when kind=INITIAL; `length` only when
the path reached the length cluster (INITIAL/ZERO_RTT/HANDSHAKE).

**Primary lane (quiche, the agreement claim).** Compatible iff:

| quiche | ours | compare |
|---|---|---|
| Ok(Initial) | Parsed{INITIAL} | version, dcid, scid, token bytes == |
| Ok(Handshake/ZeroRTT) | Parsed{same kind} | version, dcid, scid == (quiche has no length here — ours uncompared) |
| Ok(Retry) | Parsed{RETRY} | version, dcid, scid ==; token UNCOMPARED (named boundary) |
| Ok(VersionNegotiation) | Parsed{VN} | dcid, scid ==; versions list uncompared |
| Ok(Short) | Parsed{SHORT} | nothing beyond kind (dcid needs config) |
| Ok(ty) with unsupported version | Parsed{UNKNOWN_VERSION} | version, dcid, scid == (quiche's v1-bit type reading uncompared) |
| Err(BufferTooShort) | Truncation | class only |
| Err(InvalidPacket) | Structural | class only |

Any other pairing is a mismatch. NOTE the length-field asymmetry:
quiche never parses `length`, so the primary lane never compares it —
the quinn lane does.

**Secondary lane (quinn-proto, expected-divergence table).** Same
comparison, EXCEPT entries matching a divergence rule assert the
DIVERGENT outcome (a rule that stops firing is itself a test
failure — divergences are pinned, not ignored):

1. fixed bit clear → quinn `InvalidHeader("fixed bit unset")`, we
   Parsed (quiche agrees with us).
2. unsupported version (≠1, ≠0) → quinn `UnsupportedVersion`, we
   Parsed{UNKNOWN_VERSION}.
3. quinn enforces the CID cap for ALL versions → VN/unknown packets
   with ln>20 diverge (we parse, quinn rejects).
4. Initial/HS/0-RTT: quinn's `len` must equal our `length` (the one
   field ONLY this lane checks). Token via `token_pos` slice == ours.
5. Retry: quinn exposes no token — kind/cids/version only.
6. Short: quinn needs dcid_len config; factory passes 0 — kind only.

## Corpus matrix (mk_corpus.py, structural generator — header
validity needs no crypto; payload/pn bytes are free garbage)

- RFC 9001 A.1 client Initial (the real-world anchor, full 1200 B).
- Grid: {Initial} × dcid_len {0, 8, 20} × scid_len {0, 5} ×
  token_len varint width {1,2,4,8} (incl. value 0) × length varint
  width {1,2,4,8} × minimal/non-minimal encodings.
- Handshake, 0-RTT, Retry (with ≥16 and <16 tail bytes), VN
  (list of 2, empty list, trailing-not-÷4), Short, version=0xdeadbeef,
  version=draft-29 (0xff00001d: unknown to quiche 0.29.3 — verify at
  mint), fixed-bit-clear Initial, dcid_len 21 (full buffer AND
  truncated), garbage, empty, 1-byte packets.
- Truncation ladder over a canonical Initial: cut at every field
  boundary and inside every varint (lead byte present, tail missing;
  token bytes short; length tail short).
- Floor: ≥ 60 entries, all minted through the factory only.

## Factory

`examples/real_world/quic_initial/factory/` — excluded crate, pinned
lock: quiche 0.29.3, quinn-proto 0.11.16, octets 0.3.6, ALL
`default-features = false`. Reads corpus hex lines, emits one golden
JSON entry per input: `{hex, quiche: {...}|{err}, quinn: {...}|{err}}`.
Golden: `conformance/initial.quiche-0.29.3.golden.json` (primary pin
in the name; quinn pin recorded in the file header). `capture.sh`
greps both pins from Cargo.lock. Smoke = the probe's differential
table reproduced in-container.

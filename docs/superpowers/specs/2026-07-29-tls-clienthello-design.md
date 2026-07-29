# `tls_clienthello` — Example Design (binding)

**Status:** design, binding for Phase 5 of the TLS ClientHello run
(charter: `docs/plans/2026-07-29-tls-clienthello-charter.md`).
**Incumbent pin:** rustls 0.23.43 (factory `Cargo.lock`); oracle =
the public `Acceptor` API via `oracle/tls_clienthello/factory/`.
**IR slice:** sized regions + remaining()
(`2026-07-29-sized-region-tlv-ir-design.md`, incl. build-time
refinements).

## Scope

One complete ClientHello in one TLS record in one contiguous buffer —
the same assumption nginx ssl_preread and every eBPF SNI parser makes.
Modeled: record header, handshake header, all ClientHello body fields,
the full extensions TLV walk, SNI (type 0) to hostname depth with both
nested regions (extension data AND server_name_list). All other
extension types: type+length+skip.

**Boundaries (documented, not modeled):** cross-record fragmentation
(rustls: buffers more; us: read truncation), TCP stream reassembly,
ECH (the visible SNI is a decoy — semantic note, the QUIC-config-gate
analog), everything after the ClientHello, and rustls's POST-DECODE
policy layer (`PeerIncompatible(*)`: missing signature_algorithms,
null-compression requirements — those fire after a successful parse
and are accept-class for projection purposes, see Laxness).

## State graph (region structure)

```
s_record   extract Rec{ctype:8, ver:16, len:16}
           select ctype { 0x16 -> push(len) -> s_hs;
                          default reject "not a handshake record" }
s_hs       extract Hs{typ:8, len:24}
           select typ { 0x01 -> push(len) -> s_fixed;
                        default reject "not a client hello" }
s_fixed    extract Body{ver:16, random:bytes[32]} -> s_sid_len
s_sid_len  extract SidLen{len:8}
           select len { [0,32] -> s_sid; [33,255] -> reject
                        "session id too long" }
s_sid      extract Sid{body:bytes[SidLen.len]} -> s_cs_len
s_cs_len   extract CsLen{len:16}
           select (len, len&1) { 0 -> reject "empty cipher suites";
                                 odd -> reject "odd cipher suites length";
                                 default -> s_cs }
s_cs       extract Cs{body:bytes[CsLen.len]} -> s_comp_len
s_comp_len extract CompLen{len:8}
           select len { 0 -> reject "empty compressions";
                        default -> s_comp }
s_comp     extract Comp{body:bytes[CompLen.len]} -> s_ext_check
s_ext_check select remaining()   # of the HANDSHAKE region
           { 0 -> s_done_noext; 1 -> reject "partial extensions length";
             default -> s_ext_len }
s_ext_len  extract ExtLen{len:16}; push(len) -> s_tlv
s_tlv      select remaining()    # of the extensions region
           { 0 -> s_done; [1,3] -> reject "partial extension header";
             default -> s_ext }
s_ext      extract Ext{typ:16, len:16}
           select (typ, seen_sni) { (0,0) -> s_sni;
                                    (0,1) -> reject "duplicate sni";
                                    default -> s_skip }
s_skip     extract Skip{body:bytes[Ext.len]} -> s_tlv
s_sni      assign seen_sni=1; push(Ext.len) -> s_sni_list
s_sni_list extract SniList{list_len:16}; push(list_len) -> s_sni_entry
s_sni_entry extract Entry{ntype:8, hlen:16}
           select ntype { 0 -> s_host; default -> reject
                          "unsupported sni name type" }
s_host     extract Host{name:bytes[hlen]}; pop; pop -> s_tlv
           # both pops exact: list_len AND ext len must be consistent
s_done     pop; pop; pop -> accept   # ext block, handshake, record
s_done_noext pop; pop -> accept      # handshake, record
```

Metadata: `seen_sni` (1 bit) — duplicate-SNI detection only; the SNI
value itself is the extracted `host.name` bytes.

`max_depth = 96`: fixed prefix ≈ 11 states + ~3 per skipped extension
(+5 for the SNI descent) covers a 17-extension browser CH (~65) with
headroom. Testgen's loop-unroll cap (2) bounds the SUITE, not the
parser — deep CHs are corpus-covered.

Region nesting K = 4 (record > handshake > extensions > SNI-ext >
SNI-list is depth 5 — record(1) hs(2) ext-block(3) ext-data(4)
list(5)) — NOTE: K = 5 pushes total; validator depth confirms.

## Projection & laxness (vs the rustls golden)

Ours: from `ParseResult` → `{verdict, reason-class, sni}` where sni =
`host.name` bytes (accepts only). Golden: `{verdict, err, sni}` from
the factory (`accept` / `incomplete` / `reject`+Debug-err).

Compatibility matrix (diff passes iff every corpus line lands in a ✓
cell; accept/accept also requires SNI string equality, including
None==None):

| ours \ rustls | accept | incomplete | reject InvalidMessage(*) | reject PeerIncompatible(*) | reject PeerMisbehaved(*) |
|---|---|---|---|---|---|
| Accept | ✓ (+sni eq) | ✗ | ✗ | ✓ policy-laxness (sni unobservable) | ✗ |
| Reject "out of bounds" (truncation class) | ✗ | ✓ | ✗ | ✗ | ✗ |
| Reject structural (region classes + authored rejects) | ✗ | ✗ | ✓ | ✗ | ✓ (SNI-content + trailing-fragment errs) |

Named expectations from the Phase-1 probes: duplicate ext →
`InvalidMessage(DuplicateExtension(0))` ↔ our "duplicate sni";
sid>32 → `InvalidMessage(TrailingData("SessionID"))` ↔ our "session id
too long"; record-len lie → `incomplete` ↔ our truncation; trailing
byte in record → `PeerMisbehaved(KeyEpochWithPendingFragment)` ↔ our
"region not exhausted"; name_type=1 →
`PeerMisbehaved(ServerNameMustContainOneHostName)` ↔ our "unsupported
sni name type"; ext-less legacy CH →
`PeerIncompatible(SignatureAlgorithmsExtensionRequired)` ↔ our Accept
(policy laxness — the flagship quirk-catalog entry).

## Corpus matrix (~30 lines; twins of projection unit tests)

Accepts: policy-complete TLS1.2 CH with SNI; + GREASE cipher/ext;
no-SNI; rustls-minted TLS1.3 first flight (from `selftest`-style
generation — real supported_versions/key_share); many-extension
browser-shaped CH; empty extensions block; extensionless legacy CH
(policy-laxness accept); session_id exactly 32; SNI hostname 1 byte.

Structural rejects: garbage; ctype != 0x16; hs type != 0x01; duplicate
SNI; session_id 33; name_type = 1; SNI list_len lying vs hlen; ext len
overrunning the block; ext block shorter than handshake body
(trailing); record trailing byte; odd cipher_suites len; zero
cipher_suites; empty compressions; remaining()==1 before ExtLen;
partial TLV header (remaining 1..3).

Truncation ladder (→ rustls incomplete): cut inside record header,
handshake header, random, session_id body, cipher_suites body,
extensions block, SNI hostname; record len declaring more than sent.

## Gate shape

- Factory mints `clienthello.rustls-0.23.43.golden.json` from
  `corpus.txt` (comment+hex, dpdk convention). Committed; version tag
  in filename + `rustls_version` field.
- `src/oracle/tls_clienthello.rs`: projection + the compatibility
  matrix + `diff tls-clienthello` CLI (interp over corpus, compare to
  golden). Unit tests: one per matrix row + the named expectations.
- Gate tests: committed golden agrees (interp side re-run in-gate,
  rustls side is the committed capture); floors: entries >= 28,
  rustls_version non-empty and == the Cargo.lock pin.
- Live lane (out of gate): `capture.sh` re-mints; witness replay in
  Phase 7 feeds `witnesses.txt` (gitignored, katran convention).

## Perf budget

Suite enumeration must stay under the design budget (release enum
< 120s; expect FAR less — loop cap 2 keeps the tree small). Bench
with `symex_bench` before committing artifacts; STOP per charter if
blown.

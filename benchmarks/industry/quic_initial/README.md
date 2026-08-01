# `quic_initial` — QUIC v1 Initial long header vs quiche (+ quinn-proto lane)

The varint example: one Pakeles description of the QUIC v1 long header
(RFC 9000 §17.2) whose parse agrees with **quiche 0.29.3**
(`Header::from_slice`) over the committed corpus — **151 entries, 0
mismatches** — with **quinn-proto 0.11.16** (`ProtectedHeader::decode`)
as a second lane whose stricter behavior is pinned divergence-by-
divergence, not ignored. Symbolic-execution witness replay adds 33
solver-derived boundary packets through both oracles: also 0
mismatches.

The reason this example exists: **QUIC varints size themselves** — the
top 2 bits of a varint's first byte encode its total width (1/2/4/8
bytes). That looked like it would force new IR. It doesn't: extract
the 2-bit prefix as an ordinary fixed field, select into four width
arms, and compose the value `(v6 << k) | tail` inline where it's
needed — a `var_bytes` length for the token bytes, a metadata assign
for the observable value. The engine needed **zero changes** (see the
charter, `docs/plans/2026-07-31-quic-initial-charter.md`, for why that
finding is the point). What the varints DID force is two backend
refusals, below.

- Source: [`quic_initial.py`](quic_initial.py) (design doc:
  `docs/designs/2026-07-31-quic-initial-design.md`)
- Oracle: [`src/lib.rs`](src/lib.rs); run
  `./dev.sh cargo run -p pakeles-benchmark-quic-initial`
- Golden factory (unprivileged):
  `./dev.sh benchmarks/industry/quic_initial/factory/capture.sh`
  (pinned quiche + quinn-proto + octets via the factory `Cargo.lock`,
  all `default-features = false` — **no crypto backend anywhere**:
  header parsing needs no keys, which is the whole point)
- eBPF deliverable: the generated parser is **verifier-clean in the
  real kernel at the committed max_depth** and TEST_RUN-agrees with
  the userspace core 136/136
  (`docs/designs/2026-07-31-quic-initial-ebpf-deliverable.md`;
  `./dev-priv.sh benchmarks/industry/quic_initial/spike/run.sh`)
- `gen/` holds C, eBPF, docs, and graph artifacts plus TWO designed
  refusals: `gen/P4-UNSUPPORTED.txt` (a varint-sized field's length
  range exceeds any static P4 `varbit` bound — even the 2-byte form
  implies 16383 bytes) and `gen/LUA-UNSUPPORTED.txt` (56-bit tails and
  62-bit composed values exceed Lua 5.2's bit32/53-bit-mantissa number
  model).

## Scope

One QUIC packet in one contiguous buffer. Deep path: v1 Initial —
first byte, version, DCID/SCID (v1 cap 20 mirrored, check-before-read
like quiche), token-length varint (all four widths) + token bytes,
payload-length varint (all four widths, value observed). Handshake and
0-RTT parse through the length varint (quinn's extent); Retry, version
negotiation, unknown versions, and short headers are classified with
their CIDs where the grammar provides them. Parsing stops before the
packet number — it is under header protection (RFC 9001 §5.4), as are
the first byte's low 4 bits, which are extracted but excluded from
every claim.

**Boundaries (documented, not modeled):**

- **Short-header DCID length** is out-of-band LB configuration — the
  katran-config-gate analog. Short packets are classified only.
- **Retry token** is "everything except the last 16 bytes", which
  needs `remaining() - 16` as a byte length — v1 bans `remaining()`
  in field widths. Retry is classified through its CIDs; quiche's
  Retry token (and its InvalidPacket on a short Retry tail) sit in
  boundary rows of the matrix.
- **Version-negotiation list** is not walked (quinn's stance; quiche
  walks it and can BufferTooShort inside it — boundary row).
- **Coalesced datagrams** are datagram semantics, not header parsing
  (quinn splits them in `PartialDecode`, above the decode we referee).
- **QUIC v2** (different type-bit mapping): out of scope; quiche
  0.29.3 doesn't support it either.

## The two-lane matrix

**quiche is the primary lane and the agreement claim.** It is the
shape-match: no fixed-bit policy, no version allow-list, owned field
values. Compatible = same class and equal version/DCID/SCID (+ token
for Initial), with the boundary rows above.

**quinn is the pinned-divergence lane.** Where quinn is stricter, the
strictness is asserted, not excused: a fixed-bit-clear packet, an
unsupported version, or an over-20-byte CID on a non-v1 packet MUST
make quinn error while we (and quiche) parse — if such an entry ever
starts parsing OK in quinn, the lane fails. In exchange quinn referees
the one field quiche never reads: the payload-length varint (it also
cross-checks the token via `token_pos`).

## Quirk catalog (oracle-vs-oracle, all witnessed by corpus entries)

1. **The fixed bit is policy, not grammar.** quiche parses
   fixed-bit-clear packets (`Ok(Initial)`); quinn rejects them
   (`invalid header: fixed bit unset`) unless `grease_quic_bit`. RFC
   9000 says endpoints MUST discard — quiche leaves that to the
   caller, which is precisely the parser/policy split this gallery
   models.
2. **Unknown versions split the oracles three ways from one nibble.**
   quiche interprets the v1 type bits of ANY unsupported version and
   parses on (version 0xdeadbeef arrives as `Ok(Initial)` with a
   token); quinn extracts both CIDs, then rejects
   (`unsupported version`). Notably **draft-29 (0xff00001d) is an
   unknown version to quiche 0.29.3** while quinn 0.11.16 still lists
   it as supported-by-default — two current, mainstream QUIC stacks
   disagree about which packets are even parseable.
3. **The 20-byte CID cap is version-gated in quiche, unconditional in
   quinn.** A 21-byte DCID on a version-negotiation packet is fine by
   quiche (cap applies only to supported versions) and `malformed
   cid` by quinn.
4. **The oracles disagree where "header parse" ends.** quiche stops
   after the Initial token; quinn also reads the payload-length
   varint. A packet cut inside the length field is quiche-Ok,
   quinn-Err — our parse takes the union extent, and the matrix
   accepts our truncation there only when quinn confirms it.
5. **Retry's tail is quiche's problem, not quinn's.** quiche slices
   "rest minus 16-byte tag" and rejects a short tail
   (`InvalidPacket`); quinn's decode doesn't touch the Retry token at
   all (`Ok(Retry)`).
6. **Non-minimal varints are accepted everywhere** (both oracles, and
   us): RFC 9000 §16 only mandates minimal encoding where a spec says
   so, and the long-header length fields don't. A 4-byte encoding of
   0 parses identically to a 1-byte one.

## What the varints forced instead of IR

Two parity-plus boundaries, different in kind from the TLV/region one
(`tls_clienthello`):

- **P4-16:** the two-field-split CONTROL FLOW is P4-expressible, but a
  faithful extraction of the varint-sized payload is not — `varbit`
  needs a static bound and even the 2-byte token form implies 131064
  bits (cap 65535). `gen p4` refuses; the refusal is committed.
- **Lua 5.2:** 56-bit tail fields and 62-bit composed values exceed
  bit32 semantics and the 53-bit double mantissa. `gen lua` refuses;
  the refusal is committed. (C, eBPF, docs, and viz all lower this
  parser; the eBPF artifact is kernel-verifier-clean.)

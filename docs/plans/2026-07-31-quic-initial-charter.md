# Autonomous run: QUIC Initial long header — the varint target

**Date:** 2026-07-31
**Status:** charter (self-authored; user delegated the arc end-to-end
this session). Sixth incumbent-agreement target, first post-roadmap.
**Done =** full gate green on main with a new `quic_initial` example
whose parse (projection over the cleartext v1 long header) agrees with
a pinned quiche header parser over a committed corpus (version-tagged
claim), a quinn-proto secondary lane with its expected-divergence
table, a documented quirk catalog, an eBPF deliverable note, README
gallery counts updated 5→6, and memory updated.

## The headline finding (recorded up front, decided by recon)

The target was picked believing QUIC varints — a field whose width
lives in its own top 2 bits — would FORCE new IR (the "two-field split
vs first-class self-sizing field" question). Recon says otherwise:
**the existing IR subsumes self-sizing varints with zero engine
changes.** The binding pattern (the "two-field split", now verified
against the validator source):

- Lead byte: `prefix = bits(2)` + `v6 = bits(6)` (bit-granular widths
  are first-class; the discriminant is its own fixed field, so the
  eDSL's fixed-field-only select-key rule is satisfied).
- Select on `prefix` into 4 width arms (exact keys 0..3).
- Each arm extracts its own tail (`bits(8)`/`bits(24)`/`bits(56)`; arm
  0 has no tail) and uses the composed value `(v6 << K) | tail`
  INLINE where it is needed: as a `var_bytes` length (token), as a
  `push_region` length, or in an `assign` (length field → metadata).
  `SHL`/`OR` are in `BinOpKind`; max value 2^62-1 fits `u64` eval.
- Cross-instance `byte_len` refs are legal — the validator's only
  demand is "definitely extracted on every path"
  (`validate.rs:551-608`, must-analysis at `:483`).

The three walls that shape (but don't block) the design, all v1
validator rules: metadata may not be a `byte_len` or `push` length
(pathid soundness); `var_bytes` values are opaque (never in `env`);
select keys must be fixed fields (eDSL). Consequence: each width arm
carries its own uses of the composed value — the 4 arms cannot
converge first and compute after, because the per-arm tail instances
die at the must-analysis join. Cost: ~5 states per value-consuming
varint. Accepted.

**Decision: two-field split under existing IR; no first-class varint
construct.** Rationale: the engine-minimality counterweight was
recorded when this target was chosen (the engine grew a lot in July);
a first-class field would buy ~4 states per varint and cost a new
`FieldWidth` kind across validate + interp + pathid + symex + 4
backends; and "the sized-region slice already subsumes QUIC varints"
is a stronger thesis statement than a bespoke construct. Revisit only
if a future target hits the walls for real (e.g. needs a varint VALUE
as a length after convergence).

## Context

- Sequenced after the 5-target roadmap + consolidation (workspace
  split). Publication deliberately follows this arc.
- Continues the packet-path/XDP/LB line (katran → tls_clienthello →
  this): the v1 long header is exactly what LBs route on (DCID), and
  katran's QUIC support was a documented config-gated BOUNDARY —
  this run converts the packet-content half into a claim.
- Naming rule (real_world README "Naming"): protocol-namespaced like
  tls_clienthello — quiche/quinn are referees, the modeled thing is
  the wire format; "Initial" is RFC 9000's own noun for the packet
  type. Class `QuicInitial` → snake → `quic_initial`. ✓

## Incumbents & scope

- **Primary oracle: quiche 0.29.3 `Header::from_slice(buf, dcid_len)`**
  — empirically verified (probe project built + run): pure bytes→
  Header, `default-features = false` builds with NO crypto backend
  (no BoringSSL, ~38 crates). Fields: ty, version, dcid, scid,
  token: Option<Vec<u8>>, versions. Parse boundary: stops after the
  Initial token, BEFORE the payload length varint. Behavior notes
  (all verified): does NOT validate the fixed bit; tolerates unknown
  versions (parses v1-shaped type bits through); CID cap (≤20) only
  enforced for supported versions (v1 only in 0.29.3); errors are
  just BufferTooShort | InvalidPacket.
- **Secondary oracle: quinn-proto 0.11.16 `ProtectedHeader::decode`**
  — also pure (`default-features = false` drops rustls/ring), config:
  `supported_versions = &[1]`, `grease_quic_bit = false`,
  `FixedLengthConnectionIdParser`. Covers what quiche doesn't:
  validates the fixed bit, unconditional CID cap, parses the payload
  `length` varint, fine-grained `InvalidHeader(&'static str)` errors.
  Token exposed only as `token_pos: Range<usize>`; VN version list
  NOT parsed. The two oracles' KNOWN divergences (fixed bit, unknown
  version, CID cap, error classes, parse extent) are corpus gold —
  the secondary lane asserts against an expected-divergence table,
  not blind agreement.
- **Varint unit oracle: `octets 0.3.6`** (zero deps, the exact code
  quiche uses) for varint-level vectors incl. non-minimal encodings.
- **Factory pattern as tls_clienthello:** `quic_initial/factory/` is
  its own workspace-EXCLUDED crate with committed Cargo.lock; the
  quiche pin IS the agreement claim and the golden filename carries
  it (`initial.quiche-0.29.3.golden.json`); quinn verdicts recorded
  inside entries. Goldens minted only by the factory. AEAD/crypto
  never enters: header parsing needs no keys (that's the whole
  point), so the factory stays `default-features = false` too.
- **Parse scope (deep path):** v1 Initial long header end-to-end:
  first byte (form/fixed/type + 4 protected low bits, extracted but
  excluded from the claim) → version → dcid_len + dcid (cap ≤ 20
  mirrored) → scid_len + scid → token-length varint (all 4 widths) +
  token bytes → payload-length varint (all 4 widths, value →
  metadata) → accept. Parse extent = the UNION of the oracles
  (through the length varint; quiche authoritative to token, quinn
  for length).
- **Classification breadth (shallow arms):** long-header v1
  Handshake / 0-RTT / Retry classified by type bits (depth per
  design-lite); version==0 → VersionNegotiation classified, list not
  walked (quinn's stance; quiche's list-walk is a documented
  divergence); first bit 0 → Short classified only.
- **Boundaries (document, don't model):** short-header DCID length is
  out-of-band LB config — the katran-config-gate analog; Retry token
  ("rest minus 16-byte tag") wants `remaining()-16` as a byte length,
  which v1 bans in `byte_len` — named boundary, not worth an engine
  change for a shallow arm; packet number + payload under header
  protection/AEAD (the ECH-analog semantic note: reserved+pn-len
  bits are extracted but unobservable in any honest claim); coalesced
  datagrams (PartialDecode's split is datagram semantics, not header
  parsing); QUIC v2 (0x6b3343cf — different type-bit mapping, quiche
  0.29.3 doesn't support it either).
- **Quirk hunting grounds:** fixed-bit-clear packets (quiche accepts,
  quinn rejects); unknown versions (quiche parses through, quinn
  rejects post-CID); dcid_len 21 with truncated vs full buffer
  (error-class order); non-minimal varint encodings for token_len /
  length (RFC 9000 §16 legal everywhere unless stated); token_len
  prefix 11 with 8-byte varint on a 1200-byte packet (value ≫
  buffer); zero-length DCID+SCID; VN with trailing bytes not ÷4;
  Retry shorter than 16 bytes after SCID; truncation ladder at every
  varint width boundary. ≥1 real divergence expected or honest none.

## Binding references

- Recon reports (this session): oracle-shape probe (scratchpad
  `oracle-probe/`, empirical differential table) + IR-expressiveness
  survey (validate.rs / interp walls, quoted above). The charter's
  claims about oracle signatures and validator rules trace there.
- `examples/real_world/tls_clienthello/` — the wiring template:
  excluded factory crate + pinned lock, golden-name-carries-pin,
  lib.rs projection/laxness/gate-test shape, README structure.
- Registration checklist (from recon, apply verbatim): workspace
  members + exclude; `pakeles-dev` REAL_WORLD table (gates
  gen_vectors); `scripts/gen-examples.sh`; `python/tests/conftest.py`
  REAL_WORLD; real_world README table; root README counts 5→6;
  Cargo.lock; factory/target gitignore line.
- eDSL notes: no reflected shift/bitwise ops (`const(1) << x` if int
  is on the left — moot here, `v6` leads every expr); `oneof`/
  `range()` expand to exact arms; per-instance var-width headers.
- Memory: [[p4-parity-ambition]] (max_depth sole termination
  authority), [[symex-perf]] (budgets; arm coalescing precedent),
  [[ebpf-verifier-codegen]] (unrolling ceiling — tls_clienthello was
  verifier-clean only ≤ depth 22 at 96 states; this parser is ~15-20
  states, expect no ceiling trouble), [[observation-patch-oracle]]
  (git hazards: never add a whole factory dir).
- RFC 9000 §16 (varints), §17.2 (long header), §17.2.2 (Initial),
  §17.2.5 (Retry); RFC 9001 §5.4 (header protection — why the low 4
  bits are out of claim), A.1 (sample client Initial, corpus anchor);
  RFC 8999 (version-independent invariants).

## Phase 0 — preflight

Tree clean; main not diverged; full gate green; branch
`quic-initial`. Commit this charter.

## Phase 1 — factory + corpus + goldens

1. `factory/` crate (excluded): quiche + quinn-proto + octets, all
   `default-features = false`, pinned lock committed. Emits one
   golden line per corpus entry: quiche verdict/fields + quinn
   verdict/fields + input hex. Reproduce the probe's differential
   table inside the dev container as the smoke test.
2. `mk_corpus.py`: structural generator (header validity needs no
   crypto — payload bytes are free) sweeping the quirk grounds above
   + RFC 9001 A.1 anchor + truncation ladders. Corpus floor ≥ 60.
3. STOP gate (expected pre-passed by the probe): factory can't
   reproduce the probe results in-container.

## Phase 2 — design-lite (binding, committed before building)

`docs/designs/2026-07-31-quic-initial-design.md`: state map with the
two varint clusters spelled out (token: value consumed as byte_len
per arm; length: value assigned to metadata per arm); projection
struct + laxness matrix vs BOTH oracles (primary = agreement, quinn
lane = expected-divergence table); max_depth number with the linear-
path arithmetic; shallow-arm depth for Handshake/0-RTT/Retry/VN;
error-class mapping (BufferTooShort→Truncation etc.); corpus matrix;
floors. STOP gate: the varint spike (below) hits a wall recon missed.

Spike first, inside this phase: a minimal 4-arm varint parser through
validator + interp + symex before the full example exists. This is
the empirical check on the headline finding; it replaces the engine
phase the TLS charter needed.

## Phase 3 — build the example

`quic_initial/` per the tls_clienthello template: `quic_initial.py`
(class `QuicInitial`; LabeledEnum where honest — packet-type bits,
varint prefix widths; NOT for byte-swapped or single-entry cases) →
regen + full registration checklist → `src/lib.rs` projection +
laxness + diff + gate tests (golden pin-prefix assert, corpus floor,
canonical-IR, artifacts-current, C/BPF/Lua conformance) → `src/main.rs`
diff bin → README (scope, boundaries, quirk catalog skeleton).
Small commits, full gate per commit, `git status` after each.

## Phase 4 — eBPF deliverable

Generated `parser.bpf.c` loaded in the real kernel (verifier-clean
bar) + BPF_PROG_TEST_RUN agreement vs interp over the corpus; short
docs note à la katran/TLS. The LB-routing framing (DCID extraction in
XDP) is the audience artifact. If the verifier rejects: document the
gap precisely — but at ~15-20 states this would itself be a finding.

## Phase 5 — quirk hunt

Symex witness replay through the factory (both oracles); the
oracle-vs-oracle divergence table graduates from expected-divergence
config to README quirk catalog with witnesses. Same honesty bar as
the last four (rich ground here — fixed bit, unknown versions,
non-minimal varints; report none-beyond-known honestly if so).

## Phase 6 — closure

Full gate + regen clean; blob check; README counts updated; ff-merge
+ push only if green; verify CI run green; memory update
([[next-incumbent-candidates]]: QUIC done + the varint verdict;
[[p4-parity-ambition]]: varints join the subsumed-by-regions column;
new memory only if a durable lesson emerged beyond these).

## Ground rules

As dpdk+katran+sai_p4+tls: single line of work; dev.sh for all gate
commands (dev-priv.sh only for the eBPF spike, never the gate); full
gate PER commit; floors only ratchet; goldens minted only by the
factory; latent-bug protocol (engine bug found en route → own
minimal fix + test + commit); every STOP = tree green + report;
never commit build outputs (gitignore first); never `git add` a
whole factory dir; verify `git status` after each commit. The
no-engine-change verdict is a PREDICTION until the Phase-2 spike
confirms it — if a wall appears, STOP and write the design note
rather than improvising IR changes mid-example. Fallback if the arc
proves infeasible (it shouldn't — the oracle gate is already passed
empirically): BGP path attributes per [[next-incumbent-candidates]].

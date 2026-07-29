# Autonomous run: TLS ClientHello / SNI — the TLV flagship

**Date:** 2026-07-29
**Status:** charter (self-authored per the roadmap standing instruction
after sai_p4 closed). Fifth and FINAL incumbent-agreement target.
**Done =** full gate green on main with a new `tls_clienthello`-class
example whose parse (projection incl. SNI) agrees byte-string-for-
byte-string with a pinned rustls ClientHello parser over a committed
corpus (version-tagged claim), the deferred TLV IR slice (sized
regions / substream / TLV loop / peek) landed across interp + symex +
backends, a documented quirk catalog, an eBPF SNI deliverable note,
and memory updated.

## Why this target is different (the big one)

Every prior target fit the existing IR. This one exists to FORCE the
deferred rung-3 leftover: **sized regions** (a length field bounds an
inner substream), a **TLV loop** (iterate extensions until the region
is exhausted — `max_depth` stays the SOLE termination authority, per
the P4-parity bar: this is the "more than P4 for TLV" claim), and
**peek/lookahead** if the design needs it. So the run has an ENGINE
PHASE before the example phase, each with its own design doc and STOP
gate. Do not shortcut the IR design to get to the example faster.

Wire format (3 nested sized regions + TLV loop + nested TLV):
record hdr (type=0x16, ver, len16) → handshake hdr (type=0x01, len24)
→ body: ver(2) random(32) session_id(len8+var) cipher_suites(len16+var)
compression(len8+var) extensions(len16 → TLV loop: type16 len16 data;
ext 0 = SNI: list-len16, entry: name_type8 len16 hostname).

## Context

- Roadmap position: DPDK (done) → Katran (done) → sai_p4 (done) →
  **TLS ClientHello** (last). Backend/audience: C + eBPF backends /
  the LB-middlebox-observability audience; a verifier-clean generated
  SNI parser attacks a famous community pain and EXTENDS the katran
  real-kernel deliverable (strongest result so far).
- Target re-validated 2026-07-29 against rivals (BGP path attrs,
  802.11 IEs, RADIUS, DHCP, X.509/DER): wins on notability × oracle
  cleanliness × eBPF continuity; nested TLV depth ≥ all feasible
  rivals. BGP loses on oracle isolation + verdict semantics + no eBPF
  hook. 802.11 IEs / RADIUS VSAs noted as future TLV side-corpus.
- Make-or-break (roadmap + this charter): (a) the TLV IR slice must
  stay decidable-by-construction AND symex-tractable (loop unrolling ×
  path explosion — see [[symex-perf]]; arm coalescing precedent); (b)
  the eBPF backend must emit a verifier-clean bounded loop (bounded by
  max_depth unroll or verifier-friendly loop form).

## Incumbents & scope

- **Primary oracle: rustls** — `ClientHelloPayload` via its `Codec`
  read path: bytes in, struct-or-error out, no connection state, no
  privileges. Pin the latest release at run time (record exact crate
  version + git tag in the golden). License Apache-2.0/ISC/MIT — a
  tiny harness crate in `oracle/tls_clienthello/factory/` with a
  pinned Cargo.lock (crates.io dep, NOT vendored source; nothing
  GPL-shaped here, but the katran git hazards still apply verbatim).
- **Secondary opinion: tshark** (`ssl_dissect_hnd_cli_hello`) on
  divergence candidates only, if available in the environment;
  skippable, not gating.
- **Quirk contrast (optional, docs-only): nginx ssl_preread** — a
  shortcut-taking real-world SNI parser; cite, don't harness.
- **Scope:** one complete ClientHello in one TLS record in one
  contiguous buffer (the same assumption nginx preread & every eBPF
  SNI parser makes — document as scoping, with cross-record
  fragmentation as a NAMED quirk/boundary, not a gap). Parse: record
  hdr → handshake hdr → all fixed/vector fields → full extensions TLV
  walk → SNI host_name extraction. Projection (finalize in design
  doc): (verdict, err, sni_present, sni_hostname, ext_type_sequence?).
- **Boundaries (document, don't model):** cross-record fragmentation;
  TCP stream reassembly; ECH (visible SNI is a decoy — semantic note,
  the QUIC-config-gate analog); post-CH handshake.
- **Quirk hunting grounds:** GREASE values (RFC 8701) ignored-not-
  rejected; extensions block ABSENT entirely (legal pre-TLS-1.2 hello);
  duplicate extensions; session_id len > 32; empty cipher_suites / odd
  vector lengths; inner/outer length inconsistencies (record len vs
  handshake len vs body consumption); trailing bytes after extensions;
  SNI with name_type != 0 or multiple entries. ≥1 real divergence
  between us/rustls/contrast incumbents or honest none.

## Binding references (read first)

- `docs/superpowers/specs/2026-07-21-flow-dissector-rung3-design.md` —
  where the sized-region/TLV slice was deferred; recover the original
  framing.
- `examples/katran_flow/` + `src/oracle/katran.rs` +
  `docs/designs/2026-07-29-katran-ebpf-deliverable.md` — freshest
  oracle/projection/gate shape + the eBPF-loads-in-real-kernel
  deliverable this run extends.
- `examples/dpdk_ptype/` — C-backend projection + laxness precedent.
- Memory: `parser-target-roadmap`, `p4-parity-ambition` (max_depth =
  sole termination authority — the TLV loop MUST honor this),
  `symex-perf` (field-variable encoding, incremental session, arm
  coalescing, dev.sh gotcha), `observation-patch-oracle` (git hazards:
  never `git add` a whole factory dir; verify status after each
  commit).
- RFC 8446 §3 (vector notation) + §4.1.2 (ClientHello); RFC 6066 §3
  (SNI); RFC 8701 (GREASE).

## Phase 0 — preflight

Tree clean; main not diverged; full gate green; branch
`tls-clienthello`. Commit this charter if not already committed.

## Phase 1 — incumbent harness (feasibility gate)

1. Pin rustls (latest release); write the factory harness crate:
   stdin/file byte string → parse as ClientHello → emit the projection
   line (verdict/err/sni/...). Record pin.
2. Smoke it: a canned real-world CH (e.g. from a curl/openssl s_client
   capture), a GREASE-laden browser CH, a truncated CH, garbage.
3. Confirm tshark presence (optional lane).
4. STOP gate: rustls's parse entry can't be isolated as bytes→result,
   or its error surface is too coarse to project. Report what was
   tried.

## Phase 2 — IR slice design (binding, committed before building)

`docs/superpowers/specs/<date>-tlv-ir-design.md`: sized regions /
substream semantics (region end vs buffer end; nested region
arithmetic; laxness at region underflow/overflow), TLV loop construct
(termination = region exhausted, max_depth as the hard bound and sole
termination AUTHORITY; per-iteration match on type; unknown-type skip
arm), peek if needed; interp semantics; symex strategy (unroll to
max_depth; expected path growth + coalescing plan; budget numbers);
per-backend lowering sketch (C, eBPF verifier-friendly form, P4
varbit/lookahead mapping OR documented P4-backend boundary); what the
P4-feature side-corpus overlap covers (lookahead/varbit) vs defers.
STOP gate: no design keeps decidability + symex tractability + a
verifier-plausible eBPF lowering.

## Phase 3 — IR slice build (engine work; small commits, full gate
per commit)

Interp + eDSL surface + symex + C backend + eBPF backend (P4 backend
per design verdict). A micro-example (minimal TLV parser, à la
counted_items) lands WITH the slice as its regression anchor before
the flagship example exists. Bench numbers vs [[symex-perf]] budget.

## Phase 4 — design-lite for the example (binding)

`docs/superpowers/specs/<date>-tls-clienthello-design.md`: coverage
map (which CH fields/extensions modeled; SNI full depth; other
extensions type+skip), projection + laxness vs rustls's error surface,
corpus matrix sketch, gate shape (committed version-tagged golden +
live tool-gated differential vs the pinned harness), floors,
out-of-scope list (the boundaries above).

## Phase 5 — build the example

`tls_clienthello` eDSL example + regen + registration → corpus
(real-browser CHs incl. GREASE, openssl/rustls-generated, each quirk
ground above, truncation ladder over every length field) → golden
mint via factory only → projection `src/oracle/tls_clienthello.rs` +
`diff tls-clienthello` CLI + gate tests + floors → README + quirk
catalog. Small commits, full gate per commit, `git status` after each.

## Phase 6 — eBPF SNI deliverable (the audience artifact)

Generated eBPF parser for the example: load into the real kernel
(verifier-clean bar, as katran) + BPF_PROG_TEST_RUN agreement vs
interp + rustls over the corpus. Short docs note à la
`2026-07-29-katran-ebpf-deliverable.md`. If verifier rejects: the
design-vs-verifier gap IS the finding — document precisely.

## Phase 7 — quirk hunt

Symex witness replay through the rustls harness (and tshark on
divergences); catalog with the same honesty bar as the last three
(≥1 real quirk expected — GREASE/absent-extensions/duplicates are
rich ground; report none honestly if so).

## Phase 8 — closure

Full gate + regen clean; blob check; ff-merge + push only if green;
memory update (roadmap: TLS done → ROADMAP COMPLETE, all four
post-ladder targets closed; note the two named side-corpora deferred:
P4-feature + TLV-protocol (802.11 IEs / RADIUS VSAs)); update
[[p4-parity-ambition]] with what the TLV slice actually delivered vs
the "more than P4" bar.

## Ground rules

As dpdk+katran+sai_p4: single line of work; dev.sh gotchas; full gate
PER commit; floors only ratchet; goldens minted only by the factory;
latent-bug protocol (an engine bug found en route gets its own
minimal fix + test + commit); every STOP = tree green + report;
never commit build outputs (gitignore first); never `git add` a whole
factory dir; verify `git status` after each commit. Engine phases
(2–3) are REAL design work — if the TLV slice wants to balloon,
STOP and report rather than land a half-designed loop construct;
Babel/RFC 8966 remains the named fallback only if TLS proves
infeasible, per roadmap.

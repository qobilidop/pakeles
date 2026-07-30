# Autonomous run: Katran packet parsing — eBPF two-way diff + katran-keys projection

**Date:** 2026-07-29
**Status:** charter for an autonomous run (self-authored per the roadmap's
standing instruction after dpdk_ptype closed; same template as
`docs/plans/2026-07-29-dpdk-ptype-charter.md`)
**Done =** full gate green on main with a new `katran_flow`-class example
whose projected flow keys agree packet-for-packet with Katran's own BPF
parsing over a committed corpus (version-tagged claim), a documented
divergence/quirk catalog (>=1 real quirk or an honest "none surfaced"),
an eBPF-backend deliverable exercised against the example (the
audience-facing artifact), and memory updated.

Third instantiation of the incumbent-agreement pattern (pinned incumbent
→ projection defined before building → corpus + minted agreement →
honest boundary docs). The incumbent is **privileged** (BPF_PROG_TEST_RUN
in-kernel, like the flow-dissector factory — `dev-priv.sh`, out-of-gate
mint, committed version-tagged goldens; the everyday gate stays
unprivileged).

## Context

- Roadmap position: DPDK ptype (DONE 2026-07-29) → **Katran** → sai_p4 →
  TLS ClientHello. Backend/audience pairing: eBPF backend, eBPF-community
  pitch — testgen (path-complete TEST_RUN vectors) as much as codegen
  (verifier-clean by construction).
- Incumbent: github.com/facebookincubator/katran, the XDP balancer's
  packet-parsing path (`katran/lib/bpf/` — `balancer_kern.c`,
  `pckt_parsing.h`, `handle_icmp.h` at the pinned commit chosen in
  phase 1). Katran's BPF sources are GPL-2.0 → **fetch-at-capture-time,
  never vendored** (bpf_flow.c precedent).
- Make-or-break (from the roadmap): carving the "katran keys" projection
  out of LB logic — the program computes a flow tuple (src/dst,
  ports, proto), QUIC connection-id server-id routing, and
  ICMP-embedded inner-packet handling, then makes LB decisions we do
  NOT model. The observation problem is phase 1's core question: how to
  read the parsed keys from a TEST_RUN (their flow struct via map,
  return-value encoding, or an instrumentation patch pinned+diffed like
  a capture.c).
- Likely IR drivers (verify against source, do not trust recollection):
  QUIC first-byte flag dispatch and variable-length connection-id
  fields; ICMP "packet-in-packet" re-entrancy (a third flavor after
  IPIP/GRE). If a genuine IR gap surfaces (e.g. var-bits), that is a
  design-phase finding: prefer scoping rung-style (model what the IR
  expresses today, boundary-doc the rest) over mid-run IR invention —
  unless the gap is small and precedented (arm-coalescing-scale).

## Binding references (read first)

- `examples/real_world/dpdk_ptype/README.md`, `src/oracle/dpdk_ptype.rs`,
  `docs/superpowers/specs/2026-07-29-dpdk-ptype-design.md` — the
  freshest instantiation: laxness-rule projection, quirk catalog shape,
  build-notes conventions.
- `examples/real_world/linux_flow_dissector/README.md` + `oracle/linux_flow_dissector/`
  — the privileged golden-factory pattern (BPF_PROG_TEST_RUN, capture.c,
  dev-priv.sh, version-tagged goldens, floors).
- Memory: `parser-target-roadmap`, `flow-dissector-northstar` (factory +
  stray-session incidents), `symex-perf` (arm coalescing, bench
  workflow, dev.sh gotchas).

## Phase 0 — preflight

1. Tree clean; main not behind/diverged from origin. Dirty/diverged →
   STOP, report.
2. Full gate green on pristine main. Red → latent-bug protocol.
3. Branch `katran` off main.

## Phase 1 — incumbent study + factory harness

1. Pin: latest katran main commit at study time (record hash — it is
   the version tag). Fetch the BPF parsing sources; read
   `balancer_kern.c`'s process_packet path end-to-end, list exactly
   what is parsed (L2? katran is XDP on L3?; IPv4/v6, ext headers?,
   TCP/UDP, ICMP+inner, QUIC cid, encap handling) vs what is LB logic
   (consistent hashing, maps, stats) — the parse/decide boundary
   drives everything.
2. Solve the observation problem: make the parsed keys visible under
   `BPF_PROG_TEST_RUN` in the dev-priv container. Preferred: run their
   program unmodified and read whatever structured state it exposes
   (return codes + output packet + maps). Fallback: a pinned
   instrumentation patch (diff committed, applied at capture time —
   the sai_p4 gadget pattern arriving early). Smoke-test on hand-built
   packets.
3. STOP gate: their program cannot run under TEST_RUN in our container
   (map/prog-type/kernel-feature gaps) after a genuine bounded attempt
   — report what was tried; shrinking the claim (e.g. parsing-functions
   extracted into a harness prog, pinned+diffed) is the user's call.

## Phase 2 — design-lite (committed before building)

`docs/superpowers/specs/<date>-katran-design.md`, from source:

1. Coverage map: exactly which packet shapes the parse path
   distinguishes, incl. the ICMP-inner and QUIC arms; what it validates
   vs assumes; all drop/pass/tx verdicts relevant to parsing.
2. Projection: our ParseResult → katran keys, with the laxness/verdict
   rule (their drop vs our reject; LB-decision outputs excluded).
3. Example scope + name (content-named; a field-for-field model of the
   parse path only — LB logic is the boundary).
4. IR gaps found: model-or-boundary decision per gap, precedented-scale
   fixes only.
5. Gate shape: committed version-tagged golden (privileged mint,
   flow-dissector pattern) + everyday unprivileged diff; floors.
6. The eBPF deliverable: our generated parser.bpf.c for the example,
   TEST_RUN-exercised in the gate (rbpf already covers it; a real
   kernel TEST_RUN of OUR program in the factory run is the
   audience-facing extra).

STOP gate: the projection cannot be made deterministic per-packet, or
the observation problem forces modeling LB state (maps/config) beyond a
pinnable default.

## Phase 3 — plan doc

Tasks/corpus matrix/floors/commit messages, dpdk-ptype conventions.
Symex: re-measure with `symex_bench` before regen; arm coalescing is
in-tree now.

## Phase 4 — build (small semantic commits, gate green per commit —
run the gate for intermediate commits too; the dpdk run's tip-only
verification was a noted deviation, not the norm)

eDSL example + regen; projection + `diff katran` + gate tests; corpus +
privileged golden mint (byte-identity discipline, floors after);
README.

## Phase 5 — quirk hunt

Witness replay through the factory; catalog divergences honestly.

## Phase 6 — eBPF deliverable spike

Our `parser.bpf.c` under real-kernel BPF_PROG_TEST_RUN (factory
container): verifier acceptance (the headline claim), correctness vs
interp over the corpus, and an indicative cycles comparison vs Katran's
own parse if separable. Findings over polish; a verifier rejection is a
first-class finding.

## Phase 7 — closure

Gate + regen clean; ff-merge + push only if green; memory updates
(roadmap status, new pattern notes); then proceed to the sai_p4 charter
per the standing instruction.

## Ground rules

Identical to the dpdk-ptype charter: single line of work; dev.sh env
gotchas; full gate per commit; floors only ratchet; goldens minted only
by the factory; latent-bug protocol (precisely-characterized fixes in
own commits, flagged in the report); every STOP = tree green + report.
Privileged steps only via `./dev-priv.sh` (never in the everyday gate).

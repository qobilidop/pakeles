# Autonomous run: complete the linux_flow_dissector ladder (4a follow-ups + rung 4b)

**Date:** 2026-07-29
**Status:** charter for an autonomous run; not started
**Done =** full gate green on main with kernel agreement active over the whole
corpus including GRE, README divergence boundary updated, memory updated.

This is a run charter, not a rung plan: phase 2 below produces the actual
rung-4b plan doc per the repo's spec → plan → build convention.

## Binding references (read first, in this order)

- `docs/superpowers/specs/2026-07-28-flow-dissector-rung4b-design.md` — binding
  design-lite for 4b (kernel semantics ordering, projection deltas, corpus
  matrix, symex gate). Do not re-derive kernel semantics; verify against the
  vendored `bpf_flow.c` only where the design says "verified against".
- `docs/superpowers/plans/2026-07-28-flow-dissector-rung4a.md` — 4a plan +
  follow-up notes.
- `examples/linux_flow_dissector/README.md` — divergence/boundary text to
  update.
- Memory: `flow-dissector-northstar` (follow-up details, stray-session
  incidents), `symex-perf` (bench workflow, dev.sh gotchas).

## Phase 0 — preflight (abort conditions live here)

1. Tree must be clean. `main` may be ahead of `origin/main` (e.g. this doc's
   commit) but must not be behind or diverged. If dirty or diverged: STOP,
   report.
2. Regenerate vectors (`./dev.sh scripts/gen-examples.sh` —
   linux_flow_dissector regen should be ~8s). Run the full gate. Must be
   green BEFORE any change.
3. Create branch `flow-dissector-4b` off main. All work happens there.

## Phase 1 — rung-4a goldens-mint follow-up

1. Mint: `./dev-priv.sh oracle/flow_dissector/factory/capture.sh` (privileged,
   kernel 6.8.0 — if the reported kernel version differs from the committed
   golden's tag, STOP and report).
2. HARD GATE: diff the new golden against
   `examples/linux_flow_dissector/conformance/flow_keys.linux-6.8.0.golden.json`.
   Every pre-existing entry must be byte-identical; the only changes allowed
   are the 12 rung-4a tunnel vectors and the `is_encap` field. Any drift in an
   existing entry: STOP, report, do not commit.
3. Commit the golden. THEN (separate commit) ratchet `committed_goldens_agree`
   floors to ok≥27/drop≥12 and add `"is_encap"` to the required subset — the
   gate must reflect the committed golden, never precede it.
4. Update the README lines saying the tunnel-agreement claim "activates with
   the re-mint" (lines ~90 and ~157). Gate green before moving on.

## Phase 2 — rung 4b plan + symex gate

1. Write `docs/superpowers/plans/<date>-flow-dissector-rung4b.md` per the
   design-lite. Resolve the open spelling question as the design leans: the
   TEB arm targets `"parse_ethernet"` directly; no `parse_gre_teb` state —
   unless you hit a concrete validator/codegen blocker, which you document.
2. SYMEX GATE (before building anything): add the GRE states to the example,
   run enumerate-only via `symex_bench`, and project full-regen wall-clock.
   If projection exceeds 15 minutes: STOP, commit the measurement note to the
   plan doc, report. (The design says the user decides sequencing in that
   case.)

## Phase 3 — build 4b (small semantic commits, tree green per commit)

1. Example: `GRE` + `GREOpt` as separate headers (the version≠0 accept must
   never touch the optional region — this ordering is the crux, kernel
   step 2); assign `is_encap` only in `parse_gre_opt`; proto dispatch
   0x0800/0x86DD/TEB, default reject. `max_depth` stays 10. Regen all `gen/*`
   artifacts.
2. Projection deltas: `n_proto` = LAST `vlan_q` instance else first
   `ethernet`; GRE-stop accept (version≠0) = thoff at GRE base start,
   `ip_proto` 47, ports 0, `is_encap` false, no L4 expected.
3. Corpus: the full GRE matrix from the design §Oracle — ~10 accepts
   (incl. version=1 accept-stop with flags set + truncated tail, TEB + inner
   802.1Q where `n_proto` is the inner tag's encapsulated proto, GRE behind
   IPIP, MPLS-over-TEB) and 4 drops (truncated base, truncated inner after
   version-0 optionals, TEB truncated inner eth, ARP-over-GRE).
4. Run existing projection tests — all pre-4b behavior must be preserved.

## Phase 4 — 4b goldens + closure

1. Privileged re-mint; same byte-identity HARD GATE for all pre-existing
   entries (now including the phase-1 tunnel entries).
2. Commit golden, then ratchet floors by the new vector counts (separate
   commit, same ordering rule as phase 1).
3. README: delete the GRE divergence line (proto-47 leaves the excluded set);
   add the R-bit and PPTP fidelity-boundary notes from the design.
4. Full gate green including env-gated conformance; fresh vector regen.
5. Merge branch to main (ff) and push ONLY if every gate passed and both
   golden re-mints were byte-clean. Otherwise leave the branch and report.
6. Update memory: `flow-dissector-northstar` (ladder complete / what
   remains), `symex-perf` if regen numbers changed materially.

## Ground rules

- Single line of work. No parallel agents writing to the tree (stray-session
  incidents 2026-07-25 and 2026-07-28: verbatim-applied drafts, premature
  floor bumps, bogus status files).
- `dev.sh` does not forward host env vars — use `./dev.sh env VAR=x cmd`.
- Never TaskStop a `./dev.sh` command (leaves the container running and
  burning CPU). If a container must be killed, note it for the user.
- Every STOP above means: commit nothing further, write up exactly what was
  observed vs expected, and end the run with the tree in a green state.

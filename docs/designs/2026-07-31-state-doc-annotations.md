# State docstrings as IR doc annotations

**Proposal (2026-07-31, draft — not yet implemented).** Lift the
docstrings that `Parser` state methods (and the class itself) already
carry into the IR as `annotations["doc"]`, so the prose that today
exists only in the Python source becomes part of the one description
that yields many artifacts — rendered by `pakeles doc`, available to
`viz`, and equality-guarded like everything else.

## Motivation

The ParserDef migration (ccf1878) turned the gallery's per-state
comments into method docstrings — `parse_gre`'s "step order is the
crux" note, `s_tlv`'s "1..3 bytes cannot hold a type+length header".
That prose is load-bearing documentation of *modeled incumbent
behavior*, and right now it is trapped in one authoring surface: the
generated markdown (`gen/*.md`) describes each state's mechanics
(extracts, arms) but not its intent. The project's core claim is "one
description, many artifacts that provably agree"; the description's
own explanation should not be the one thing that fails to propagate.

## Mechanism

No schema change. `State` and `Parser` both already carry
`map<string, string> annotations = 15`, and annotations are the
designed extension point with two precedents: `severity` on rejects,
`tshark.key` on fields. We add one flat key, matching `severity`'s
flatness:

- **eDSL lift** (`Parser._assemble`): for each state method,
  `inspect.getdoc(func)` (dedented, surrounding whitespace stripped;
  newlines kept) → `State.annotations["doc"]`; absent/empty docstring
  → no key. The class docstring lifts the same way to
  `Parser.annotations["doc"]`. Underscore helpers are not states and
  are never lifted.
- **docgen**: render the doc under each state's bullet (indented
  continuation line(s)), and the parser-level doc under the title.
  The committed `gen/*.md` artifacts regenerate; their equality guard
  (`committed_artifacts_current`) keeps them current thereafter.
- **viz** (optional, separable): state node tooltips. Defer unless it
  falls out trivially.
- **Everything else ignores the key.** interp, symex, testgen, lint,
  and all four codegen backends must not read it — annotations stay
  non-semantic. (Today nothing reads `State.annotations` at all;
  lua/docgen read only reject `severity`, oracle reads only
  `tshark.key`.)

Determinism is already solved: existing annotations survive `fmt-ir`
canonically (sorted keys in both pbjson and the Python `to_json`), as
the committed `severity`/`tshark.key` entries demonstrate.

## Migration

One regen (`./dev.sh scripts/gen-examples.sh`) after the eDSL change.
The committed `ir.json` diff is additive `annotations` entries only —
reviewable at a glance; the embedded synthetic IRs refresh through the
same run (`include_str!` re-embeds, no code change); the gitignored
conformance suites are untouched in structure and regenerate in CI as
always.

## The coupling this creates — deliberately

Conformance tests proto-equality, so after this change **an edited
docstring fails conformance until the gallery is regenerated**, exactly
like an edited arm. That is the point: prose about modeled behavior
becomes part of the reviewed, committed artifact and cannot silently
drift from it. The cost is that docstring wording tweaks now require a
regen commit. Accepted: the gallery docstrings describe incumbent
semantics ("katran drops ihl != 5"), not implementation chatter, and
should be reviewed with the same weight.

## Alternatives rejected

- **A `Display`/`doc` schema field on `State`.** A proto bump, pbgen
  regen in both languages, and version churn — for no capability the
  annotations map doesn't already provide. Field-level docs use
  `Display` because they carry structured name/format too; state docs
  are prose only.
- **docgen reading the Python source.** Breaks the only-contract rule:
  the serialized IR is the interface, and docgen must work on any
  `ir.json`, including ones no Python produced.
- **Status quo.** The prose exists; it just doesn't travel.

## Open questions

- Whether `pakeles doc` should render the full multi-line docstring or
  first-paragraph-only (lean: full text; the gallery's docstrings are
  already terse).
- Whether `lint` should cap length or validate anything about the
  value (lean: no — free-form prose, zero semantics).
- Whether the eDSL should also lift `Metadata` field `doc=` into
  parity here — it already flows via `MetadataField.display.doc`, so
  no action; noted to confirm no overlap confusion.

## Acceptance

- eDSL emits the annotations; conformance stays green after one regen
  whose `ir.json` diff is additive `"annotations"` entries only.
- `pakeles doc` output for `linux_flow_dissector` shows the GRE
  step-order note under `parse_gre`.
- Grep-proof that no semantic consumer (interp/symex/codegen) reads
  `annotations["doc"]`.

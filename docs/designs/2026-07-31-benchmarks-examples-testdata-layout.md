# Decision record: benchmarks/ + educational examples/ + testdata decoupling

**Date:** 2026-07-31 (user decisions, discussed and approved this
session). Follows `2026-07-30-polyglot-repo-layout.md`.

## The three decisions

1. **`examples/{academic,real_world}` → `benchmarks/{academic,industry}`.**
   The gallery's measured/compared corpus serves the *benchmarking*
   purpose of an academic-paper evaluation, and the tree now says so
   (the literature itself uses the word: Vera calls switch.p4 "a good
   benchmark"; Leapfrog calls the Gibb graphs its "benchmarks").
   `academic`/`industry` is a symmetric provenance pair. The industry
   half's identity is UNCHANGED — incumbent-agreement claims with
   oracles, goldens, and laxness matrices; "benchmark" is the corpus
   role, not a demotion of the claim (its README says both). Crate
   prefix follows: `pakeles-benchmark-<name>`.

2. **`examples/synthetic/` flattened to `examples/`, repurposed as
   educational.** One example per directory at top level; this is
   where a Pakeles user learns the Python eDSL (eth_ipvx_l4 is the
   hello-world; docstring-lifting makes each tutorial generate its
   own rendered docs in `gen/doc.md`). Tutorials keep their own gate
   (eDSL-equality, canonical IR, committed artifacts current, backend
   conformance) run from pakeles-dev — proven, but not load-bearing
   for the engine.

3. **The core library is decoupled from all example/benchmark
   trees.** Three strands:
   - `pakeles::examples` (embedded gallery mirrors) is DELETED. The
     core's own test parsers are independent frozen fixture files in
     **`testdata/parsers/*.ir.json`** — the existing language-neutral
     fixture tree (`testdata/basic.pcap`, deterministically
     regenerated, consumed by path via `test_repo_path`). Fixtures
     start as copies of the former synthetic trio but are now free to
     evolve for COVERAGE while tutorials evolve for PEDAGOGY —
     divergence is intended. Fixture conformance generates its symex
     suites in-test (no committed `gen/`, no vectors files).
   - Gallery-wide test batteries move out of the lib crate:
     `rust/pakeles/tests/{synthetic_gallery,academic_gallery}.rs` →
     pakeles-dev tests (tutorials + academic). Dependency arrows only
     point outward: the lib tests itself against `testdata/`; the dev
     crate tests the trees; industry benchmark crates test
     themselves.
   - The CLI's built-in default parser is REMOVED (`--ir` required;
     `export-ir` deleted). Rationale (user): the CLI is a dev tool
     that always runs inside the checkout — every documented
     invocation is `./dev.sh` from the repo root — so "works without
     a checkout" was a non-goal, and explicit `--ir` paths in the
     quickstart teach the actual model: parsers are files.

## Resulting layout

```
benchmarks/academic/     # transcriptions from published evaluations
benchmarks/industry/     # incumbent-agreement claims (crates)
examples/                # educational, flat, graded; gate via pakeles-dev
testdata/                # basic.pcap + parsers/*.ir.json (core fixtures)
third_party/             # unchanged
rust/  python/  proto/   # unchanged
```

Historical charters/design docs keep their as-written paths (they
describe history). The naming rules live on in
`benchmarks/industry/README.md` and `benchmarks/academic/README.md`.

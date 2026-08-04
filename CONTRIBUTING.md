# Contributing to Pakeles

Pakeles is pre-1.0 and changes quickly, but changes should still preserve the
repository's cross-backend guarantees. These rules apply to human and
automated contributors alike.

## Development environment

Docker is the only host prerequisite. Run tools through `dev.sh` so local work
and CI use the same pinned compilers, linters, packet tools, and P4 stack:

```sh
./dev.sh scripts/gate.sh
```

The gate is the definition of green. In order, it checks formatting and static
analysis, every supported Cargo feature boundary, publishable package
contents, required external tools, freshly generated conformance vectors, the
whole Cargo workspace, and the Python suite. During development, run the
narrow test first; run the complete gate before handing off a change.

Use `./dev.sh scripts/fmt.sh` to apply repository-owned formatters. The lint
scripts deliberately operate on tracked first-party files, so ignored factory
outputs and caches cannot change the result.

## Sources of truth

Do not fix a derived artifact without fixing its source.

| Change | Source of truth | Required regeneration |
| --- | --- | --- |
| IR schema | `proto/pakeles/**` | Rust: `./dev.sh cargo run --bin pakeles-pbgen`; Python: command in `python/README.md` |
| Tutorial or benchmark parser | adjacent `<name>.py` eDSL description | `./dev.sh scripts/gen-examples.sh` |
| Generated backend output | validated committed `<name>.ir.json` | `./dev.sh scripts/gen-examples.sh` |
| Conformance vectors | committed IR plus symbolic execution | generated automatically by `scripts/test.sh`; intentionally ignored |
| Incumbent golden | pinned external implementation and its `factory/` | run only the member's documented factory procedure |

The committed `gen/` trees are reviewable artifacts and equality guards; do
not format or edit them by hand. Tests regenerate a fresh copy elsewhere and
compare it with the commit. Conformance vectors are different: they churn with
symbolic execution, remain ignored, and are rebuilt before tests so a missing
local suite cannot silently skip backend coverage.

Golden factories are provenance tools, not ordinary tests. Some fetch pinned
third-party sources or require kernel privilege. The normal gate is
unprivileged; use `dev-priv.sh` only when a benchmark README explicitly calls
for it, then review the resulting golden diff.

## Boundary rules

- Treat decoded protobuf, JSON, pcaps, vector suites, and child-process output
  as untrusted. Rust execution and generation APIs take `ValidatedIr` or
  `ValidatedTestSuite`; do not add a raw-message bypass for convenience.
- Authored names are protocol vocabulary (`type`, `key`, `error`), so
  validation asks only that they be portable identifiers and that no two of
  them lower onto one generated member. A name that collides with a target
  language's reserved word is the emitter's problem: escape it there, where
  that language's rules — and its compiler, in the gate — actually apply.
- Presentation strings are freer still, but every emitter must escape them for
  its target language, and escape only what that target genuinely requires.
- New parsing, symbolic, input, or subprocess work needs an explicit resource
  ceiling and a test that exercises the ceiling.
- Publish files atomically through `fsutil`; external commands go through the
  bounded process helper unless a lower-level lifecycle is genuinely needed.
- Missing optional tools may justify a focused unit-test skip outside the dev
  image. The gate's `check-tools.sh` must fail when the full oracle set is not
  available.

See `docs/architecture.md` for the rationale and the main module boundaries.

## Dependency updates

Dependency changes are explicit review events:

- Edit `.devcontainer/requirements.in`, then run
  `./dev.sh scripts/update-python-lock.sh` to regenerate the complete hash lock.
- Keep `rust-toolchain.toml`, the Docker Rust version, and the verified
  `rustup-init` checksums in sync.
- Update Docker image digests, the Ubuntu snapshot, and downloaded-tool
  checksums together. Build both architectures before merging.
- Pin GitHub Actions by full commit SHA and retain the release tag in a comment
  so update tooling and reviewers can identify the intended release.

Keep commits small enough to review by invariant or subsystem. Include source,
derived artifacts, and relevant tests in the same commit; document any
deliberate compatibility or security exception where it is enforced.

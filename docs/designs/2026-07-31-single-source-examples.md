# Gallery descriptions: single source, no package mirror

**Decision (2026-07-31).** The authoritative home of each example
description is `examples/<group>/<name>/<name>.py`, beside the
artifacts it yields. `pakeles.examples` is deleted; nothing is copied
or mirrored.

## Why

The previous arrangement — authoritative modules in
`python/src/pakeles/examples/`, byte-identical copies generated into
the gallery by `gen_examples`, six equality tests guarding the mirror —
was a workaround, not a design. The 2026-07-30 layout principle says a
thing lives with what it is about, and warns that "a `rust/` that
promised to contain all Rust code would be false the day it was
created"; symmetrically, the gallery descriptions are about the
*incumbents*, not about the eDSL library, so `python/` was the wrong
side. The package location was a bootstrap leftover from when
`pakeles.examples` held only the eth mirror of the then-authoritative
Rust builder.

The package-membership arguments dissolved on inspection:

- **Importability** doesn't require a package: tests load the gallery
  files with `importlib` (`python/tests/conftest.py`), and
  `gen-examples.sh` runs each description by path.
- **Gate coverage** doesn't require a package: ruff and pyright are
  configured at the repo root (`ruff.toml`, `pyrightconfig.json` with
  `extraPaths: python/src`) and check `examples/**/<name>.py` at the
  same strictness as the library. Incumbent-side scripts
  (`factory/`, `spike/`) and generated artifacts (`gen/`) stay
  excluded — they are not eDSL surface.
- **Shipping examples in the wheel** was never load-bearing; the
  gallery on the repo is the documentation.

## What changed

- `python/src/pakeles/examples/` deleted; the gallery copies (already
  byte-identical) became the originals.
- `gen_examples` no longer copies `.py`; the six
  `committed_py_example_current` mirror tests are gone — with one
  copy there is nothing to drift.
- `test_conformance`/`test_parser_machinery` load descriptions via
  `conftest.load_example` / `example_parser` (the unique `Parser`
  subclass per module).
- CI's python step runs `ruff check .` and `pyright` from the repo
  root, then `pytest` from `python/`.

## Cost accepted

Two test files import by loader rather than by package path, and the
gallery descriptions' IDE experience depends on the root pyright
config. The wheel carries no examples.

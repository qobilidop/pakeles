#!/usr/bin/env bash
# All read-only static checks — formatters in --check mode, linters,
# type checks. No tests, no generation; see test.sh and gate.sh.
# Run as: ./dev.sh scripts/lint.sh
#
# Ordered cheap-first so failures surface fast; clippy last (it
# compiles the workspace).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
ruff format --check .
ruff check .
buf lint
buf format --diff --exit-code

# Own shell scripts only: .ci holds CI's cargo-registry mount (vendored
# .sh), third_party is vendored, target/.git are build/VCS internals.
find . \( -path ./third_party -o -path ./.ci -o -path ./target -o -path ./.git \) -prune \
  -o -name '*.sh' -print0 | xargs -0 shellcheck

actionlint
pyright
cargo clippy --workspace --all-targets -- -D warnings

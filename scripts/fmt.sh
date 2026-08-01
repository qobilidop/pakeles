#!/usr/bin/env bash
# Apply every formatter (mutating). Run as: ./dev.sh scripts/fmt.sh
#
# ruff format's scope is deliberately narrower than ruff check's: the
# gallery descriptions and markdown are excluded in ruff.toml [format]
# to preserve hand-aligned header classes.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt
ruff format .
buf format -w

# Own C only (oracle-side factory/spike code): gen/ holds generated C
# gated by equality guards, never formatters. Keep this find in step
# with the one in lint.sh.
find . \( -path ./third_party -o -path ./.ci -o -path ./target -o -path ./.git \
          -o \( -type d -name gen \) \) -prune \
  -o \( -name '*.c' -o -name '*.h' \) -print0 | xargs -0 clang-format -i

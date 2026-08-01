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

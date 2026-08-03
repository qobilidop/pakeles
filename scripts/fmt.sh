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

# Own tracked C only (oracle-side factory/spike code): gen/ holds generated C
# gated by equality guards, never formatters. Keep this filter in step with
# lint.sh.
mapfile -d '' c_files < <(git ls-files -z -- '*.c' '*.h')
own_c=()
for file in "${c_files[@]}"; do
  case "$file" in third_party/* | */gen/*) ;; *) own_c+=("$file") ;; esac
done
((${#own_c[@]} == 0)) || clang-format -i "${own_c[@]}"

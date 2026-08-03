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

# Tracked first-party files only: ignored factory outputs and cache mounts must
# never make the gate depend on whatever happens to be in a developer's tree.
mapfile -d '' shell_files < <(git ls-files -z -- '*.sh')
own_shell=()
for file in "${shell_files[@]}"; do
  case "$file" in third_party/*) ;; *) own_shell+=("$file") ;; esac
done
((${#own_shell[@]} == 0)) || shellcheck "${own_shell[@]}"

# Generated C is equality-guarded, not formatter-owned. Keep this filter in
# step with fmt.sh.
mapfile -d '' c_files < <(git ls-files -z -- '*.c' '*.h')
own_c=()
for file in "${c_files[@]}"; do
  case "$file" in third_party/* | */gen/*) ;; *) own_c+=("$file") ;; esac
done
((${#own_c[@]} == 0)) || clang-format --dry-run -Werror "${own_c[@]}"

actionlint
pyright
cargo clippy --workspace --all-targets --all-features -- -D warnings

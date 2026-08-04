#!/usr/bin/env bash
# Prove the published crate's `rust-version` is real: build the library
# shape with exactly that toolchain. A declared MSRV nobody compiles is
# a promise to consumers that the gate never checks.
#
# Networked (it installs a second toolchain), so this is not part of the
# ordinary gate — run it when `rust-version` or a dependency changes:
#   ./dev.sh scripts/check-msrv.sh
set -euo pipefail
cd "$(dirname "$0")/.."

msrv="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' rust/pakeles/Cargo.toml)"
if [ -z "$msrv" ]; then
  echo "rust/pakeles/Cargo.toml declares no rust-version" >&2
  exit 1
fi
echo "checking declared MSRV $msrv"

rustup toolchain install --profile minimal --no-self-update "$msrv"
# The library shape only: `cli` and `symex` are conveniences whose own
# dependencies (clap, z3) set their own floors.
cargo "+$msrv" check -p pakeles --no-default-features

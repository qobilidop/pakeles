#!/usr/bin/env bash
# Regenerate the gallery from its single source of truth, the Python eDSL.
set -euo pipefail
cd "$(dirname "$0")/.."
for name in eth_ipvx_l4 linux_flow_dissector; do
  ir="examples/$name/$name.ir.json"
  mkdir -p "examples/$name"
  tmp="$(mktemp)"
  PYTHONPATH=py/src python3 -m "pakeles.examples.$name" > "$tmp"
  cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$ir"
  rm -f "$tmp"
done
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples
echo "gallery regenerated from py/src/pakeles/examples/*.py"

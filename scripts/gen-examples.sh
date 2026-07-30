#!/usr/bin/env bash
# Regenerate the gallery from its single source of truth, the Python eDSL.
# Group membership (synthetic vs real_world) is encoded once, in
# src/examples.rs; keep these lists in step with it.
set -euo pipefail
cd "$(dirname "$0")/.."
synthetic="eth_ipvx_l4 counted_items tlv_items"
real_world="linux_flow_dissector dpdk_ptype katran_flow sai_parser tls_clienthello"
for group in synthetic real_world; do
  eval "names=\$$group"
  for name in $names; do
    dir="examples/$group/$name"
    mkdir -p "$dir"
    tmp="$(mktemp)"
    PYTHONPATH=py/src python3 -m "pakeles.examples.$name" > "$tmp"
    cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$dir/$name.ir.json"
    rm -f "$tmp"
  done
done
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples
echo "gallery regenerated from py/src/pakeles/examples/*.py"

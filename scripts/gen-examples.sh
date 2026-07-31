#!/usr/bin/env bash
# Regenerate the gallery from its single source of truth: the eDSL
# description committed beside each example (examples/<group>/<name>/<name>.py).
# Group membership: synthetic is encoded in rust/pakeles/src/examples.rs,
# real_world in the workspace members ([workspace] in Cargo.toml +
# gen_examples's gallery table); keep these lists in step with them.
set -euo pipefail
cd "$(dirname "$0")/.."
synthetic="eth_ipvx_l4 counted_items tlv_items"
real_world="linux_flow_dissector dpdk_ptype katran_parser sai_parser tls_clienthello"
for group in synthetic real_world; do
  eval "names=\$$group"
  for name in $names; do
    dir="examples/$group/$name"
    mkdir -p "$dir"
    tmp="$(mktemp)"
    PYTHONPATH=python/src python3 "$dir/$name.py" > "$tmp"
    cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$dir/$name.ir.json"
    rm -f "$tmp"
  done
done
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples
echo "gallery regenerated from examples/*/*/[name].py"

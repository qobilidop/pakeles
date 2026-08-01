#!/usr/bin/env bash
# Regenerate the gallery from its single source of truth: the eDSL
# description committed beside each member. Groups: examples/ (flat,
# educational tutorials), benchmarks/industry/ (workspace members),
# benchmarks/academic/. Keep these lists in step with the workspace
# members, gen_examples's gallery table (pakeles-dev), and
# python/tests/conftest.py.
set -euo pipefail
cd "$(dirname "$0")/.."
regen() {
  local base="$1"
  shift
  local name dir tmp
  for name in "$@"; do
    dir="$base/$name"
    mkdir -p "$dir"
    tmp="$(mktemp)"
    PYTHONPATH=python/src python3 "$dir/$name.py" > "$tmp"
    cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$dir/$name.ir.json"
    rm -f "$tmp"
  done
}
regen examples eth_ipvx_l4 counted_items tlv_items
regen benchmarks/industry linux_flow_dissector dpdk_ptype katran_parser sai_parser tls_clienthello quic_initial dash_parser
regen benchmarks/academic gibb_simple gibb_enterprise gibb_datacenter gibb_edge gibb_service_provider gibb_big_union kangaroo_parse_tree p4lang_switch_parser
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples
echo "gallery regenerated from the committed eDSL descriptions"

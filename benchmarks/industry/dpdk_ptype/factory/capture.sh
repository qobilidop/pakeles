#!/usr/bin/env bash
# Mint the dpdk_ptype goldens: build the unprivileged capture harness
# against the container's DPDK and replay the corpus through
# rte_net_get_ptype(). Unprivileged — runs in the normal dev container:
#
#   ./dev.sh benchmarks/industry/dpdk_ptype/factory/capture.sh
#
# The output filename carries the exact DPDK version, making the
# agreement claim precise ("agrees with DPDK X.Y.Z").
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
read -ra dpdk_flags <<<"$(pkg-config --cflags --libs libdpdk)"
gcc -O2 -o build/capture capture.c "${dpdk_flags[@]}"
ver="$(pkg-config --modversion libdpdk)"
out="../conformance/ptype.dpdk-${ver}.golden.json"
./build/capture corpus.txt > "$out"
echo "minted $out"

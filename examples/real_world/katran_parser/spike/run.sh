#!/usr/bin/env bash
# Build + load Pakeles's generated katran_parser parser as a real kernel
# XDP program (verifier runs at load) and TEST_RUN it over the corpus,
# cross-checking outcomes against the pakeles interpreter. PRIVILEGED:
#   ./dev-priv.sh examples/real_world/katran_parser/spike/run.sh
set -euo pipefail
cd "$(dirname "$0")"
gen=../gen
mkdir -p build
# Compile the XDP wrapper (which #includes the committed generated
# parser.bpf.c) to a BPF object.
clang -O2 -g -target bpf -I"$gen" -I"/usr/include/$(uname -m)-linux-gnu" \
  -c xdp_parser.bpf.c -o build/xdp_parser.bpf.o
cc -O2 -o build/run run.c -lbpf
build/run build/xdp_parser.bpf.o ../factory/corpus.txt

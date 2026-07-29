#!/usr/bin/env bash
# Build the pinned katran balancer + the capture harness and replay the
# corpus through BPF_PROG_TEST_RUN. PRIVILEGED — run via:
#   ./dev-priv.sh oracle/katran/factory/capture.sh [corpus]
set -euo pipefail
cd "$(dirname "$0")"
./fetch.sh
clang -O2 -g -target bpf -Ibuild/tree -I"/usr/include/$(uname -m)-linux-gnu" \
  -c build/tree/katran/lib/bpf/balancer.bpf.c -o build/balancer.o
cc -O2 -o build/capture capture.c -lbpf
build/capture build/balancer.o "${1:-corpus.txt}"

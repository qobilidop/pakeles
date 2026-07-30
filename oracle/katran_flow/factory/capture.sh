#!/usr/bin/env bash
# Mint the katran_flow golden by replaying the corpus through the pinned
# katran balancer (dd915fd2, default build, empty maps + the pakeles
# observation patch) under BPF_PROG_TEST_RUN. PRIVILEGED — run via:
#   ./dev-priv.sh oracle/katran_flow/factory/capture.sh [corpus]
# With no corpus arg, mints the committed golden from corpus.txt; with a
# corpus arg (e.g. smoke.txt) just prints to stdout.
set -euo pipefail
cd "$(dirname "$0")"
KATRAN_PIN="dd915fd2e21ab333eda302d753c92c8806defc8a"
export KATRAN_PIN
./fetch.sh
clang -O2 -g -target bpf -Ibuild/tree -I"/usr/include/$(uname -m)-linux-gnu" \
  -c build/tree/katran/lib/bpf/balancer.bpf.c -o build/balancer.o
cc -O2 -o build/capture capture.c -lbpf
if [ $# -ge 1 ]; then
  build/capture build/balancer.o "$1"
else
  short="${KATRAN_PIN:0:12}"
  out="../../../examples/real_world/katran_flow/conformance/katran.${short}.golden.json"
  mkdir -p "$(dirname "$out")"
  build/capture build/balancer.o corpus.txt > "$out"
  echo "minted $out (katran@${KATRAN_PIN})"
fi

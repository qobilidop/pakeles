#!/usr/bin/env bash
# Quantify the eBPF verifier ceiling for the generated TLS ClientHello
# parser: at which `max_depth` does the fully-unrolled TLV parser still
# fit the kernel's 1M-instruction budget? PRIVILEGED:
#
#   ./dev-priv.sh examples/real_world/tls_clienthello/spike/depth-sweep.sh
#
# Only max_depth varies — the parser graph, the region machinery, and
# the codegen are exactly the committed ones. Each depth is a fresh
# `gen bpf`, compile, and load attempt (the load IS the verifier run).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build/sweep
ir=../tls_clienthello.ir.json
cc -O2 -o build/run run.c -lbpf

for d in 96 64 48 32 24 23 22 20 16 12; do
  python3 - "$ir" "$d" > "build/sweep/ir-$d.json" <<'EOF'
import json, sys
ir = json.load(open(sys.argv[1]))
ir["parser"]["maxDepth"] = int(sys.argv[2])
print(json.dumps(ir))
EOF
  (cd ../../../.. && cargo run --quiet --bin pakeles -- gen bpf \
     --ir "examples/real_world/tls_clienthello/spike/build/sweep/ir-$d.json" \
     --out "examples/real_world/tls_clienthello/spike/build/sweep/parser-$d.bpf.c")
  cp ../gen/parser.h build/sweep/
  clang -O2 -g -target bpf -DPK_BUF_MASK=511u -I build/sweep \
    -I"/usr/include/$(uname -m)-linux-gnu" \
    -DPK_SWEEP_SRC="\"parser-$d.bpf.c\"" \
    -c xdp_sweep.bpf.c -o "build/sweep/prog-$d.o" 2>/dev/null
  log="build/sweep/load-$d.log"
  if build/run "build/sweep/prog-$d.o" ../factory/corpus.txt > /dev/null 2> "$log"; then
    insns=$(grep -o 'processed [0-9]* insns' "$log" | tail -1 || true)
    echo "max_depth=$d: VERIFIER ACCEPTED  ${insns:-}"
  else
    insns=$(grep -o 'processed [0-9]* insns' "$log" | tail -1 || true)
    echo "max_depth=$d: rejected  ${insns:-}"
  fi
done

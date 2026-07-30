#!/usr/bin/env bash
# Build + load Pakeles's generated tls_clienthello parser as a real
# kernel XDP program (the verifier runs at load — TLV loops in eBPF are
# the community pain point this deliverable targets) and TEST_RUN it
# over the corpus, diffing outcomes line-by-line against the SAME
# generated core run in userspace (gate-proven equal to the
# interpreter). PRIVILEGED:
#
#   ./dev-priv.sh oracle/tls_clienthello/spike/run.sh          # committed IR (max_depth 96)
#   PK_DEPTH=22 ./dev-priv.sh oracle/tls_clienthello/spike/run.sh
#
# PK_DEPTH regenerates the parser with a reduced max_depth — nothing
# else changes. The committed max_depth 96 exceeds the kernel's 1M
# instruction budget; 22 is the measured ceiling (depth-sweep.sh).
# Both lanes use the same parser, so the agreement claim holds either
# way; only how many extensions the parser can walk changes.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
gen=../../../examples/tls_clienthello/gen
src=xdp_parser.bpf.c
cflags=(-I"$gen")

if [ -n "${PK_DEPTH:-}" ]; then
  mkdir -p build/depth
  python3 - "$gen/../tls_clienthello.ir.json" "$PK_DEPTH" > build/depth/ir.json <<'EOF'
import json, sys
ir = json.load(open(sys.argv[1]))
ir["parser"]["maxDepth"] = int(sys.argv[2])
print(json.dumps(ir))
EOF
  (cd ../../.. && cargo run --quiet -- gen bpf \
     --ir oracle/tls_clienthello/spike/build/depth/ir.json \
     --out oracle/tls_clienthello/spike/build/depth/parser.bpf.c)
  (cd ../../.. && cargo run --quiet -- gen c \
     --ir oracle/tls_clienthello/spike/build/depth/ir.json \
     --out-dir oracle/tls_clienthello/spike/build/depth)
  gen=build/depth
  cflags=(-I build/depth)
  echo "using max_depth=$PK_DEPTH"
fi

# PK_BUF_MASK matches SCRATCH_BYTES-1 in the wrapper: the tighter the
# bound, the less the verifier has to explore.
clang -O2 -g -target bpf -DPK_BUF_MASK=511u "${cflags[@]}" \
  -I"/usr/include/$(uname -m)-linux-gnu" \
  -c "$src" -o build/xdp_parser.bpf.o
cc -O2 -o build/run run.c -lbpf
cc -O2 "${cflags[@]}" -o build/user user_main.c "$gen/parser.c"
build/run build/xdp_parser.bpf.o ../factory/corpus.txt > build/kernel.json
build/user ../factory/corpus.txt > build/user.json
python3 - <<'EOF'
import json
k = json.load(open("build/kernel.json"))
u = json.load(open("build/user.json"))
assert len(k) == len(u), f"line counts differ: kernel {len(k)} vs user {len(u)}"
bad = [i for i, (a, b) in enumerate(zip(k, u)) if a != b]
for i in bad:
    print(f"MISMATCH line {i}: kernel={k[i]} user={u[i]}")
print(f"{len(k)} corpus lines TEST_RUN vs userspace core: "
      f"{len(k) - len(bad)} agree, {len(bad)} mismatch")
raise SystemExit(1 if bad else 0)
EOF

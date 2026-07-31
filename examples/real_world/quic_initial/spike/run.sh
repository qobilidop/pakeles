#!/usr/bin/env bash
# Build + load Pakeles's generated quic_initial parser as a real kernel
# XDP program (the verifier runs at load) and TEST_RUN it over the
# corpus, diffing outcomes line-by-line against the SAME generated core
# run in userspace (gate-proven equal to the interpreter). PRIVILEGED:
#
#   ./dev-priv.sh examples/real_world/quic_initial/spike/run.sh
#
# The committed max_depth is 12 with 22 states — far under the
# tls_clienthello unroll ceiling — so the interesting question is only
# whether the varint clusters' composed-length var reads stay
# verifier-clean. PK_BUF_MASK matches SCRATCH_BYTES-1 in the wrapper.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
gen=../gen

clang -O2 -g -target bpf -DPK_BUF_MASK=511u -I"$gen" \
  -I"/usr/include/$(uname -m)-linux-gnu" \
  -c xdp_parser.bpf.c -o build/xdp_parser.bpf.o
cc -O2 -o build/run run.c -lbpf
cc -O2 -I"$gen" -o build/user user_main.c "$gen/parser.c"
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

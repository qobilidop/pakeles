#!/usr/bin/env bash
# Build + run the generated-C-in-DPDK spike (unprivileged, in dev.sh):
#
#   ./dev.sh benchmarks/industry/dpdk_ptype/spike/run.sh [bench_iters]
#
# Correctness + coverage over the golden corpus AND the full symex
# witness set, then the benchmark over the corpus.
set -euo pipefail
cd "$(dirname "$0")"
gen=../gen
mkdir -p build
read -ra dpdk_flags <<<"$(pkg-config --cflags --libs libdpdk)"
gcc -O2 -I"$gen" -o build/spike spike.c "$gen/parser.c" "${dpdk_flags[@]}"
python3 - <<'PY'
import json
s = json.load(open("../conformance/vectors.json"))
seen, out = set(), []
for v in s["vectors"]:
    bl = int(v["packet"]["bitLen"])
    if bl % 8:
        continue
    hx = v["packet"]["dataHex"][: bl // 4]
    if hx and hx not in seen:
        seen.add(hx)
        out.append(hx)
open("build/witnesses.txt", "w").write("\n".join(out) + "\n")
print(f"{len(out)} byte-aligned witnesses")
PY
echo "--- witness set (correctness only) ---"
./build/spike build/witnesses.txt 0
echo "--- golden corpus (correctness + bench) ---"
./build/spike ../factory/corpus.txt "${1:-200000}"

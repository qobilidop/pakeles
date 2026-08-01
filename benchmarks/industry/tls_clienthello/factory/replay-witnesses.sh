#!/usr/bin/env bash
# Phase-7 quirk hunt: replay the symex witness set through the pinned
# rustls harness and diff every witness through the same compatibility
# matrix the gate uses. Unprivileged:
#
#   ./dev.sh benchmarks/industry/tls_clienthello/factory/replay-witnesses.sh
#
# Requires benchmarks/industry/tls_clienthello/conformance/vectors.json (gitignored;
# regenerate with `./dev.sh scripts/gen-examples.sh` or
# `cargo run --bin gen_examples tls_clienthello`).
set -euo pipefail
cd "$(dirname "$0")"

vectors=../conformance/vectors.json
[ -f "$vectors" ] || { echo "missing $vectors — regenerate the gallery first"; exit 2; }

python3 - "$vectors" > witnesses.txt <<'EOF'
import json, sys
suite = json.load(open(sys.argv[1]))
print("# symex witnesses (regenerated; see replay-witnesses.sh)")
for v in suite["vectors"]:
    pkt = v["packet"]
    hexstr = pkt.get("dataHex", "")
    if not hexstr:
        continue
    # bit-granular tails can't cross the byte-oriented rustls boundary;
    # skip non-whole-byte witnesses (they are truncation shapes anyway).
    if int(pkt.get("bitLen", len(hexstr) * 4)) % 8 == 0:
        print(f"# --- {v['id']} ---")
        print(hexstr)
EOF
ver="$(grep -A1 '^name = "rustls"$' Cargo.lock | grep version | cut -d'"' -f2)"
RUSTLS_VERSION="$ver" cargo run --release --quiet -- capture witnesses.txt > witnesses.golden.json
echo "replaying $(grep -c '^[0-9a-f]' witnesses.txt) witnesses against rustls $ver"
cd ../../../..
cargo run --quiet -p pakeles-example-tls-clienthello -- --goldens benchmarks/industry/tls_clienthello/factory/witnesses.golden.json

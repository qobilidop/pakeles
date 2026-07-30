#!/usr/bin/env bash
# Mint the tls_clienthello goldens: build the pinned-rustls harness and
# replay the corpus through rustls's Acceptor. Unprivileged — runs in
# the normal dev container:
#
#   ./dev.sh oracle/tls_clienthello/factory/capture.sh
#
# The output filename carries the exact rustls pin (from Cargo.lock),
# making the agreement claim precise ("agrees with rustls X.Y.Z").
set -euo pipefail
cd "$(dirname "$0")"
# NB: the dev image sets a global CARGO_TARGET_DIR, so run via cargo
# rather than a ./target path.
ver="$(grep -A1 '^name = "rustls"$' Cargo.lock | grep version | cut -d'"' -f2)"
out="../../../examples/real_world/tls_clienthello/conformance/clienthello.rustls-${ver}.golden.json"
mkdir -p "$(dirname "$out")"
RUSTLS_VERSION="$ver" cargo run --release --quiet -- capture corpus.txt > "$out"
echo "minted $out"

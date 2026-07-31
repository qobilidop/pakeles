#!/usr/bin/env bash
# Mint the quic_initial golden: regenerate the corpus, build the
# pinned quiche/quinn-proto harness, and replay every entry through
# both oracles' public header decoders. Unprivileged — runs in the
# normal dev container:
#
#   ./dev.sh examples/real_world/quic_initial/factory/capture.sh
#
# The output filename carries the PRIMARY (quiche) pin from
# Cargo.lock; the quinn-proto pin is recorded inside the file header.
set -euo pipefail
cd "$(dirname "$0")"
# NB: the dev image sets a global CARGO_TARGET_DIR, so run via cargo
# rather than a ./target path.
python3 mk_corpus.py > corpus.txt
quiche_ver="$(grep -A1 '^name = "quiche"$' Cargo.lock | grep version | cut -d'"' -f2)"
quinn_ver="$(grep -A1 '^name = "quinn-proto"$' Cargo.lock | grep version | cut -d'"' -f2)"
out="../conformance/initial.quiche-${quiche_ver}.golden.json"
mkdir -p "$(dirname "$out")"
QUICHE_VERSION="$quiche_ver" QUINN_PROTO_VERSION="$quinn_ver" \
  cargo run --release --quiet -- capture corpus.txt > "$out"
echo "minted $out"

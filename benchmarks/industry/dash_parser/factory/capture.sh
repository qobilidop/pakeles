#!/usr/bin/env bash
# Mint the dash_parser golden: generate the observation wrapper around
# the vendored DASH parser, compile with p4c-bm2-ss, and replay the
# corpus through simple_switch. Runs in the normal dev container
# (unprivileged):
#   ./dev.sh benchmarks/industry/dash_parser/factory/capture.sh                # mint committed golden
#   ./dev.sh benchmarks/industry/dash_parser/factory/capture.sh witnesses.txt  # replay any corpus-shaped file to stdout
set -euo pipefail
cd "$(dirname "$0")"
PIN="d5c003dd7774c2b43f275c0233acc73a0ea28d2f"
mkdir -p build
cp ../../../../third_party/dash/dash_parser.p4 \
   ../../../../third_party/dash/dash_headers.p4 build/
python3 instrument.py ../../../../third_party/dash build/main.p4
( cd build && p4c-bm2-ss --arch v1model -o dash.json main.p4 )
if [ $# -ge 1 ]; then
  python3 capture.py build/dash.json "$1" "$PIN"
else
  python3 mk_corpus.py > corpus.txt
  out="../conformance/dash.${PIN:0:12}.golden.json"
  mkdir -p "$(dirname "$out")"
  python3 capture.py build/dash.json corpus.txt "$PIN" > "$out"
  echo "minted $out (DASH@${PIN})"
fi

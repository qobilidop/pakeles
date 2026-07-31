#!/usr/bin/env bash
# Mint the sai_parser golden: instrument a copy of the vendored SONiC
# PINS parser, compile with p4c-bm2-ss, and replay the corpus through
# simple_switch. Runs in the normal dev container (unprivileged):
#   ./dev.sh examples/real_world/sai_parser/factory/capture.sh          # mint committed golden
#   ./dev.sh examples/real_world/sai_parser/factory/capture.sh smoke.txt  # print to stdout
set -euo pipefail
cd "$(dirname "$0")"
PIN="e77250b8dcab96e6f0e6ba1a9643f66771caa46c"
mkdir -p build/parser build/common
python3 instrument.py ../../../../third_party/sonic-pins/parser/sai_parser.p4 build/parser/sai_parser.p4
cp ../../../../third_party/sonic-pins/common/*.p4 build/common/
( cd build/parser && p4c-bm2-ss --arch v1model -DPLATFORM_BMV2 -o sai.json sai_parser.p4 2>/dev/null )
if [ $# -ge 1 ]; then
  python3 capture.py build/parser/sai.json "$1" "$PIN"
else
  out="../conformance/sai.${PIN:0:12}.golden.json"
  mkdir -p "$(dirname "$out")"
  python3 capture.py build/parser/sai.json corpus.txt "$PIN" > "$out"
  echo "minted $out (sonic-pins@${PIN})"
fi

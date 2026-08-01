#!/usr/bin/env bash
# The whole gate — the single definition of "green". CI runs exactly
# this; contributors run it as: ./dev.sh scripts/gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/lint.sh
scripts/test.sh

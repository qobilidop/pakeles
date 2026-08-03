#!/usr/bin/env bash
# The test code may degrade gracefully outside the project container. The gate
# must not: a missing oracle/compiler would silently weaken CI coverage.
set -euo pipefail

required=(
  cc clang llvm-objcopy tshark setpriv
  p4test p4c-bm2-ss simple_switch
  protoc dot pkg-config gcc
)
missing=()
for tool in "${required[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
  echo "missing required gate tools: ${missing[*]}" >&2
  exit 1
fi
if ! pkg-config --exists libdpdk; then
  echo "missing required gate library: libdpdk" >&2
  exit 1
fi

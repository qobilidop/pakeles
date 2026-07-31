#!/usr/bin/env bash
# Privileged variant of dev.sh, ONLY for the golden factories and spikes
# that need a real kernel (bpf()/BPF_PROG_TEST_RUN — flow dissector,
# katran, the TLS eBPF spikes), which the normal unprivileged container
# cannot call. Never used by the normal gate.
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm --privileged \
  -v "$PWD":/work -w /work \
  pakeles-dev "$@"

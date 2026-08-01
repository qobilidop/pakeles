#!/usr/bin/env bash
# Privileged variant of dev.sh, ONLY for the golden factories and spikes
# that need a real kernel (bpf()/BPF_PROG_TEST_RUN — flow dissector,
# katran, the TLS eBPF spikes), which the normal unprivileged container
# cannot call. Never used by the normal gate. Everything else —
# image, mounts, cache volumes — is dev.sh's, by delegation.
set -euo pipefail
PAKELES_PRIVILEGED=1 exec "$(dirname "$0")/dev.sh" "$@"

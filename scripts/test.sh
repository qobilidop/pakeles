#!/usr/bin/env bash
# The test battery. Run as: ./dev.sh scripts/test.sh
#
# gen_vectors first: the conformance suites are gitignored and must be
# regenerated from the committed IRs on a fresh checkout — without it,
# every backend-conformance test silently skips. It writes ONLY
# conformance/vectors.*; committed gen/ artifacts stay untouched so
# the equality guards keep comparing committed against fresh. Release
# profile: the big suites (linux_flow_dissector, dpdk_ptype) are
# symex-bound and several times slower in debug.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo run --release --quiet --bin gen_vectors
cargo test --workspace
(cd python && pytest)

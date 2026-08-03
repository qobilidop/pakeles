#!/usr/bin/env bash
# Refresh the dev image's hash lock with a pinned resolver. This is an explicit
# networked dependency-update operation, not part of the ordinary gate.
set -euo pipefail
cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
cleanup() {
  rm -rf -- "$scratch"
}
trap cleanup EXIT

python3 -m venv "$scratch/venv"
"$scratch/venv/bin/python" -m pip install \
  --disable-pip-version-check \
  "pip-tools==7.5.2"
"$scratch/venv/bin/pip-compile" \
  --allow-unsafe \
  --generate-hashes \
  --output-file=.devcontainer/requirements.txt \
  --strip-extras \
  .devcontainer/requirements.in

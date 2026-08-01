#!/usr/bin/env bash
# Run any command in the pinned dev image (built from .devcontainer/,
# cached after the first build). Ephemeral by design: one container
# per invocation, nothing persists except the named volumes, which
# cache the toolchain and build state across runs. Keep the mounts in
# step with devcontainer.json and the .ci/ host-dir stand-ins in
# ci.yml's gate job.
#
# PAKELES_PRIVILEGED=1 adds --privileged; set only by dev-priv.sh —
# use that wrapper, not this variable, so privileged runs stay a
# deliberate, named act.
set -euo pipefail
cd "$(dirname "$0")"
priv=()
[ -n "${PAKELES_PRIVILEGED:-}" ] && priv=(--privileged)
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm ${priv[@]+"${priv[@]}"} \
  -v "$PWD":/work -w /work \
  -v pakeles-target:/target \
  -v pakeles-cargo:/usr/local/cargo/registry \
  -v pakeles-rustup:/usr/local/rustup \
  pakeles-dev "$@"

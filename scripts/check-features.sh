#!/usr/bin/env bash
# Compile every supported feature boundary, including the library-only shape
# used by consumers that disable the default CLI and symbolic engine.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo check -p pakeles --no-default-features
cargo check -p pakeles --no-default-features --features cli
cargo check -p pakeles --no-default-features --features symex
cargo check -p pakeles --all-features

#!/usr/bin/env bash
# Build the public distributions and assert that their easy-to-omit metadata
# and generated typing/runtime files actually made it into the archives.
set -euo pipefail
cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
cleanup() {
  rm -rf -- "$scratch"
}
trap cleanup EXIT

python_source="$scratch/source"
cp -a python "$python_source"
rm -rf -- \
  "$python_source/build" \
  "$python_source/dist" \
  "$python_source/.pytest_cache" \
  "$python_source/src/pakeles.egg-info"

python_out="$scratch/artifacts"
python3 -m build --no-isolation --outdir "$python_out" "$python_source"

shopt -s nullglob
wheels=("$python_out"/*.whl)
sdists=("$python_out"/*.tar.gz)
if ((${#wheels[@]} != 1 || ${#sdists[@]} != 1)); then
  echo "expected exactly one Python wheel and one sdist" >&2
  exit 1
fi

python3 - "${wheels[0]}" "${sdists[0]}" <<'PY'
import sys
import tarfile
import zipfile
from pathlib import Path

wheel = Path(sys.argv[1])
sdist = Path(sys.argv[2])

with zipfile.ZipFile(wheel) as archive:
    names = set(archive.namelist())
    required = {
        "pakeles/py.typed",
        "pakeles/_pb/ir_pb2.py",
        "pakeles/_pb/ir_pb2.pyi",
        "pakeles/_pb/testvec_pb2.py",
        "pakeles/_pb/testvec_pb2.pyi",
    }
    missing = sorted(required - names)
    if missing:
        raise SystemExit(f"wheel is missing required files: {', '.join(missing)}")
    metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
    if len(metadata_files) != 1:
        raise SystemExit("wheel does not contain exactly one METADATA file")
    metadata = archive.read(metadata_files[0]).decode()
    for field in ("License-Expression: Apache-2.0", "Requires-Python: >=3.10"):
        if field not in metadata:
            raise SystemExit(f"wheel metadata is missing {field!r}")

with tarfile.open(sdist, "r:gz") as archive:
    names = {Path(name).name for name in archive.getnames()}
    for required in ("README.md", "pyproject.toml", "py.typed"):
        if required not in names:
            raise SystemExit(f"sdist is missing {required}")
PY

venv="$scratch/venv"
python3 -m venv --system-site-packages "$venv"
"$venv/bin/python" -m pip install --disable-pip-version-check --no-deps "${wheels[0]}"
"$venv/bin/python" -I -c "import pakeles"

rust_files="$(cargo package -p pakeles --allow-dirty --list)"
for required in README.md src/gen/pakeles.ir.v1alpha1.rs src/gen/pakeles.testvec.v1alpha1.rs; do
  if ! grep -Fxq "$required" <<<"$rust_files"; then
    echo "Rust package is missing $required" >&2
    exit 1
  fi
done
# Feature compilation is owned by check-features.sh; this command checks that
# Cargo can assemble the publishable archive without duplicating that build.
cargo package -p pakeles --allow-dirty --no-verify

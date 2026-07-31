"""The vendored generated-protobuf modules must match fresh generation.

`src/pakeles/_pb/` is committed output (like the Rust side's
`rust/pakeles/src/gen/`, guarded by pakeles-pbgen's test) — this is the
symmetric guard: regenerate from `proto/` and byte-compare, so a
`proto/` edit without the protoc step (python/README.md) is a red gate,
never silent drift. Skips where protoc is absent (it runs in the dev
container, whose protoc is pinned).
"""

import pathlib
import shutil
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
VENDORED = ROOT / "python/src/pakeles/_pb"
GENERATED = [
    "pakeles/ir/v1alpha1/ir_pb2.py",
    "pakeles/ir/v1alpha1/ir_pb2.pyi",
    "pakeles/testvec/v1alpha1/testvec_pb2.py",
    "pakeles/testvec/v1alpha1/testvec_pb2.pyi",
]


def test_vendored_pb_current() -> None:
    if shutil.which("protoc") is None:
        pytest.skip("protoc not available")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [
                "protoc",
                f"--proto_path={ROOT / 'proto'}",
                f"--python_out={tmp}",
                f"--pyi_out={tmp}",
                str(ROOT / "proto/pakeles/ir/v1alpha1/ir.proto"),
                str(ROOT / "proto/pakeles/testvec/v1alpha1/testvec.proto"),
            ],
            check=True,
        )
        for rel in GENERATED:
            fresh = (pathlib.Path(tmp) / rel).read_text()
            committed = (VENDORED / pathlib.Path(rel).name).read_text()
            assert fresh == committed, (
                f"{pathlib.Path(rel).name} drifted from proto/; regenerate "
                "with the protoc command in python/README.md"
            )

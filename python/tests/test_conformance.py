"""The load-bearing test: each gallery description must produce IR
proto-equal to its committed `ir.json` beside it — the canonicalized
artifact (`scripts/gen-examples.sh`) must never drift from the eDSL
source that generates it."""

import os
import subprocess
import sys

import pytest
from google.protobuf import json_format

from conftest import ALL_EXAMPLES, SRC, example_parser, gallery_dir
from pakeles._pb import ir_pb2


@pytest.mark.parametrize("name", ALL_EXAMPLES)
def test_edsl_matches_gallery(name: str) -> None:
    gallery = gallery_dir(name) / f"{name}.ir.json"
    ours = example_parser(name).to_pb()
    committed = json_format.Parse(gallery.read_text(), ir_pb2.Ir())
    assert ours == committed


@pytest.mark.parametrize("name", ALL_EXAMPLES)
def test_own_json_roundtrips_to_same_proto(name: str) -> None:
    p = example_parser(name)
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()


def test_description_main_emits_parseable_json() -> None:
    script = gallery_dir("eth_ipvx_l4") / "eth_ipvx_l4.py"
    out = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    ).stdout
    expected = example_parser("eth_ipvx_l4").to_pb()
    assert json_format.Parse(out, ir_pb2.Ir()) == expected

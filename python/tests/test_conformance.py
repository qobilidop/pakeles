"""The load-bearing test: the eDSL re-authors the gallery description
and must produce IR proto-equal to the committed `ir.json` the Rust
builder generated — two authoring surfaces, one artifact."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from google.protobuf import json_format

from pakeles import ParserDef
from pakeles._pb import ir_pb2
from pakeles.examples.counted_items import CountedItems
from pakeles.examples.dpdk_ptype import DpdkPtype
from pakeles.examples.eth_ipvx_l4 import EthIpvxL4
from pakeles.examples.katran_flow import KatranFlow
from pakeles.examples.linux_flow_dissector import LinuxFlowDissector
from pakeles.examples.sai_parser import SaiParser
from pakeles.examples.tls_clienthello import TlsClienthello
from pakeles.examples.tlv_items import TlvItems

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parents[1] / "src"

BUILDERS: dict[str, type[ParserDef]] = {
    "eth_ipvx_l4": EthIpvxL4,
    "linux_flow_dissector": LinuxFlowDissector,
    "counted_items": CountedItems,
    "tlv_items": TlvItems,
    "dpdk_ptype": DpdkPtype,
    "katran_flow": KatranFlow,
    "sai_parser": SaiParser,
    "tls_clienthello": TlsClienthello,
}

# Gallery groups, mirroring src/examples.rs (SYNTHETIC / REAL_WORLD):
# constructed to isolate a capability vs. checked against a real
# implementation.
SYNTHETIC = ["eth_ipvx_l4", "counted_items", "tlv_items"]
REAL_WORLD = [
    "linux_flow_dissector",
    "dpdk_ptype",
    "katran_flow",
    "sai_parser",
    "tls_clienthello",
]
ALL_EXAMPLES = SYNTHETIC + REAL_WORLD


def gallery_dir(name: str) -> str:
    return f"examples/{'synthetic' if name in SYNTHETIC else 'real_world'}/{name}"


@pytest.mark.parametrize("name", ALL_EXAMPLES)
def test_python_authoring_matches_gallery(name: str) -> None:
    gallery = ROOT / f"{gallery_dir(name)}/{name}.ir.json"
    ours = BUILDERS[name].build().to_pb()
    committed = json_format.Parse(gallery.read_text(), ir_pb2.Ir())
    assert ours == committed


@pytest.mark.parametrize("name", ALL_EXAMPLES)
def test_own_json_roundtrips_to_same_proto(name: str) -> None:
    p = BUILDERS[name].build()
    assert json_format.Parse(p.to_json(), ir_pb2.Ir()) == p.to_pb()


def test_module_main_emits_parseable_json() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "pakeles.examples.eth_ipvx_l4"],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    ).stdout
    assert json_format.Parse(out, ir_pb2.Ir()) == EthIpvxL4.build().to_pb()

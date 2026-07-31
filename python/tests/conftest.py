"""Load gallery example descriptions as modules.

The authoritative example sources live beside their artifacts in
`examples/<group>/<name>/<name>.py` (single source; no package
mirror), so tests import them by path.
"""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from pakeles import Parser

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parents[1] / "src"

SYNTHETIC = ["eth_ipvx_l4", "counted_items", "tlv_items"]
REAL_WORLD = [
    "linux_flow_dissector",
    "dpdk_ptype",
    "katran_flow",
    "sai_parser",
    "tls_clienthello",
]
ALL_EXAMPLES = SYNTHETIC + REAL_WORLD


def gallery_dir(name: str) -> Path:
    group = "synthetic" if name in SYNTHETIC else "real_world"
    return REPO_ROOT / "examples" / group / name


def load_example(name: str) -> ModuleType:
    """Import `examples/<group>/<name>/<name>.py` by path (memoized
    via sys.modules under its bare stem)."""
    if name in sys.modules:
        return sys.modules[name]
    path = gallery_dir(name) / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def example_parser(name: str) -> type[Parser]:
    """The unique Parser subclass defined in a gallery module."""
    module = load_example(name)
    classes = [
        v
        for v in vars(module).values()
        if isinstance(v, type)
        and issubclass(v, Parser)
        and v is not Parser
        and v.__module__ == name
    ]
    assert len(classes) == 1, f"{name}: expected one Parser subclass, got {classes}"
    return classes[0]

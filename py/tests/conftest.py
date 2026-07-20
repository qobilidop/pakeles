"""Pytest configuration for pakeles tests."""

import os
from pathlib import Path

from pytest import Config


def pytest_configure(config: Config) -> None:
    """Add src directory to PYTHONPATH for subprocesses."""
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    pythonpath = os.environ.get("PYTHONPATH", "")
    if pythonpath:
        os.environ["PYTHONPATH"] = f"{src_dir}:{pythonpath}"
    else:
        os.environ["PYTHONPATH"] = src_dir

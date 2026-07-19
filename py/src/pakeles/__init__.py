"""Pakeles Python authoring eDSL.

Declarative header classes, operator-overloaded expressions, and coarse
state combinators that emit the normative Pakeles IR. The Rust CLI
(`pakeles lint`) remains the validation authority.
"""

from pakeles._build import Parser, parser
from pakeles._expr import Expr, FieldSpec, const
from pakeles._header import Header, bits, var_bytes
from pakeles._states import StateChain, accept, extract, reject

__all__ = [
    "Expr",
    "FieldSpec",
    "Header",
    "Parser",
    "StateChain",
    "accept",
    "bits",
    "const",
    "extract",
    "parser",
    "reject",
    "var_bytes",
]

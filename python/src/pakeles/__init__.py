"""Pakeles Python authoring eDSL.

Declarative header classes, operator-overloaded expressions, and coarse
state combinators that emit the normative Pakeles IR. The Rust CLI
(`pakeles lint`) remains the validation authority.
"""

from pakeles._build import Parser, parser
from pakeles._expr import Expr, FieldSpec, const, remaining
from pakeles._header import Header, bits, var_bytes
from pakeles._meta import Meta, MetaFieldSpec, meta_bits
from pakeles._states import StateChain, accept, assign, extract, reject

__all__ = [
    "Expr",
    "FieldSpec",
    "Header",
    "Meta",
    "MetaFieldSpec",
    "Parser",
    "StateChain",
    "accept",
    "assign",
    "bits",
    "const",
    "extract",
    "meta_bits",
    "parser",
    "reject",
    "remaining",
    "var_bytes",
]

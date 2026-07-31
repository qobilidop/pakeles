"""Pakeles Python authoring eDSL.

Declarative header classes, operator-overloaded expressions, and coarse
state combinators that emit the normative Pakeles IR. The Rust CLI
(`pakeles lint`) remains the validation authority.
"""

from pakeles._build import Parser
from pakeles._def import ParserDef
from pakeles._expr import Expr, FieldSpec, const, remaining
from pakeles._header import Header, bits, var_bytes
from pakeles._meta import Meta, MetaFieldSpec, meta_bits
from pakeles._states import (
    ArmKey,
    StateChain,
    Target,
    accept,
    assign,
    extract,
    reject,
)

__all__ = [
    "ArmKey",
    "Expr",
    "FieldSpec",
    "Header",
    "Meta",
    "MetaFieldSpec",
    "Parser",
    "ParserDef",
    "StateChain",
    "Target",
    "accept",
    "assign",
    "bits",
    "const",
    "extract",
    "meta_bits",
    "reject",
    "remaining",
    "var_bytes",
]

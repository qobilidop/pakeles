"""Pakeles Python authoring eDSL.

Declarative header classes, operator-overloaded expressions, and coarse
state combinators that emit the normative Pakeles IR. The Rust CLI
(`pakeles lint`) remains the validation authority.
"""

from pakeles._expr import Expr, FieldSpec, const
from pakeles._header import Header, bits, var_bytes

__all__ = [
    "Expr",
    "FieldSpec",
    "Header",
    "bits",
    "const",
    "var_bytes",
]

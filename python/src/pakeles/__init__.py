"""The Pakeles Python eDSL.

Declarative header classes, operator-overloaded expressions, and
class-based parser definitions (`Parser`: states as methods, targets
as `self.<state>` references) that emit the normative Pakeles IR. The
Rust CLI (`pakeles lint`) remains the validation authority.
"""

from pakeles._expr import Expr, FieldSpec, const, remaining
from pakeles._header import Header, bits, var_bytes
from pakeles._metadata import Metadata, MetadataFieldSpec, metadata_bits
from pakeles._parser import Parser
from pakeles._states import (
    ArmKey,
    State,
    Target,
    accept,
    assign,
    extract,
    goto,
    oneof,
    pop_region,
    push_region,
    reject,
    select,
)

__all__ = [
    "ArmKey",
    "Expr",
    "FieldSpec",
    "Header",
    "Metadata",
    "MetadataFieldSpec",
    "Parser",
    "State",
    "Target",
    "accept",
    "assign",
    "bits",
    "const",
    "extract",
    "goto",
    "metadata_bits",
    "oneof",
    "pop_region",
    "push_region",
    "reject",
    "remaining",
    "select",
    "var_bytes",
]

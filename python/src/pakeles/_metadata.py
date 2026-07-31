"""Declared parse metadata: typed, read-write scalars (see metadata v1 spec)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from ._expr import Operand
from ._pb import ir_pb2


@dataclass
class MetadataFieldSpec(Operand):
    """One declared metadata field; created by `metadata_bits()` in a `Metadata`
    class body. `name` is assigned by the `Metadata` machinery at class
    finalization."""

    width_bits: int
    init: int = 0
    display_name: str = ""
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED
    doc: str = ""
    name: str = ""  # filled by Metadata.__init_subclass__

    @property
    def header(self) -> str:
        """No header instance — metadata fields are parser-scoped. Present
        for parity with FieldSpec/BoundField so generic select-key error
        messages in `_build._check` can format uniformly."""
        return "metadata"

    def as_expr(self):  # -> Expr
        from ._expr import Expr

        return Expr(meta_ref=self)


def metadata_bits(
    width: int,
    display: str = "",
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED,
    *,
    init: int = 0,
    doc: str = "",
) -> MetadataFieldSpec:
    """A declared metadata scalar (1..64 bits, initialized to `init`)."""
    if not 1 <= width <= 64:
        raise ValueError(f"metadata width {width} outside 1..=64")
    if init < 0 or init >= 1 << width:
        raise ValueError(f"metadata init {init} does not fit in {width} bits")
    return MetadataFieldSpec(
        width_bits=width, init=init, display_name=display, format=format, doc=doc
    )


class Metadata:
    """Base class for metadata declarations. Subclass and declare fields:

    class M(Metadata):
        flag = metadata_bits(1)
        acc = metadata_bits(8, init=5)
    """

    _fields: ClassVar[list[MetadataFieldSpec]] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        fields: list[MetadataFieldSpec] = []
        for attr, value in vars(cls).items():
            if isinstance(value, MetadataFieldSpec):
                value.name = attr
                fields.append(value)
        cls._fields = fields
        if not fields:
            raise ValueError(f"metadata class {cls.__name__!r} declares no fields")

    def __init__(self) -> None:
        raise TypeError("Metadata classes are declarations; do not instantiate")

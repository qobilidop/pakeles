"""Declared parse metadata: typed, read-write scalars (see metadata v1 spec)."""

from __future__ import annotations

from dataclasses import dataclass

from ._expr import Operand
from ._pb import ir_pb2


@dataclass
class MetaFieldSpec(Operand):
    """One declared metadata field; created by `meta_bits()` in a `Meta`
    class body. `name` is assigned by the `Meta` machinery at class
    finalization."""

    width_bits: int
    init: int = 0
    display_name: str = ""
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED
    doc: str = ""
    name: str = ""  # filled by Meta.__init_subclass__

    @property
    def header(self) -> str:
        """No header instance — metadata fields are parser-scoped. Present
        for parity with FieldSpec/BoundField so generic select-key error
        messages in `_build._check` can format uniformly."""
        return "metadata"

    def as_expr(self):  # -> Expr
        from ._expr import Expr

        return Expr(meta_ref=self)


def meta_bits(
    width: int,
    display: str = "",
    format: ir_pb2.DisplayFormat = ir_pb2.DISPLAY_FORMAT_UNSPECIFIED,
    *,
    init: int = 0,
    doc: str = "",
) -> MetaFieldSpec:
    """A declared metadata scalar (1..64 bits, initialized to `init`)."""
    if not 1 <= width <= 64:
        raise ValueError(f"metadata width {width} outside 1..=64")
    if init < 0 or init >= 1 << width:
        raise ValueError(f"metadata init {init} does not fit in {width} bits")
    return MetaFieldSpec(
        width_bits=width, init=init, display_name=display, format=format, doc=doc
    )


class Meta:
    """Base class for metadata declarations. Subclass and declare fields:

    class M(Meta):
        flag = meta_bits(1)
        acc = meta_bits(8, init=5)
    """

    _fields: list[MetaFieldSpec] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        fields: list[MetaFieldSpec] = []
        for attr, value in vars(cls).items():
            if isinstance(value, MetaFieldSpec):
                value.name = attr
                fields.append(value)
        cls._fields = fields
        if not fields:
            raise ValueError(f"metadata class {cls.__name__!r} declares no fields")

    def __init__(self) -> None:
        raise TypeError("Meta classes are declarations; do not instantiate")

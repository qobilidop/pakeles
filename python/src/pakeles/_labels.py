"""One vocabulary for dispatch and display: labeled integer enums.

A `LabeledEnum` member is an `int` that may carry a prose display
label. Declaring the protocol registry slice a parser touches as one
enum lets select arms (`{EtherType.IPV4: ...}`) and field display
labels (`bits(labels=EtherType)`) share a single source of truth, so
a mistyped member name fails at import time instead of silently
dispatching a wrong wire value.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import IntEnum
from typing import Self, cast


class LabeledEnum(IntEnum):
    """An `IntEnum` whose members may carry a display label:

        class EtherType(LabeledEnum):
            IPV4 = 0x0800, "IPv4"
            ARP = 0x0806            # label defaults to the member name

    Members are ints: use them directly as select arm keys. Pass the
    class, or a curated list of members, as `bits(labels=...)`.
    """

    _label: str | None

    def __new__(cls, value: int, label: str | None = None) -> Self:
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj._label = label
        return obj

    @property
    def label(self) -> str:
        return self._label if self._label is not None else self.name


# What `bits(labels=...)` accepts: a plain {value: label} mapping, an
# enum class (all members, in definition order), or a curated iterable
# of members (order preserved — labels are a deliberate per-field
# subset, not necessarily the whole registry).
LabelsArg = Mapping[int, str] | type[IntEnum] | Iterable[IntEnum]


def coerce_labels(labels: LabelsArg) -> dict[int, str]:
    """Normalize any accepted `labels=` form to `{int: label}`.

    Plain `IntEnum` members (no `label` attribute) label as their
    member name."""
    if isinstance(labels, Mapping):
        mapping = cast(Mapping[int, str], labels)
        return {int(v): s for v, s in mapping.items()}
    return {
        int(m): m.label if isinstance(m, LabeledEnum) else m.name for m in labels
    }

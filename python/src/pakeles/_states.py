"""Coarse state combinators (tf.data/nom-style): one line per state.

`extract(IPv4).select(IPv4.protocol, {6: self.tcp}, default=reject(...))`
builds one state inside a `Parser` state method; targets are
state-method references (`self.tcp`), resolved to state names at
assembly time. Plain string names remain valid targets. States with no
leading extract start from the other free builders: `assign(...)`,
`select(...)`, `goto(...)`, `push_region(...)`, `pop_region()`.

Arm keys may be single values, `oneof(...)` value sets, `range`s, or —
for multi-key selects — tuples of any of those; sets and ranges expand
to exact per-value arms at `select()` time, in order.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Protocol

from pakeles._expr import (
    BoundField,
    Expr,
    FieldSpec,
    Operand,
    RemainingSpec,
    coerce_expr,
)
from pakeles._header import Header, Instance
from pakeles._metadata import MetadataFieldSpec


@dataclass(frozen=True)
class Accept:
    pass


@dataclass(frozen=True)
class Reject:
    reason: str
    info: bool = False


def accept() -> Accept:
    return Accept()


def reject(reason: str, *, info: bool = False) -> Reject:
    """Explicit reject. `info=True` marks a payload boundary (unknown
    next protocol) rather than malformedness."""
    return Reject(reason=reason, info=info)


class StateRef(Protocol):
    """A state-method reference (`self.parse_x` inside a `Parser`
    body): a zero-argument bound method whose `__name__` is the state
    name. Assembly resolves these to plain name strings; a string
    target remains the P4-convention forward reference."""

    __name__: str

    def __call__(self) -> State: ...


@dataclass(frozen=True)
class OneOf:
    """A value set in an arm key: `oneof(0x8847, 0x8848)` sends every
    listed value to one target (expanded to exact arms, in order)."""

    values: tuple[int, ...]


def oneof(*values: int) -> OneOf:
    if len(values) < 2:
        raise ValueError("oneof() needs at least two values")
    return OneOf(values=values)


Target = str | StateRef | Accept | Reject
ArmValue = int | tuple[int, ...]  # one arm's exact value(s), post-expansion
ArmKey = int | OneOf | range | tuple["int | OneOf | range", ...]
SelectKey = FieldSpec | BoundField | MetadataFieldSpec | RemainingSpec
RegionOp = tuple[str, Expr | None]  # ("push", len_expr) | ("pop", None)


def _expand_arm(key: ArmKey) -> list[ArmValue]:
    """One authored arm key -> its exact arm values, in authored order."""
    if isinstance(key, OneOf):
        return list(key.values)
    if isinstance(key, range):
        return list(key)
    if isinstance(key, tuple):
        pools = [
            list(k.values) if isinstance(k, OneOf) else list(k) if isinstance(k, range) else [k]
            for k in key
        ]
        return [tuple(combo) for combo in itertools.product(*pools)]
    return [key]


def _resolve(header: type[Header] | Instance, instance: str | None) -> tuple[type[Header], str | None]:
    if isinstance(header, Instance):
        if instance is not None:
            raise ValueError("pass either Header['name'] or instance=, not both")
        return header.header_type, header.name
    return header, instance


@dataclass
class SelectSpec:
    keys: tuple[SelectKey, ...]
    arms: dict[ArmValue, Target]
    default: Target


@dataclass
class State:
    """One state under construction: extracts, assigns, plus one transition."""

    extracts: list[tuple[type[Header], str | None]] = dc_field(
        default_factory=list[tuple[type[Header], str | None]]
    )
    assigns: list[tuple[MetadataFieldSpec, Expr]] = dc_field(
        default_factory=list[tuple[MetadataFieldSpec, Expr]]
    )
    region_ops: list[RegionOp] = dc_field(default_factory=list[RegionOp])
    transition: SelectSpec | Target | None = None

    def _need_open(self) -> None:
        if self.transition is not None:
            raise ValueError("state already has a transition")

    def extract(
        self, header: type[Header] | Instance, instance: str | None = None
    ) -> State:
        self._need_open()
        self.extracts.append(_resolve(header, instance))
        return self

    def assign(self, target: MetadataFieldSpec, value: Expr | Operand | int) -> State:
        self._need_open()
        self.assigns.append((target, coerce_expr(value)))
        return self

    def push_region(self, length: Expr | Operand | int) -> State:
        """Open a sized region of `length` BYTES at the cursor (region
        ops run after assigns, before the transition, in call order)."""
        self._need_open()
        self.region_ops.append(("push", coerce_expr(length)))
        return self

    def pop_region(self) -> State:
        """Close the innermost sized region (exact-mode: the cursor
        must sit at the region end)."""
        self._need_open()
        self.region_ops.append(("pop", None))
        return self

    def select(
        self,
        key: SelectKey | tuple[SelectKey, ...],
        arms: dict[ArmKey, Target],
        *,
        default: Target,
    ) -> State:
        self._need_open()
        keys = key if isinstance(key, tuple) else (key,)
        expanded: dict[ArmValue, Target] = {}
        for arm_key, target in arms.items():
            for value in _expand_arm(arm_key):
                if value in expanded:
                    raise ValueError(f"duplicate select arm value {value!r}")
                expanded[value] = target
        self.transition = SelectSpec(keys=keys, arms=expanded, default=default)
        return self

    def then(self, target: Target) -> State:
        self._need_open()
        self.transition = target
        return self

    def accept(self) -> State:
        return self.then(Accept())


def extract(header: type[Header] | Instance, instance: str | None = None) -> State:
    return State().extract(header, instance)


def assign(target: MetadataFieldSpec, value: Expr | Operand | int) -> State:
    return State().assign(target, value)


def select(
    key: SelectKey | tuple[SelectKey, ...],
    arms: dict[ArmKey, Target],
    *,
    default: Target,
) -> State:
    """A state that only dispatches (no extract)."""
    return State().select(key, arms, default=default)


def goto(target: Target) -> State:
    """A pure pass-through state: one unconditional transition."""
    return State().then(target)


def push_region(length: Expr | Operand | int) -> State:
    return State().push_region(length)


def pop_region() -> State:
    return State().pop_region()

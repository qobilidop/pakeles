"""Coarse state combinators (tf.data/nom-style): one line per state.

`extract(IPv4).select(IPv4.protocol, {6: self.tcp}, default=reject(...))`
builds one state inside a `Parser` state method; targets are
state-method references (`self.tcp`), resolved to state names at
assembly time. Plain string names remain valid targets. States with no
leading extract start from the other free builders: `assign(...)`,
`select(...)`, `goto(...)`, `push_region(...)`, `pop_region()`.

A target may also be an inline `State` chain (an anonymous
continuation, e.g. `{V.RETRY: assign(M.kind, K.RETRY).accept()}`):
assembly hoists it into a real state named `<parent>__<arm label>`
(`__default` for the default, `__then` for a direct transition), with
`.named(...)` overriding the generated name and `.doc(...)` supplying
the prose a method docstring would. One inline `State` object reused
across several arms (or shared via a variable) hoists once.

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


@dataclass(frozen=True)
class Masked:
    """A ternary arm key: `masked(0, 0xfe00)` matches any value whose
    bits under the mask equal the value's (the IR's Masked keyset
    entry; first-match arm order is the priority, as ever)."""

    value: int
    mask: int


def masked(value: int, mask: int) -> Masked:
    if value & ~mask:
        raise ValueError(f"masked value {value:#x} has bits outside its mask {mask:#x}")
    return Masked(value=value, mask=mask)


# One arm's value(s), post-expansion: exact ints and/or ternary Masked.
ArmValue = int | Masked | tuple["int | Masked", ...]
ArmKey = int | OneOf | range | Masked | tuple["int | OneOf | range | Masked", ...]
SelectKey = FieldSpec | BoundField | MetadataFieldSpec | RemainingSpec
RegionOp = tuple[str, Expr | None]  # ("push", len_expr) | ("pop", None)


def _key_labels(key: SelectKey) -> dict[int, str]:
    if isinstance(key, BoundField):
        return key.spec.labels
    return getattr(key, "labels", None) or {}


def _first_missing(covered: set[int], total: int, want: int) -> list[int]:
    """The `want` smallest values in [0, total) not in `covered`,
    without iterating the (possibly 2^64-sized) range."""
    out: list[int] = []
    prev = -1
    for v in sorted(covered) + [total]:
        for m in range(prev + 1, v):
            out.append(m)
            if len(out) == want:
                return out
        prev = v
    return out


def _exhaustive_default(keys: tuple[SelectKey, ...], arms: dict[ArmValue, Target]) -> Reject:
    """Prove the arms cover every representable value of the key,
    licensing an omitted `default=`; the synthesized IR default is a
    machine-written unreachable reject. Conservative by design: a
    single fixed-width key with exact-value arms only — masked arms
    and multi-key selects always need an explicit default."""
    no_default = "select has no default= and "
    if len(keys) != 1:
        raise ValueError(
            no_default + "exhaustiveness is only provable for a "
            "single key; pass an explicit default"
        )
    key = keys[0]
    width = key.width_bits
    if width is None:
        raise ValueError(
            no_default + f"key {key.header}.{key.name} is not a "
            "fixed-width field; pass an explicit default"
        )
    if any(not isinstance(v, int) for v in arms):
        raise ValueError(
            no_default + "masked arms cannot prove exhaustiveness; "
            "pass an explicit default"
        )
    total = 1 << width
    covered = {v for v in arms if isinstance(v, int) and 0 <= v < total}
    if len(covered) == total:
        return Reject(reason="unreachable")
    labels = _key_labels(key)
    shown = [
        f"{m} ({labels[m]})" if m in labels else str(m)
        for m in _first_missing(covered, total, 8)
    ]
    listed = ", ".join(shown) + (", ..." if total - len(covered) > 8 else "")
    raise ValueError(
        f"select on {key.header}.{key.name} ({width} bits) is not "
        f"exhaustive: arms cover {len(covered)} of {total} values, "
        f"missing {listed}; add arms or pass default="
    )


def _expand_arm(key: ArmKey) -> list[ArmValue]:
    """One authored arm key -> its exact arm values, in authored order."""
    if isinstance(key, OneOf):
        return list(key.values)
    if isinstance(key, range):
        return list(key)
    if isinstance(key, tuple):
        pools: list[list[int | Masked]] = [
            list(k.values)
            if isinstance(k, OneOf)
            else list(k)
            if isinstance(k, range)
            else [k]
            for k in key
        ]
        return [tuple(combo) for combo in itertools.product(*pools)]
    return [key]


def _resolve(
    header: type[Header] | Instance, instance: str | None
) -> tuple[type[Header], str | None]:
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
    doc_text: str | None = None
    """State prose for `annotations["doc"]`: a state method's
    docstring (which wins when both are present), else `.doc(...)`."""
    name_override: str | None = None
    """Explicit state name for an inline target (`.named(...)`);
    ignored on a method state, whose def name is its name."""

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
        default: Target | None = None,
    ) -> State:
        """`default=` may be omitted when the arms provably cover every
        representable key value (single fixed-width key, exact values):
        the IR's mandatory default becomes a synthesized unreachable
        reject, and a coverage gap is an error naming the missing
        values instead of a silent fall-through."""
        self._need_open()
        keys = key if isinstance(key, tuple) else (key,)
        expanded: dict[ArmValue, Target] = {}
        for arm_key, target in arms.items():
            for value in _expand_arm(arm_key):
                if value in expanded:
                    raise ValueError(f"duplicate select arm value {value!r}")
                expanded[value] = target
        if default is None:
            default = _exhaustive_default(keys, expanded)
        self.transition = SelectSpec(keys=keys, arms=expanded, default=default)
        return self

    def then(self, target: Target) -> State:
        self._need_open()
        self.transition = target
        return self

    def accept(self) -> State:
        return self.then(Accept())

    def doc(self, text: str) -> State:
        """Attach state prose, the inline-target counterpart of a
        method docstring (callable anywhere in the chain)."""
        self.doc_text = text
        return self

    def named(self, name: str) -> State:
        """Override the auto-generated name when this chain is an
        inline target (callable anywhere in the chain)."""
        self.name_override = name
        return self


Target = str | StateRef | Accept | Reject | State
"""A transition target: a state name, a state-method reference, a
terminal, or an inline `State` chain hoisted at assembly time."""


def extract(header: type[Header] | Instance, instance: str | None = None) -> State:
    return State().extract(header, instance)


def assign(target: MetadataFieldSpec, value: Expr | Operand | int) -> State:
    return State().assign(target, value)


def select(
    key: SelectKey | tuple[SelectKey, ...],
    arms: dict[ArmKey, Target],
    *,
    default: Target | None = None,
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

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
for multi-key selects — tuples of any of those. Unit-step ranges lower to
one compact IR range entry; conveniences that genuinely expand have a
fixed budget so an authored Cartesian product cannot exhaust memory.
"""

from __future__ import annotations

import inspect
import itertools
import os
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


@dataclass(frozen=True)
class RangeValue:
    """Inclusive compact range after authoring-time normalization."""

    lo: int
    hi: int


# One arm's value(s), post-expansion.
ScalarArmValue = int | Masked | RangeValue
ArmValue = ScalarArmValue | tuple[ScalarArmValue, ...]
ArmKey = int | OneOf | range | Masked | tuple["int | OneOf | range | Masked", ...]
SelectKey = FieldSpec | BoundField | MetadataFieldSpec | RemainingSpec
RegionOp = tuple[str, Expr | None]  # ("push", len_expr) | ("pop", None)


_PKG_DIR = os.path.dirname(__file__)


def _caller_src() -> tuple[str, int] | None:
    """(file, line) of the nearest stack frame outside this package."""
    frame = inspect.currentframe()
    while frame is not None:
        filename = frame.f_code.co_filename
        # Skip this package and synthesized frames (dataclass __init__
        # is compiled from "<string>").
        if not filename.startswith("<") and os.path.dirname(filename) != _PKG_DIR:
            return filename, frame.f_lineno
        frame = frame.f_back
    return None


def _key_labels(key: SelectKey) -> dict[int, str]:
    if isinstance(key, BoundField):
        return key.spec.labels
    return getattr(key, "labels", None) or {}


def _first_missing(covered: list[tuple[int, int]], total: int, want: int) -> list[int]:
    """The `want` smallest values in [0, total) not in `covered`,
    without iterating the (possibly 2^64-sized) range."""
    out: list[int] = []
    cursor = 0
    for lo, hi in covered + [(total, total)]:
        for m in range(cursor, lo):
            out.append(m)
            if len(out) == want:
                return out
        cursor = max(cursor, hi + 1)
    return out


def _covered_intervals(
    arms: dict[ArmValue, Target], total: int
) -> tuple[list[tuple[int, int]], int] | None:
    intervals: list[tuple[int, int]] = []
    for value in arms:
        if isinstance(value, int):
            if 0 <= value < total:
                intervals.append((value, value))
        elif isinstance(value, RangeValue):
            lo, hi = max(0, value.lo), min(total - 1, value.hi)
            if lo <= hi:
                intervals.append((lo, hi))
        else:
            return None
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged, sum(hi - lo + 1 for lo, hi in merged)


def _exhaustive_default(
    keys: tuple[SelectKey, ...], arms: dict[ArmValue, Target]
) -> Reject:
    """Prove the arms cover every representable value of the key,
    licensing an omitted `default=`; the synthesized IR default is a
    machine-written unreachable reject. Conservative by design: a
    single fixed-width key with exact/range arms only — masked arms and
    multi-key selects always need an explicit default."""
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
    total = 1 << width
    coverage = _covered_intervals(arms, total)
    if coverage is None:
        raise ValueError(
            no_default + "masked arms or multi-key arms cannot prove exhaustiveness; "
            "pass an explicit default"
        )
    covered, covered_count = coverage
    if covered_count == total:
        return Reject(reason="unreachable")
    labels = _key_labels(key)
    shown = [
        f"{m} ({labels[m]})" if m in labels else str(m)
        for m in _first_missing(covered, total, 8)
    ]
    listed = ", ".join(shown) + (", ..." if total - covered_count > 8 else "")
    raise ValueError(
        f"select on {key.header}.{key.name} ({width} bits) is not "
        f"exhaustive: arms cover {covered_count} of {total} values, "
        f"missing {listed}; add arms or pass default="
    )


_MAX_EXPANDED_ARMS = 10_000
_MAX_COMPACT_RANGE_ARMS = 1_000


def _range_pool(key: range) -> list[ScalarArmValue]:
    if not key:
        raise ValueError("empty range select arm")
    if key.step == 1:
        return [RangeValue(key.start, key.stop - 1)]
    if len(key) > _MAX_EXPANDED_ARMS:
        raise ValueError(
            f"non-unit range expands to {len(key)} arms; limit is {_MAX_EXPANDED_ARMS}"
        )
    return list(key)


def _expand_arm(key: ArmKey) -> list[ArmValue]:
    """One authored arm key -> compact/expanded values in authored order."""
    if isinstance(key, OneOf):
        return [value for value in key.values]
    if isinstance(key, range):
        return [value for value in _range_pool(key)]
    if isinstance(key, tuple):
        pools: list[list[ScalarArmValue]] = [
            list(k.values)
            if isinstance(k, OneOf)
            else _range_pool(k)
            if isinstance(k, range)
            else [k]
            for k in key
        ]
        combinations = 1
        for pool in pools:
            combinations *= len(pool)
            if combinations > _MAX_EXPANDED_ARMS:
                raise ValueError(
                    f"select arm Cartesian product expands to {combinations} arms; "
                    f"limit is {_MAX_EXPANDED_ARMS}"
                )
        return [tuple(combo) for combo in itertools.product(*pools)]
    return [key]


def _scalar_values_overlap(left: ScalarArmValue, right: ScalarArmValue) -> bool:
    if isinstance(left, Masked) or isinstance(right, Masked):
        return left == right
    left_lo, left_hi = (
        (left.lo, left.hi) if isinstance(left, RangeValue) else (left, left)
    )
    right_lo, right_hi = (
        (right.lo, right.hi) if isinstance(right, RangeValue) else (right, right)
    )
    return left_lo <= right_hi and right_lo <= left_hi


def _arm_values_overlap(left: ArmValue, right: ArmValue) -> bool:
    if isinstance(left, tuple) or isinstance(right, tuple):
        return (
            isinstance(left, tuple)
            and isinstance(right, tuple)
            and len(left) == len(right)
            and all(
                _scalar_values_overlap(left_part, right_part)
                for left_part, right_part in zip(left, right)
            )
        )
    return _scalar_values_overlap(left, right)


def _contains_range(value: ArmValue) -> bool:
    if isinstance(value, tuple):
        return any(isinstance(part, RangeValue) for part in value)
    return isinstance(value, RangeValue)


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

    extracts: list[tuple[type[Header], str | None, bool]] = dc_field(
        default_factory=list[tuple[type[Header], str | None, bool]]
    )
    """(header, instance, lookahead) triples, in declared order."""
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
    src: tuple[str, int] | None = dc_field(default=None, compare=False)
    """Authoring site (file, line): the first frame outside this
    package when the chain started. Diagnostics only — deliberately
    never emitted into the IR, so goldens stay machine-independent."""

    def __post_init__(self) -> None:
        if self.src is None:
            self.src = _caller_src()

    def src_note(self) -> str:
        """` (defined at file:line)` for error messages, or ``."""
        if self.src is None:
            return ""
        return f" (defined at {self.src[0]}:{self.src[1]})"

    def _need_open(self) -> None:
        if self.transition is not None:
            raise ValueError("state already has a transition")

    def extract(
        self, header: type[Header] | Instance, instance: str | None = None
    ) -> State:
        self._need_open()
        self.extracts.append((*_resolve(header, instance), False))
        return self

    def lookahead(
        self, header: type[Header] | Instance, instance: str | None = None
    ) -> State:
        """Peek a header: bind its fields (they drive selects and appear
        in the observables at their true offsets) WITHOUT advancing the
        cursor — P4's `lookahead<T>()`. The peeked header must be
        all-fixed-width (Rust validator authority, W9)."""
        self._need_open()
        self.extracts.append((*_resolve(header, instance), True))
        return self

    def assign(self, target: MetadataFieldSpec, value: Expr | Operand | int) -> State:
        self._need_open()
        self.assigns.append((target, coerce_expr(value)))
        return self

    def push_region(
        self,
        length: Expr | Operand | int | None = None,
        *,
        bits: Expr | Operand | int | None = None,
    ) -> State:
        """Open a sized region at the cursor (region ops run after
        assigns, before the transition, in call order). `length` is in
        BYTES — the common wire unit, sugar for `bits=length * 8`;
        pass `bits=` for a bit-denominated length."""
        self._need_open()
        if (length is None) == (bits is None):
            raise ValueError("push_region takes exactly one of length (bytes) or bits=")
        expr = coerce_expr(length) * 8 if length is not None else coerce_expr(bits)
        self.region_ops.append(("push", expr))
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
        representable key value (single fixed-width key, exact/range values):
        the IR's mandatory default becomes a synthesized unreachable
        reject, and a coverage gap is an error naming the missing
        values instead of a silent fall-through."""
        self._need_open()
        keys = key if isinstance(key, tuple) else (key,)
        expanded: dict[ArmValue, Target] = {}
        compact_ranges: list[ArmValue] = []
        for arm_key, target in arms.items():
            for value in _expand_arm(arm_key):
                if len(expanded) >= _MAX_EXPANDED_ARMS:
                    raise ValueError(
                        f"select expands past {_MAX_EXPANDED_ARMS} arms; "
                        "use compact ranges or split the state"
                    )
                if value in expanded:
                    raise ValueError(f"duplicate select arm value {value!r}")
                contains_range = _contains_range(value)
                if contains_range and len(compact_ranges) >= _MAX_COMPACT_RANGE_ARMS:
                    raise ValueError(
                        f"select has more than {_MAX_COMPACT_RANGE_ARMS} compact range arms"
                    )
                candidates = expanded if contains_range else compact_ranges
                overlap = next(
                    (
                        existing
                        for existing in candidates
                        if _arm_values_overlap(value, existing)
                    ),
                    None,
                )
                if overlap is not None:
                    raise ValueError(
                        f"overlapping select arm values {overlap!r} and {value!r}"
                    )
                expanded[value] = target
                if contains_range:
                    compact_ranges.append(value)
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


def lookahead(header: type[Header] | Instance, instance: str | None = None) -> State:
    """A state chain starting with a peek (see `State.lookahead`)."""
    return State().lookahead(header, instance)


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


def push_region(
    length: Expr | Operand | int | None = None,
    *,
    bits: Expr | Operand | int | None = None,
) -> State:
    return State().push_region(length, bits=bits)


def pop_region() -> State:
    return State().pop_region()

"""The `Parser` base class: states as methods, targets as
`self.<state>` references.

    class EthIpvxL4(Parser):
        max_depth = 4

        def parse_ethernet(self) -> State:
            return extract(Ethernet).select(
                Ethernet.ethertype,
                {0x0800: self.parse_ipv4, 0x86DD: self.parse_ipv6},
                default=reject("unsupported ethertype", info=True),
            )
        ...

The def name is the IR state name, written exactly once; a transition
target is the bound method itself, so a typo is an unknown-attribute
error in the editor and jump-to-def/rename work. Bodies run only at
assembly time (`to_pb()`/`to_json()`/`save()`/`check()`), so forward
references, back edges, and self-loops cost nothing.

A target may also be an inline `State` chain; assembly hoists it into
a real state named `<parent>__<arm label>` (see the `_states` module
doc). Single-use one-or-two-op continuations read best inline; keep a
named method for anything shared or carrying paragraph-length prose.

The first-defined state is the start unless a `start = <method>`
attribute says otherwise (mixin states precede the class body's own in
definition order — set `start` explicitly when mixing in). Underscore
names are helpers, not states. Subclasses inherit, add, and override
states; an override keeps the overridden state's position, and `start`
resolves by name against the final class, so an inherited `start` picks
up overrides.
"""

from __future__ import annotations

import inspect
from enum import IntEnum
from typing import Any, ClassVar, Protocol

from pakeles._build import Assembly
from pakeles._header import snake
from pakeles._metadata import Metadata
from pakeles._pb import ir_pb2
from pakeles._states import (
    Accept,
    ArmValue,
    Masked,
    RangeValue,
    Reject,
    SelectSpec,
    State,
    Target,
)

_RESERVED = frozenset(
    {"name", "max_depth", "metadata", "start", "check", "to_pb", "to_json", "save"}
)


class StateFunc(Protocol):
    """An unbound state method, as referenced in a class body
    (`start = parse_ethernet`)."""

    __name__: str

    def __call__(self, _instance: Any, /) -> State: ...


def _label_part(value: int | Masked | RangeValue) -> str:
    if isinstance(value, Masked):
        return f"m{value.value:x}_{value.mask:x}"
    if isinstance(value, RangeValue):
        return f"r{value.lo}_{value.hi}"
    if isinstance(value, IntEnum):
        return value.name.lower()
    return f"v{value}"


def _arm_label(arm_key: ArmValue) -> str:
    parts = arm_key if isinstance(arm_key, tuple) else (arm_key,)
    return "_".join(_label_part(p) for p in parts)


def _resolve_all(states: dict[str, State]) -> None:
    """Swap state-method references for their state-name strings and
    hoist inline `State` targets into named entries of `states`.

    Deterministic order: method states in definition order; within a
    state, select arms in authored order, then the default, then a
    direct target; nested inline states depth-first. Hoisted names are
    `<parent>__<label>` unless `.named(...)` overrides; one inline
    object reached twice (oneof/range expansion, or author reuse via a
    variable) hoists once, under its first-encountered name."""
    hoisted: dict[int, str] = {}

    def resolve(target: Target, parent: str, label: str) -> str | Accept | Reject:
        if isinstance(target, (str, Accept, Reject)):
            return target
        if isinstance(target, State):
            if (name := hoisted.get(id(target))) is not None:
                return name
            name = target.name_override or f"{parent}__{label}"
            if name in states:
                raise ValueError(
                    f"inline state name {name!r} (target of {parent!r}) "
                    f"collides with an existing state; use .named() to "
                    f"disambiguate" + target.src_note()
                )
            states[name] = target
            hoisted[id(target)] = name
            resolve_state(name, target)
            return name
        return target.__name__

    def resolve_state(name: str, state: State) -> None:
        tr = state.transition
        if isinstance(tr, SelectSpec):
            tr.arms = {k: resolve(t, name, _arm_label(k)) for k, t in tr.arms.items()}
            tr.default = resolve(tr.default, name, "default")
        elif tr is not None:
            state.transition = resolve(tr, name, "then")

    for name, state in list(states.items()):
        resolve_state(name, state)


class Parser:
    """Base class for parser definitions (see module doc)."""

    name: ClassVar[str | None] = None
    """IR parser name; defaults to the snake_cased class name."""

    max_depth: ClassVar[int]

    metadata: ClassVar[type[Metadata] | None] = None

    start: ClassVar[StateFunc | None] = None
    """Start state override; defaults to the first-defined state."""

    @classmethod
    def _state_functions(cls) -> dict[str, Any]:
        """State methods in definition order, base classes first; an
        override keeps the overridden def's position."""
        funcs: dict[str, Any] = {}
        for klass in reversed(cls.__mro__):
            if klass is Parser or klass is object:
                continue
            for attr, value in vars(klass).items():
                if attr.startswith("_") or attr in _RESERVED:
                    continue
                if inspect.isfunction(value):
                    funcs[attr] = value
        return funcs

    @classmethod
    def _assemble(cls) -> Assembly:
        """Run each state method once and assemble the validated IR."""
        if cls is Parser:
            raise TypeError("assemble on a Parser subclass, not Parser itself")
        if not hasattr(cls, "max_depth"):
            raise ValueError(f"{cls.__name__} must set max_depth")
        funcs = cls._state_functions()
        if not funcs:
            raise ValueError(f"{cls.__name__} defines no state methods")
        inst = cls()
        states: dict[str, State] = {}
        for sname, func in funcs.items():
            state = getattr(inst, sname)()
            if not isinstance(state, State):
                raise TypeError(
                    f"state method {sname!r} returned "
                    f"{type(state).__name__}, expected a State "
                    f"(underscore-prefix helper methods)"
                )
            if method_doc := inspect.getdoc(func):
                state.doc_text = method_doc
            states[sname] = state
        _resolve_all(states)
        start = cls.start
        start_name = start.__name__ if start is not None else next(iter(funcs))
        # cls.__doc__ (not inspect.getdoc): every class body defines its
        # own __doc__, so an undocumented subclass stays undocumented
        # instead of inheriting this base class's docstring.
        doc = inspect.cleandoc(cls.__doc__) if cls.__doc__ else None
        return Assembly(
            cls.name or snake(cls.__name__),
            max_depth=cls.max_depth,
            start=start_name,
            states=states,
            metadata=cls.metadata,
            doc=doc,
        )

    @classmethod
    def check(cls) -> None:
        """Assemble now, discarding the result: raises on any
        authoring error the fast-fail checks can catch."""
        cls._assemble()

    @classmethod
    def to_pb(cls) -> ir_pb2.Ir:
        return cls._assemble().to_pb()

    @classmethod
    def to_json(cls) -> str:
        return cls._assemble().to_json()

    @classmethod
    def save(cls, path: str) -> None:
        cls._assemble().save(path)

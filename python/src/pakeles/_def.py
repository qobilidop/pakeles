"""Class-based parser definitions: states as methods, targets as
`self.<state>` references.

    class EthIpvxL4(ParserDef):
        max_depth = 4

        def parse_ethernet(self) -> StateChain:
            return extract(Ethernet).select(
                Ethernet.ethertype,
                {0x0800: self.parse_ipv4, 0x86DD: self.parse_ipv6},
                default=reject("unsupported ethertype", info=True),
            )
        ...

The def name is the IR state name, written exactly once; a transition
target is the bound method itself, so a typo is an unknown-attribute
error in the editor and jump-to-def/rename work. Bodies run only at
`build()`, so forward references, back edges, and self-loops cost
nothing.

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
from typing import Any, ClassVar, Protocol

from pakeles._build import Parser
from pakeles._header import snake
from pakeles._meta import Meta
from pakeles._states import Accept, Reject, SelectSpec, StateChain, Target

_RESERVED = frozenset({"name", "max_depth", "metadata", "start", "build"})


class StateFunc(Protocol):
    """An unbound state method, as referenced in a class body
    (`start = parse_ethernet`)."""

    __name__: str

    def __call__(self, _instance: Any, /) -> StateChain: ...


def _target_name(target: Target) -> Target:
    if isinstance(target, (str, Accept, Reject)):
        return target
    return target.__name__


def _resolve_refs(chain: StateChain) -> StateChain:
    """Swap state-method references for their state-name strings."""
    tr = chain.transition
    if isinstance(tr, SelectSpec):
        tr.arms = {k: _target_name(t) for k, t in tr.arms.items()}
        tr.default = _target_name(tr.default)
    elif tr is not None:
        chain.transition = _target_name(tr)
    return chain


class ParserDef:
    """Base class for class-based parser definitions (see module doc)."""

    name: ClassVar[str | None] = None
    """IR parser name; defaults to the snake_cased class name."""

    max_depth: ClassVar[int]

    metadata: ClassVar[type[Meta] | None] = None

    start: ClassVar[StateFunc | None] = None
    """Start state override; defaults to the first-defined state."""

    @classmethod
    def _state_functions(cls) -> dict[str, Any]:
        """State methods in definition order, base classes first; an
        override keeps the overridden def's position."""
        funcs: dict[str, Any] = {}
        for klass in reversed(cls.__mro__):
            if klass is ParserDef or klass is object:
                continue
            for attr, value in vars(klass).items():
                if attr.startswith("_") or attr in _RESERVED:
                    continue
                if inspect.isfunction(value):
                    funcs[attr] = value
        return funcs

    @classmethod
    def build(cls) -> Parser:
        """Run each state method once and assemble the `Parser`."""
        if cls is ParserDef:
            raise TypeError("build() must be called on a ParserDef subclass")
        if not hasattr(cls, "max_depth"):
            raise ValueError(f"{cls.__name__} must set max_depth")
        funcs = cls._state_functions()
        if not funcs:
            raise ValueError(f"{cls.__name__} defines no state methods")
        inst = cls()
        states: dict[str, StateChain] = {}
        for sname in funcs:
            chain = getattr(inst, sname)()
            if not isinstance(chain, StateChain):
                raise TypeError(
                    f"state method {sname!r} returned "
                    f"{type(chain).__name__}, expected a StateChain "
                    f"(underscore-prefix helper methods)"
                )
            states[sname] = _resolve_refs(chain)
        start = cls.start
        start_name = start.__name__ if start is not None else next(iter(funcs))
        return Parser(
            cls.name or snake(cls.__name__),
            max_depth=cls.max_depth,
            start=start_name,
            states=states,
            metadata=cls.metadata,
        )

"""Inline `State` targets: hoisting, deterministic naming, `.named()`
and `.doc()`, sharing, nesting, and collisions."""

import pytest

from pakeles import (
    Header,
    LabeledEnum,
    Metadata,
    Parser,
    State,
    assign,
    bits,
    extract,
    metadata_bits,
    oneof,
    reject,
)


class Kind(LabeledEnum):
    A = 1
    B = 2


class H(Header):
    tag = bits(8)


class M(Metadata):
    kind = metadata_bits(2)


def state_names(parser: type[Parser]) -> list[str]:
    return [s.name for s in parser.to_pb().parser.states]


def state_by_name(parser: type[Parser], name: str):
    for s in parser.to_pb().parser.states:
        if s.name == name:
            return s
    raise AssertionError(f"no state {name!r}")


class ArmInline(Parser):
    max_depth = 3
    metadata = M

    def parse_h(self) -> State:
        return extract(H).select(
            H.tag,
            {
                Kind.A: assign(M.kind, Kind.A).accept(),
                7: assign(M.kind, Kind.B).accept(),
            },
            default=reject("unknown tag"),
        )


def test_arm_inline_hoists_with_enum_and_value_labels() -> None:
    assert state_names(ArmInline) == ["parse_h", "parse_h__a", "parse_h__v7"]
    st = state_by_name(ArmInline, "parse_h__a")
    assert st.assigns[0].metadata == "kind"
    assert st.transition.direct.HasField("accept")
    # The parent's first arm targets the hoisted state.
    parent = state_by_name(ArmInline, "parse_h")
    assert parent.transition.select.arms[0].next.state == "parse_h__a"


def test_direct_then_inline() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            return extract(H).then(assign(M.kind, Kind.A).accept())

    assert state_names(P) == ["parse_h", "parse_h__then"]


def test_default_inline_and_nested() -> None:
    class P(Parser):
        max_depth = 4
        metadata = M

        def parse_h(self) -> State:
            return extract(H).select(
                H.tag,
                {Kind.A: "parse_h"},
                default=assign(M.kind, Kind.B).then(
                    assign(M.kind, Kind.A).accept()
                ),
            )

    assert state_names(P) == [
        "parse_h",
        "parse_h__default",
        "parse_h__default__then",
    ]


def test_named_override_and_doc() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            return extract(H).then(
                assign(M.kind, Kind.A).doc("classify-only tail").named("mark").accept()
            )

    assert state_names(P) == ["parse_h", "mark"]
    assert state_by_name(P, "mark").annotations["doc"] == "classify-only tail"


def test_method_docstring_wins_over_chain_doc() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            """From the docstring."""
            return extract(H).doc("from the chain").accept()

    assert state_by_name(P, "parse_h").annotations["doc"] == "From the docstring."


def test_oneof_expansion_shares_one_hoisted_state() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            return extract(H).select(
                H.tag,
                {oneof(3, 4): assign(M.kind, Kind.A).accept()},
                default=reject("unknown tag"),
            )

    # Both expanded arms reach the same object: hoisted once, named
    # from the first-encountered arm.
    assert state_names(P) == ["parse_h", "parse_h__v3"]
    sel = state_by_name(P, "parse_h").transition.select
    assert [a.next.state for a in sel.arms] == ["parse_h__v3", "parse_h__v3"]


def test_variable_reuse_shares_one_hoisted_state() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            mark = assign(M.kind, Kind.A).accept()
            return extract(H).select(
                H.tag,
                {Kind.A: mark, Kind.B: mark},
                default=reject("unknown tag"),
            )

    assert state_names(P) == ["parse_h", "parse_h__a"]


def test_collision_with_existing_state_raises() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            return extract(H).then(assign(M.kind, Kind.A).named("parse_h").accept())

    with pytest.raises(ValueError, match="collides"):
        P.check()


def test_inline_without_transition_raises() -> None:
    class P(Parser):
        max_depth = 3
        metadata = M

        def parse_h(self) -> State:
            return extract(H).then(assign(M.kind, Kind.A))

    with pytest.raises(ValueError, match="parse_h__then.*no transition"):
        P.check()

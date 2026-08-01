"""Assembly-time errors carry the authoring site of the offending
state (`defined at file:line`); builder-time errors already do via the
normal traceback. The location never reaches the IR."""

import re

import pytest

from pakeles import Header, Parser, State, bits, extract, goto


class H(Header):
    tag = bits(8)


def test_unknown_state_reference_names_the_def_site() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).then("nope")

    with pytest.raises(
        ValueError,
        match=r"unknown state 'nope'.*defined at .*test_source_locations\.py:\d+",
    ):
        P.check()


def test_missing_transition_names_the_def_site() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H)

    with pytest.raises(
        ValueError, match=r"no transition.*test_source_locations\.py:\d+"
    ):
        P.check()


def test_inline_collision_names_the_def_site() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).then(goto("parse_h").named("parse_h"))

    with pytest.raises(ValueError, match=r"collides.*test_source_locations\.py:\d+"):
        P.check()


def test_src_points_at_the_chain_start_line() -> None:
    st = extract(H)  # this exact line
    assert st.src is not None
    file, line = st.src
    assert file.endswith("test_source_locations.py")
    with open(__file__, encoding="utf-8") as f:
        assert "this exact line" in f.readlines()[line - 1]


def test_src_never_reaches_the_ir() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).accept()

    assert not re.search(r"\bsrc\b", P.to_json())

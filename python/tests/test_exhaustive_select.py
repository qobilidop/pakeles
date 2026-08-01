"""Exhaustiveness-aware select defaults: omission licensed by proof,
coverage gaps named, conservative refusals for masked/multi-key."""

import pytest

from pakeles import (
    Header,
    LabeledEnum,
    Parser,
    State,
    bits,
    extract,
    masked,
    oneof,
    reject,
)


class Two(LabeledEnum):
    A = 0, "Alpha"
    B = 1
    C = 2
    D = 3


class H(Header):
    ty = bits(2, labels=Two)
    big = bits(16)
    pair = bits(2)


def test_exhaustive_omits_default_and_synthesizes_unreachable() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).select(
                H.ty,
                {
                    Two.A: "parse_h",
                    Two.B: "parse_h",
                    Two.C: "parse_h",
                    Two.D: "parse_h",
                },
            )

    sel = P.to_pb().parser.states[0].transition.select
    assert sel.default_target.reject.reason == "unreachable"


def test_oneof_and_range_count_toward_coverage() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).select(
                H.big,
                {oneof(0, 1): "parse_h", range(2, 1 << 16): "parse_h"},
            )

    sel = P.to_pb().parser.states[0].transition.select
    assert sel.default_target.reject.reason == "unreachable"


def test_gap_is_an_error_naming_missing_values_with_labels() -> None:
    with pytest.raises(ValueError, match=r"missing 0 \(Alpha\), 3 \(D\)"):
        extract(H).select(H.ty, {Two.B: "x", Two.C: "x"})


def test_big_gap_reports_count_and_first_values() -> None:
    with pytest.raises(ValueError, match=r"cover 2 of 65536 values, missing 1, 3, "):
        extract(H).select(H.big, {0: "x", 2: "x"})


def test_masked_arms_require_explicit_default() -> None:
    with pytest.raises(ValueError, match="masked arms"):
        extract(H).select(H.ty, {masked(0, 0b10): "x", masked(2, 0b10): "x"})


def test_multi_key_requires_explicit_default() -> None:
    with pytest.raises(ValueError, match="single key"):
        extract(H).select((H.ty, H.pair), {(0, 0): "x"})


def test_explicit_default_still_respected() -> None:
    class P(Parser):
        max_depth = 2

        def parse_h(self) -> State:
            return extract(H).select(
                H.ty,
                {Two.A: "parse_h"},
                default=reject("not A", info=True),
            )

    sel = P.to_pb().parser.states[0].transition.select
    assert sel.default_target.reject.reason == "not A"


def test_out_of_range_arm_values_do_not_fake_coverage() -> None:
    # 4 distinct values, but one exceeds the 2-bit width: not exhaustive.
    with pytest.raises(ValueError, match="not\nexhaustive|not exhaustive"):
        extract(H).select(H.ty, {0: "x", 1: "x", 2: "x", 4: "x"})

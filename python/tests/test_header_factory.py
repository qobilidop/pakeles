"""`header()`: manufactured Header types are class-statement
equivalent — same IR, same validation, family-loop friendly."""

import pytest

from pakeles import FieldSpec, Header, Parser, State, bits, extract, header, var_bytes


class Lead(Header):
    hi = bits(6)


def test_equivalent_to_class_statement() -> None:
    t = bits(8, "Tail")
    made = header("Tok1", t=t, body=var_bytes((Lead.hi << 8) | t))

    class Tok1(Header, name="tok1"):
        t = bits(8, "Tail")
        body = var_bytes((Lead.hi << 8) | t)

    assert made.to_pb() == Tok1.to_pb()


def test_snake_naming_and_field_order() -> None:
    made = header("OptMss", kind=bits(8), length=bits(8))
    ht = made.to_pb()
    assert ht.name == "opt_mss"
    assert [f.name for f in ht.fields] == ["kind", "length"]


def test_no_fields_raises() -> None:
    with pytest.raises(ValueError, match="declares no fields"):
        header("Empty")


def test_family_loop_in_a_parser() -> None:
    tiers: dict[int, tuple[type[Header], FieldSpec]] = {}
    for i, tail in [(0, 8), (1, 16)]:
        t = bits(tail, "Tail")
        tiers[i] = (header(f"Tier{i}", t=t), t)

    class P(Parser):
        max_depth = 2

        def parse_lead(self) -> State:
            return extract(Lead).select(
                Lead.hi,
                {
                    i: extract(hdr).named(f"tier_{i}").accept()
                    for i, (hdr, _t) in tiers.items()
                },
                default="parse_lead",
            )

    names = [s.name for s in P.to_pb().parser.states]
    assert names == ["parse_lead", "tier_0", "tier_1"]
    types = [h.name for h in P.to_pb().parser.header_types]
    assert types == ["lead", "tier0", "tier1"]

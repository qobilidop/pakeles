"""`lookahead()` serializes as an Extract with the peek flag."""

import json

from pakeles import Header, Parser, State, bits, extract, lookahead


class Nibble(Header):
    v = bits(4)


class Full(Header):
    v = bits(4)
    rest = bits(4)


class Peeker(Parser):
    name = "peeker"
    max_depth = 2

    def s0(self) -> State:
        return lookahead(Nibble).select(Nibble.v, {4: self.s1}, default="s1")

    def s1(self) -> State:
        return extract(Full).accept()


def test_lookahead_serializes_flag() -> None:
    states = {s["name"]: s for s in json.loads(Peeker.to_json())["parser"]["states"]}
    ex = states["s0"]["extracts"][0]
    assert ex["headerType"] == "nibble"
    assert ex["lookahead"] is True
    # A consuming extract carries no flag (proto default omitted).
    assert "lookahead" not in states["s1"]["extracts"][0]


def test_extract_then_lookahead_chain() -> None:
    chain = extract(Full).lookahead(Nibble)
    kinds = [(h.ir_name(), peek) for h, _, peek in chain.extracts]
    assert kinds == [("full", False), ("nibble", True)]

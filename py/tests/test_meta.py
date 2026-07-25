from google.protobuf import json_format

from pakeles import Header, Meta, assign, bits, extract, meta_bits, parser
from pakeles._pb import ir_pb2


class H(Header):
    n = bits(8)


class M(Meta):
    flag = meta_bits(1)
    acc = meta_bits(8, init=5)


def build():
    return parser(
        "t",
        max_depth=4,
        metadata=M,
        start="s0",
        states={
            "s0": extract(H)
            .assign(M.acc, H.n)
            .assign(M.flag, 1)
            .select(M.acc, {0: "done"}, default="s0"),
            "done": assign(M.flag, M.flag + 1).accept(),
        },
    )


def test_metadata_declarations_serialize():
    ir = json_format.Parse(build().to_json(), ir_pb2.Ir())
    md = ir.parser.metadata
    assert [(m.name, m.bits, m.init) for m in md] == [("flag", 1, 0), ("acc", 8, 5)]


def test_assigns_serialize_in_order():
    ir = json_format.Parse(build().to_json(), ir_pb2.Ir())
    s0 = next(s for s in ir.parser.states if s.name == "s0")
    assert [a.metadata for a in s0.assigns] == ["acc", "flag"]
    assert s0.assigns[0].value.field.header == "h"
    done = next(s for s in ir.parser.states if s.name == "done")
    assert done.assigns[0].value.bin.lhs.metadata.name == "flag"
    assert not done.extracts  # pass-through state


def test_select_on_metadata_key():
    ir = json_format.Parse(build().to_json(), ir_pb2.Ir())
    s0 = next(s for s in ir.parser.states if s.name == "s0")
    assert s0.transition.select.keys[0].metadata.name == "acc"


def test_meta_validation_errors():
    import pytest

    with pytest.raises(ValueError):
        meta_bits(0)
    with pytest.raises(ValueError):
        meta_bits(65)
    with pytest.raises(ValueError):
        meta_bits(4, init=16)

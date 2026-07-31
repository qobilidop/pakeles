import pytest
from google.protobuf import json_format

from pakeles import (
    Header,
    Meta,
    ParserDef,
    StateChain,
    assign,
    bits,
    extract,
    meta_bits,
)
from pakeles._pb import ir_pb2


class H(Header):
    n = bits(8)


class M(Meta):
    flag = meta_bits(1)
    acc = meta_bits(8, init=5)


class TMeta(ParserDef):
    name = "t"
    max_depth = 4
    metadata = M

    def s0(self) -> StateChain:
        return (
            extract(H)
            .assign(M.acc, H.n)
            .assign(M.flag, 1)
            .select(M.acc, {0: self.done}, default=self.s0)
        )

    def done(self) -> StateChain:
        return assign(M.flag, M.flag + 1).accept()


def test_metadata_declarations_serialize():
    ir = json_format.Parse(TMeta.build().to_json(), ir_pb2.Ir())
    md = ir.parser.metadata
    assert [(m.name, m.bits, m.init) for m in md] == [("flag", 1, 0), ("acc", 8, 5)]


def test_assigns_serialize_in_order():
    ir = json_format.Parse(TMeta.build().to_json(), ir_pb2.Ir())
    s0 = next(s for s in ir.parser.states if s.name == "s0")
    assert [a.metadata for a in s0.assigns] == ["acc", "flag"]
    assert s0.assigns[0].value.field.header == "h"
    done = next(s for s in ir.parser.states if s.name == "done")
    assert done.assigns[0].value.bin.lhs.metadata.name == "flag"
    assert not done.extracts  # pass-through state


def test_select_on_metadata_key():
    ir = json_format.Parse(TMeta.build().to_json(), ir_pb2.Ir())
    s0 = next(s for s in ir.parser.states if s.name == "s0")
    assert s0.transition.select.keys[0].metadata.name == "acc"


def test_meta_validation_errors():
    with pytest.raises(ValueError):
        meta_bits(0)
    with pytest.raises(ValueError):
        meta_bits(65)
    with pytest.raises(ValueError):
        meta_bits(4, init=16)


def test_meta_validation_error_width_64_init_overflow():
    # width == 64 is the boundary where a naive `width < 64` guard would
    # skip the upper-bound check entirely (Python ints are unbounded, so
    # 2**64 doesn't wrap or raise on its own — the check must be explicit).
    with pytest.raises(ValueError):
        meta_bits(64, init=2**64 + 5)


def test_assign_rejects_field_from_a_different_metadata_class():
    # Two Meta classes with structurally identical fields (same name,
    # width, init) must still be distinguished by identity, not value
    # equality — a dataclass `==` would incorrectly consider them
    # interchangeable.
    class OtherM(Meta):
        flag = meta_bits(1)
        acc = meta_bits(8, init=5)

    class T2(ParserDef):
        name = "t2"
        max_depth = 4
        metadata = M

        def s0(self) -> StateChain:
            return assign(OtherM.flag, 1).accept()

    with pytest.raises(ValueError):
        T2.build()

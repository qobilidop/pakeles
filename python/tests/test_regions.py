"""Sized regions + remaining() serialize to the IR schema."""

import json

from pakeles import (
    Header,
    Parser,
    State,
    bits,
    extract,
    pop_region,
    remaining,
    select,
    var_bytes,
)


class TotalHdr(Header):
    total = bits(8)


class Item(Header):
    t = bits(8)
    ln = bits(8)
    val = var_bytes(ln)


class TlvMini(Parser):
    name = "tlv_mini_py"
    max_depth = 8

    def s0(self) -> State:
        return extract(TotalHdr).push_region(TotalHdr.total).then(self.tlv)

    def tlv(self) -> State:
        return select(remaining(), {0: self.done}, default=self.item_s)

    def item_s(self) -> State:
        return extract(Item).then(self.tlv)

    def done(self) -> State:
        return pop_region().accept()


def _tlv() -> str:
    return TlvMini.to_json()


def test_region_ops_serialize() -> None:
    states = {s["name"]: s for s in json.loads(_tlv())["parser"]["states"]}
    push_ops = states["s0"]["regionOps"]
    assert len(push_ops) == 1
    # push_region(bytes) is ×8 sugar over the bit-denominated IR.
    push = push_ops[0]["push"]
    assert push["bin"]["op"] == "BIN_OP_KIND_MUL"
    assert push["bin"]["lhs"]["field"] == {"header": "total_hdr", "field": "total"}
    assert push["bin"]["rhs"]["constant"] == "8"
    assert states["done"]["regionOps"] == [{"pop": {}}]


def test_remaining_select_key_serializes() -> None:
    by_name = {s["name"]: s for s in json.loads(_tlv())["parser"]["states"]}
    tlv = by_name["tlv"]
    # remaining() (bytes view) serializes as the raw bit quantity >> 3.
    assert tlv["transition"]["select"]["keys"] == [
        {
            "bin": {
                "op": "BIN_OP_KIND_SHR",
                "lhs": {"remaining": {}},
                "rhs": {"constant": "3"},
            }
        }
    ]


def test_push_region_after_transition_rejected() -> None:
    chain = extract(TotalHdr).accept()
    try:
        chain.push_region(TotalHdr.total)
    except ValueError as e:
        assert "transition" in str(e)
    else:
        raise AssertionError("push_region after transition should fail")

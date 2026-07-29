"""Sized regions + remaining() serialize to the IR schema."""

import json

from pakeles import Header, StateChain, bits, extract, parser, remaining, var_bytes


class TotalHdr(Header):
    total = bits(8)


class Item(Header):
    t = bits(8)
    ln = bits(8)
    val = var_bytes(ln)


def _tlv() -> str:
    return parser(
        "tlv_mini_py",
        max_depth=8,
        start="s0",
        states={
            "s0": extract(TotalHdr).push_region(TotalHdr.total).then("tlv"),
            "tlv": StateChain().select(remaining(), {0: "done"}, default="item_s"),
            "item_s": extract(Item).then("tlv"),
            "done": StateChain().pop_region().accept(),
        },
    ).to_json()


def test_region_ops_serialize() -> None:
    states = {s["name"]: s for s in json.loads(_tlv())["parser"]["states"]}
    push_ops = states["s0"]["regionOps"]
    assert len(push_ops) == 1
    assert push_ops[0]["push"]["field"] == {"header": "total_hdr", "field": "total"}
    assert states["done"]["regionOps"] == [{"pop": {}}]


def test_remaining_select_key_serializes() -> None:
    by_name = {s["name"]: s for s in json.loads(_tlv())["parser"]["states"]}
    tlv = by_name["tlv"]
    assert tlv["transition"]["select"]["keys"] == [{"remaining": {}}]


def test_push_region_after_transition_rejected() -> None:
    chain = extract(TotalHdr).accept()
    try:
        chain.push_region(TotalHdr.total)
    except ValueError as e:
        assert "transition" in str(e)
    else:
        raise AssertionError("push_region after transition should fail")

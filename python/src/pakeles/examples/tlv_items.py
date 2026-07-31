"""Length-bounded TLV items: the sized-region toy example.

A one-byte total length opens a sized region; inside it, TLV items
(kind, len, value[len]) repeat until `remaining() == 0`, then the
region is popped exact-fill and the parse accepts. This is the
regression anchor for the sized-region IR slice (see
docs/superpowers/specs/2026-07-29-sized-region-tlv-ir-design.md):
push/pop, the remaining() select key, region-bounded reads (an item
crossing the region end is "out of region bounds", not a truncation),
and the exact-mode pop.

It is also the smallest witness of the parity-plus boundary: `gen p4`
refuses this parser — a P4-16 parser cannot parse INSIDE a
length-bounded window — while the C, eBPF, and Lua backends lower it.

max_depth remains the sole termination authority: the TLV loop is a
plain cyclic state bounded by the global depth budget.
"""

from pakeles import (
    Header,
    Parser,
    StateChain,
    bits,
    extract,
    parser,
    remaining,
    var_bytes,
)
from pakeles.fmt import DEC, HEX


class TotalLen(Header):
    total = bits(8, "Total Length", DEC, doc="bytes of TLV items that follow")


class Item(Header):
    kind = bits(8, "Kind", HEX)
    ln = bits(8, "Length", DEC)
    val = var_bytes(ln)


def tlv_items() -> Parser:
    return parser(
        "tlv_items",
        max_depth=8,
        start="parse_total",
        states={
            "parse_total": extract(TotalLen)
            .push_region(TotalLen.total)
            .then("tlv_loop"),
            # Loop head: region exhausted -> close; else another item.
            "tlv_loop": StateChain().select(
                remaining(), {0: "close"}, default="parse_item"
            ),
            "parse_item": extract(Item).then("tlv_loop"),
            # Exact-mode pop: trailing bytes inside the region reject.
            "close": StateChain().pop_region().accept(),
        },
    )


if __name__ == "__main__":
    print(tlv_items().to_json())

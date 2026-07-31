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
    ParserDef,
    StateChain,
    bits,
    extract,
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


class TlvItems(ParserDef):
    max_depth = 8

    def parse_total(self) -> StateChain:
        return extract(TotalLen).push_region(TotalLen.total).then(self.tlv_loop)

    def tlv_loop(self) -> StateChain:
        """Loop head: region exhausted -> close; else another item."""
        return StateChain().select(remaining(), {0: self.close}, default=self.parse_item)

    def parse_item(self) -> StateChain:
        return extract(Item).then(self.tlv_loop)

    def close(self) -> StateChain:
        """Exact-mode pop: trailing bytes inside the region reject."""
        return StateChain().pop_region().accept()


if __name__ == "__main__":
    print(TlvItems.build().to_json())

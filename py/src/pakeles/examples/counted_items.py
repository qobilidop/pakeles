"""Count-prefixed items: the metadata-v1 toy example.

A one-byte count, then exactly `count` one-byte items. Exercises BOTH
metadata paths before any kernel-facing example depends on them:
- constant write on a no-extract pass-through state (`mark_done` — the
  rung-4a `is_encap` shape);
- read-write accumulator loop with a select-on-metadata exit
  (`parse_item` — the TLV shape the P4-parity ambition targets).

max_depth (not the count field) bounds the parse: count > 5 rejects with
"max depth exceeded" — metadata never extends the budget.
"""

from pakeles import Header, Meta, Parser, assign, bits, extract, meta_bits, parser
from pakeles.fmt import DEC, HEX


class Count(Header):
    n = bits(8, "Item Count", DEC)


class Item(Header):
    v = bits(8, "Value", HEX)


class CountMeta(Meta):
    done = meta_bits(1, "Done", DEC, doc="set on the pass-through completion state")
    remaining = meta_bits(8, "Remaining", DEC, doc="items left to read")


def counted_items() -> Parser:
    return parser(
        "counted_items",
        max_depth=8,
        metadata=CountMeta,
        start="parse_count",
        states={
            "parse_count": extract(Count)
            .assign(CountMeta.remaining, Count.n)
            .select(CountMeta.remaining, {0: "mark_done"}, default="parse_item"),
            # Accumulator loop: read one item, count down, exit at zero.
            "parse_item": extract(Item)
            .assign(CountMeta.remaining, CountMeta.remaining - 1)
            .select(CountMeta.remaining, {0: "mark_done"}, default="parse_item"),
            # No-extract pass-through state: constant metadata write, then stop.
            "mark_done": assign(CountMeta.done, 1).accept(),
        },
    )


if __name__ == "__main__":
    print(counted_items().to_json())

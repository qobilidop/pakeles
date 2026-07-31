"""Count-prefixed items: the metadata-v1 toy example.

A one-byte count, then exactly `count` one-byte items. Exercises BOTH
metadata paths before any kernel-facing example depends on them:
- constant write on a no-extract pass-through state (`mark_done` — the
  rung-4a `is_encap` shape);
- read-write accumulator loop with a select-on-metadata exit
  (`parse_item` — the TLV shape the P4-parity ambition targets).

max_depth (not the count field) bounds the parse: count > 6 rejects with
"max depth exceeded" — metadata never extends the budget.
"""

from pakeles import (
    Header,
    Metadata,
    Parser,
    State,
    assign,
    bits,
    extract,
    metadata_bits,
)
from pakeles.fmt import DEC, HEX


class Count(Header):
    n = bits(8, "Item Count", DEC)


class Item(Header):
    v = bits(8, "Value", HEX)


class CountMeta(Metadata):
    done = metadata_bits(1, "Done", DEC, doc="set on the pass-through completion state")
    remaining = metadata_bits(8, "Remaining", DEC, doc="items left to read")


class CountedItems(Parser):
    max_depth = 8
    metadata = CountMeta

    def parse_count(self) -> State:
        return (
            extract(Count)
            .assign(CountMeta.remaining, Count.n)
            .select(CountMeta.remaining, {0: self.mark_done}, default=self.parse_item)
        )

    def parse_item(self) -> State:
        """Accumulator loop: read one item, count down, exit at zero."""
        return (
            extract(Item)
            .assign(CountMeta.remaining, CountMeta.remaining - 1)
            .select(CountMeta.remaining, {0: self.mark_done}, default=self.parse_item)
        )

    def mark_done(self) -> State:
        """No-extract pass-through state: constant metadata write, then stop."""
        return assign(CountMeta.done, 1).accept()


if __name__ == "__main__":
    print(CountedItems.to_json())

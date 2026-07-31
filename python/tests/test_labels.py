# Tests intentionally reach into Header internals (_fields).
# pyright: reportPrivateUsage=false
from enum import IntEnum

from pakeles import Header, LabeledEnum, Parser, State, bits, extract, oneof, reject
from pakeles.fmt import HEX


class EtherType(LabeledEnum):
    IPV4 = 0x0800, "IPv4"
    ARP = 0x0806
    MPLS_UC = 0x8847, "MPLS unicast"
    MPLS_MC = 0x8848, "MPLS multicast"


def test_label_defaults_to_member_name() -> None:
    assert EtherType.ARP.label == "ARP"
    assert EtherType.IPV4.label == "IPv4"


def test_members_are_plain_ints() -> None:
    assert EtherType.IPV4 == 0x0800
    assert int(EtherType.MPLS_MC) == 0x8848


def test_labels_accepts_enum_class() -> None:
    class Eth(Header):
        ethertype = bits(16, "Type", HEX, labels=EtherType)

    assert Eth._fields[0].labels == {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
    }


def test_labels_accepts_curated_member_list() -> None:
    class Eth(Header):
        ethertype = bits(16, labels=[EtherType.MPLS_MC, EtherType.IPV4])

    assert Eth._fields[0].labels == {0x8848: "MPLS multicast", 0x0800: "IPv4"}


def test_value_labels_emit_in_canonical_value_order() -> None:
    class Eth(Header):
        ethertype = bits(16, labels={0x86DD: "IPv6", 0x0800: "IPv4"})

    # Authored order carries no meaning: emission sorts by value, the
    # same canonical order `pakeles fmt-ir` produces.
    labels = Eth.to_pb().fields[0].display.value_labels
    assert [(vl.value, vl.label) for vl in labels] == [
        (0x0800, "IPv4"),
        (0x86DD, "IPv6"),
    ]


def test_labels_accepts_plain_intenum_and_dict_with_member_keys() -> None:
    class Proto(IntEnum):
        TCP = 6
        UDP = 17

    class H(Header):
        a = bits(8, labels=Proto)
        b = bits(8, labels={Proto.TCP: "tcp!"})

    assert H._fields[0].labels == {6: "TCP", 17: "UDP"}
    assert H._fields[1].labels == {6: "tcp!"}
    assert all(type(k) is int for k in H._fields[1].labels)


def test_members_serialize_as_ints_in_arms_and_value_labels() -> None:
    class Eth(Header):
        ethertype = bits(16, "Type", HEX, labels=[EtherType.IPV4])

    class P(Parser):
        max_depth = 2

        def parse_ethernet(self) -> State:
            return extract(Eth).select(
                Eth.ethertype,
                {
                    EtherType.IPV4: self.parse_done,
                    oneof(EtherType.MPLS_UC, EtherType.MPLS_MC): self.parse_done,
                },
                default=reject("no"),
            )

        def parse_done(self) -> State:
            return extract(Eth).accept()

    ir = P.to_pb()
    labels = ir.parser.header_types[0].fields[0].display.value_labels
    assert [(vl.value, vl.label) for vl in labels] == [(0x0800, "IPv4")]
    sel = ir.parser.states[0].transition.select
    arm_values = [e.value for arm in sel.arms for e in arm.entries]
    assert arm_values == [0x0800, 0x8847, 0x8848]

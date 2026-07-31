# Tests intentionally reach into internals in places.
# pyright: reportPrivateUsage=false
import pytest

from pakeles import Header, Parser, State, bits, extract, reject
from pakeles._build import Assembly
from pakeles.fmt import DEC, HEX


class Ethernet(Header):
    dst = bits(48, "Destination")
    ethertype = bits(16, "Type", HEX)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    protocol = bits(8, "Protocol", DEC)


class TParser(Parser):
    name = "t"
    max_depth = 2

    def ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {0x0800: self.ipv4},
            default=reject("unsupported ethertype", info=True),
        )

    def ipv4(self) -> State:
        return extract(IPv4).accept()


def test_builds_expected_ir_shape() -> None:
    ir = TParser.to_pb()
    p = ir.parser
    assert p.start_state == "ethernet"
    assert [h.name for h in p.header_types] == ["ethernet", "ipv4"]
    st = p.states[0]
    assert st.extracts[0].header_type == "ethernet"
    sel = st.transition.select
    assert sel.keys[0].field.field == "ethertype"
    assert sel.arms[0].entries[0].value == 0x0800
    assert sel.arms[0].next.state == "ipv4"
    assert sel.default_target.reject.reason == "unsupported ethertype"
    assert sel.default_target.reject.annotations["severity"] == "info"
    assert ir.parser.states[1].transition.direct.accept is not None


def test_unknown_state_rejected() -> None:
    # String targets remain valid Parser targets — and stay checked.
    class Bad(TParser):
        def ethernet(self) -> State:
            return extract(Ethernet).select(
                Ethernet.ethertype, {0x0800: "nope"}, default=reject("x")
            )

    with pytest.raises(ValueError, match="nope"):
        Bad.check()


def test_oversized_arm_value_rejected() -> None:
    class Bad(TParser):
        def ipv4(self) -> State:
            return extract(IPv4).select(
                IPv4.protocol, {0x1FF: self.ethernet}, default=reject("x")
            )

    with pytest.raises(ValueError, match="does not fit"):
        Bad.check()


def test_unknown_start_rejected() -> None:
    # White-box: the assembly layer still guards a start/states mismatch.
    with pytest.raises(ValueError, match="start state"):
        Assembly(
            "t",
            max_depth=2,
            start="missing",
            states={"only": extract(Ethernet).accept()},
        )


def test_double_transition_rejected() -> None:
    with pytest.raises(ValueError, match="already has a transition"):
        extract(Ethernet).accept().then("x")


def test_json_roundtrip() -> None:
    from google.protobuf import json_format

    from pakeles._pb import ir_pb2

    parsed = json_format.Parse(TParser.to_json(), ir_pb2.Ir())
    assert parsed == TParser.to_pb()

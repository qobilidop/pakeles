# Tests intentionally reach into internals in places.
# pyright: reportPrivateUsage=false
import pytest

from pakeles import Header, bits, extract, parser, reject
from pakeles.fmt import DEC, HEX


class Ethernet(Header):
    dst = bits(48, "Destination")
    ethertype = bits(16, "Type", HEX)


class IPv4(Header):
    version = bits(4, "Version", DEC)
    protocol = bits(8, "Protocol", DEC)


def _states():
    return {
        "ethernet": extract(Ethernet).select(
            Ethernet.ethertype,
            {0x0800: "ipv4"},
            default=reject("unsupported ethertype", info=True),
        ),
        "ipv4": extract(IPv4).accept(),
    }


def test_builds_expected_ir_shape() -> None:
    ir = parser("t", max_depth=2, start="ethernet", states=_states()).to_pb()
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
    states = _states()
    states["ethernet"] = extract(Ethernet).select(
        Ethernet.ethertype, {0x0800: "nope"}, default=reject("x")
    )
    with pytest.raises(ValueError, match="nope"):
        parser("t", max_depth=2, start="ethernet", states=states)


def test_oversized_arm_value_rejected() -> None:
    states = _states()
    states["ipv4"] = extract(IPv4).select(
        IPv4.protocol, {0x1FF: "ethernet"}, default=reject("x")
    )
    with pytest.raises(ValueError, match="does not fit"):
        parser("t", max_depth=2, start="ethernet", states=states)


def test_unknown_start_rejected() -> None:
    with pytest.raises(ValueError, match="start state"):
        parser("t", max_depth=2, start="missing", states=_states())


def test_double_transition_rejected() -> None:
    with pytest.raises(ValueError, match="already has a transition"):
        extract(Ethernet).accept().then("x")


def test_json_roundtrip() -> None:
    from google.protobuf import json_format

    from pakeles._pb import ir_pb2

    p = parser("t", max_depth=2, start="ethernet", states=_states())
    parsed = json_format.Parse(p.to_json(), ir_pb2.Ir())
    assert parsed == p.to_pb()

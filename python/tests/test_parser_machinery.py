"""Parser machinery: the class-ness must pay rent.

IR fidelity of the gallery classes is covered by test_conformance;
here: mixins, ladder-style inheritance rungs, one-state variant
overrides of a real gallery parser, and the build-time guardrails.
"""

import json

import pytest

from conftest import example_parser, load_example
from pakeles import Parser, State, extract, goto, reject

_lfd = load_example("linux_flow_dissector")
TCP = _lfd.TCP
UDP = _lfd.UDP
VLAN = _lfd.VLAN
Ethernet = _lfd.Ethernet
IPv4 = _lfd.IPv4
LinuxFlowDissector = example_parser("linux_flow_dissector")

# --- inheritance: ladder rungs on a shared mixin ----------------------


class L4Tail:
    """State mixin: the terminal TCP/UDP tail shared across rungs."""

    def parse_tcp(self) -> State:
        return extract(TCP).accept()

    def parse_udp(self) -> State:
        return extract(UDP).accept()


class Rung0(L4Tail, Parser):
    """Eth -> IPv4 -> {TCP, UDP}: a ladder's first rung."""

    max_depth = 4

    def parse_ethernet(self) -> State:
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {0x0800: self.parse_ipv4},
            default=reject("unsupported ethertype", info=True),
        )

    start = parse_ethernet  # mixin states come first; name the start

    def parse_ipv4(self) -> State:
        return extract(IPv4).select(
            IPv4.protocol,
            {6: self.parse_tcp, 17: self.parse_udp},
            default=reject("unsupported ip protocol", info=True),
        )


class Rung1(Rung0):
    """Rung0 + a single 802.1Q tag: one new state, one override."""

    max_depth = 5

    def parse_ethernet(self) -> State:  # override: add the VLAN arm
        return extract(Ethernet).select(
            Ethernet.ethertype,
            {0x0800: self.parse_ipv4, 0x8100: self.parse_vlan_q},
            default=reject("unsupported ethertype", info=True),
        )

    def parse_vlan_q(self) -> State:
        return extract(VLAN["vlan_q"]).select(
            VLAN["vlan_q"].encapsulated_proto,
            {0x0800: self.parse_ipv4},
            default=reject("unsupported ethertype", info=True),
        )


def test_rung_inheritance() -> None:
    r0 = json.loads(Rung0.to_json())["parser"]
    assert r0["startState"] == "parse_ethernet"
    assert [s["name"] for s in r0["states"]] == [
        "parse_tcp",
        "parse_udp",
        "parse_ethernet",
        "parse_ipv4",
    ]

    r1 = json.loads(Rung1.to_json())["parser"]
    # the inherited `start` resolves by name, so it picks up the override
    assert r1["startState"] == "parse_ethernet"
    # override keeps the base position; the new state appends
    assert [s["name"] for s in r1["states"]] == [
        "parse_tcp",
        "parse_udp",
        "parse_ethernet",
        "parse_ipv4",
        "parse_vlan_q",
    ]
    eth = next(s for s in r1["states"] if s["name"] == "parse_ethernet")
    arms = eth["transition"]["select"]["arms"]
    assert any(a["next"].get("state") == "parse_vlan_q" for a in arms)


# --- variant: override two states of a gallery parser -----------------


class NoEncap(LinuxFlowDissector):
    """Variant experiment: tunnels reject instead of re-entering."""

    name = "linux_flow_dissector_no_encap"

    def parse_ipip(self) -> State:
        return goto(reject("encap disabled"))

    def parse_ip6ip(self) -> State:
        return goto(reject("encap disabled"))


def test_variant_override() -> None:
    base = json.loads(LinuxFlowDissector.to_json())["parser"]
    var = json.loads(NoEncap.to_json())["parser"]
    assert var["name"] == "linux_flow_dissector_no_encap"
    assert [s["name"] for s in var["states"]] == [s["name"] for s in base["states"]]
    by_name = {s["name"]: s for s in var["states"]}
    assert (
        by_name["parse_ipip"]["transition"]["direct"]["reject"]["reason"]
        == "encap disabled"
    )

    # every non-overridden state is untouched
    def keep(states: list[dict[str, object]]) -> list[dict[str, object]]:
        return [s for s in states if s["name"] not in ("parse_ipip", "parse_ip6ip")]

    assert keep(var["states"]) == keep(base["states"])


# --- machinery guardrails ---------------------------------------------


def test_helper_without_underscore_is_an_error() -> None:
    class Bad(Parser):
        max_depth = 1

        def parse_a(self) -> State:
            return extract(TCP).accept()

        def arms(self) -> int:  # forgot the underscore prefix
            return 3

    with pytest.raises(TypeError, match="State"):
        Bad.check()


def test_reference_typo_is_an_attribute_error() -> None:
    class Typo(Parser):
        max_depth = 1

        def parse_a(self) -> State:
            # pyright flags this at edit time; the runtime error under test
            return extract(TCP).then(self.parse_b)  # type: ignore[attr-defined]

    with pytest.raises(AttributeError, match="parse_b"):
        Typo.check()


# --- docstring lifting ------------------------------------------------


def test_docstrings_lift_into_doc_annotations() -> None:
    class Documented(Parser):
        """The parser-level doc."""

        max_depth = 1

        def parse_a(self) -> State:
            """First line.

            Second line."""
            return extract(TCP).accept()

        def parse_b(self) -> State:
            return extract(UDP).accept()

    ir = json.loads(Documented.to_json())["parser"]
    assert ir["annotations"]["doc"] == "The parser-level doc."
    by_name = {s["name"]: s for s in ir["states"]}
    assert by_name["parse_a"]["annotations"]["doc"] == "First line.\n\nSecond line."
    # No docstring -> no key.
    assert "annotations" not in by_name["parse_b"]

    class Undocumented(Documented):
        max_depth = 1

    # A subclass never inherits the base class's parser-level doc
    # (its own __doc__ is None); the inherited state methods keep
    # their own docstrings.
    sub = json.loads(Undocumented.to_json())["parser"]
    assert "annotations" not in sub
    sub_states = {s["name"]: s for s in sub["states"]}
    assert sub_states["parse_a"]["annotations"]["doc"].startswith("First line.")


def test_masked_arm_emits_ternary_keyset_entry() -> None:
    from pakeles import Header, accept, bits, masked

    class Eth(Header):
        et = bits(16)

    class MaskedArms(Parser):
        max_depth = 2

        def parse(self) -> State:
            return extract(Eth).select(
                Eth.et,
                {masked(0, 0xFE00): "parse", 0x0800: "parse"},
                default=accept(),
            )

    sel = json.loads(MaskedArms.to_json())["parser"]["states"][0]["transition"][
        "select"
    ]
    entries = [arm["entries"][0] for arm in sel["arms"]]
    assert entries[0]["masked"] == {"mask": "65024"}  # value 0 = proto default
    assert entries[1] == {"value": "2048"}
    # A masked value outside its mask is an authoring error.
    with pytest.raises(ValueError, match="outside its mask"):
        masked(0x0100, 0xFE00)
    # The mask must fit the key width like any exact value.
    with pytest.raises(ValueError, match="does not fit"):

        class BadWidth(Parser):
            max_depth = 2

            def parse(self) -> State:
                return extract(Eth).select(
                    Eth.et, {masked(0, 0x1FFFF): "parse"}, default=accept()
                )

        BadWidth.to_pb()

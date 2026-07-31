"""Named header instances: `VLAN["vlan_q"]` extracts a second copy of a
header type and yields instance-bound field references."""

import pytest
from google.protobuf import json_format

from pakeles import Header, Parser, State, bits, extract, reject
from pakeles._pb import ir_pb2


class Tag(Header):
    vid = bits(12)
    pad = bits(4)
    proto = bits(16)


class Eth(Header):
    ethertype = bits(16)


class TwoTags(Parser):
    name = "two_tags"
    max_depth = 3

    def s0(self) -> State:
        return extract(Eth).select(Eth.ethertype, {0x8100: self.s1}, default=reject("no"))

    def s1(self) -> State:
        return extract(Tag["outer"]).select(
            Tag["outer"].proto, {0x8100: self.s2}, default=reject("no")
        )

    def s2(self) -> State:
        return extract(Tag["inner"]).accept()


def test_extract_records_instance_name() -> None:
    ir = TwoTags.to_pb()
    states = {s.name: s for s in ir.parser.states}
    assert states["s1"].extracts[0].header_type == "tag"
    assert states["s1"].extracts[0].instance == "outer"
    assert states["s2"].extracts[0].instance == "inner"
    # Default-instance extraction stays empty (canonical form).
    assert states["s0"].extracts[0].instance == ""


def test_bound_field_ref_serializes_instance_name() -> None:
    ir = TwoTags.to_pb()
    states = {s.name: s for s in ir.parser.states}
    key = states["s1"].transition.select.keys[0]
    assert key.field.header == "outer"
    assert key.field.field == "proto"


def test_header_type_emitted_once_for_two_instances() -> None:
    ir = TwoTags.to_pb()
    assert [h.name for h in ir.parser.header_types].count("tag") == 1


def test_unknown_field_on_instance_raises() -> None:
    with pytest.raises(AttributeError):
        _ = Tag["outer"].nope  # type: ignore[attr-defined]


def test_empty_instance_name_raises() -> None:
    with pytest.raises(TypeError, match="instance name must be a non-empty string"):
        _ = Tag[""]  # type: ignore[index]


def test_non_string_instance_name_raises() -> None:
    with pytest.raises(TypeError, match="instance name must be a non-empty string"):
        _ = Tag[123]  # type: ignore[index]


def test_bound_field_arm_width_check_still_applies() -> None:
    class Bad(Parser):
        name = "bad"
        max_depth = 2

        def s0(self) -> State:
            return extract(Tag["t"]).select(
                Tag["t"].vid, {1 << 12: self.s0}, default=reject("no")
            )

    with pytest.raises(ValueError, match="does not fit"):
        Bad.check()


def test_roundtrips_through_json() -> None:
    assert json_format.Parse(TwoTags.to_json(), ir_pb2.Ir()) == TwoTags.to_pb()

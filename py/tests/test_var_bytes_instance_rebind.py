# Tests intentionally reach into internals in places.
# pyright: reportPrivateUsage=false
import pytest

from pakeles import Header, bits, extract, parser, var_bytes
from pakeles._pb import ir_pb2


class Opt(Header):
    hdr_ext_len = bits(8)
    body = var_bytes((hdr_ext_len + 1) * 8)


def _find_byte_len_field(ht: ir_pb2.HeaderType) -> ir_pb2.Field:
    for f in ht.fields:
        if f.width.WhichOneof("width") == "byte_len":
            return f
    raise AssertionError("no byte_len field found")


def _field_refs(expr: ir_pb2.Expr) -> list[str]:
    """Depth-first collect every `field` leaf's `.header` under `expr`."""
    kind = expr.WhichOneof("kind")
    if kind == "field":
        return [expr.field.header]
    if kind == "bin":
        return _field_refs(expr.bin.lhs) + _field_refs(expr.bin.rhs)
    return []


def test_var_bytes_rebound_to_named_instance():
    # `Opt` is extracted under a custom instance name ("custom_opt") that
    # differs from the header type name ("opt"); the var-length field's
    # length expression references a sibling field of the same header
    # ("hdr_ext_len"), and that reference must follow the header to the
    # instance name, not stay pinned to the type name.
    states = {"opt": extract(Opt["custom_opt"]).accept()}
    ir = parser("t", max_depth=1, start="opt", states=states).to_pb()

    assert [h.name for h in ir.parser.header_types] == ["opt"]
    ht = ir.parser.header_types[0]
    byte_len_field = _find_byte_len_field(ht)
    refs = _field_refs(byte_len_field.width.byte_len)
    assert refs, "expected at least one field ref in the byte_len expression"
    assert refs == ["custom_opt"] * len(refs)

    # Sanity: the extracting state's own extract record still names the
    # header type separately from the instance.
    ex = ir.parser.states[0].extracts[0]
    assert ex.header_type == "opt"
    assert ex.instance == "custom_opt"


def test_var_bytes_default_instance_unchanged():
    # Default case (no custom instance name): the instance equals the
    # type name, so the rebind is a no-op and refs stay on the type name.
    states = {"opt": extract(Opt).accept()}
    ir = parser("t", max_depth=1, start="opt", states=states).to_pb()
    ht = ir.parser.header_types[0]
    byte_len_field = _find_byte_len_field(ht)
    refs = _field_refs(byte_len_field.width.byte_len)
    assert refs == ["opt"] * len(refs)


def test_var_bytes_two_instance_names_rejected():
    # The same var-length header type extracted under two distinct
    # instance names has no single instance to rebind field refs to; the
    # IR does not model per-instance header types, so this must fail
    # fast rather than silently rebind to one of them.
    states = {"opt": extract(Opt["a"]).extract(Opt["b"]).accept()}
    with pytest.raises(ValueError, match="multiple instance names"):
        parser("t", max_depth=1, start="opt", states=states).to_pb()

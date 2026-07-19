# Tests intentionally reach into Header internals (_fields/_name).
# pyright: reportPrivateUsage=false, reportUnusedClass=false
import pytest

from pakeles import Header, bits, var_bytes
from pakeles.fmt import DEC


class IPv4(Header):
    version = bits(4, "Version", DEC)
    ihl = bits(4, "Header Length", DEC, doc="in 32-bit words")
    options = var_bytes(ihl * 4 - 20)


def test_fields_collected_in_order() -> None:
    assert [f.name for f in IPv4._fields] == ["version", "ihl", "options"]
    assert IPv4._name == "ipv4"


def test_intra_class_expr_resolves_after_finalization() -> None:
    expr = IPv4._fields[2].byte_len_expr
    assert expr is not None
    e = expr.to_pb()
    assert e.bin.lhs.bin.lhs.field.header == "ipv4"
    assert e.bin.lhs.bin.lhs.field.field == "ihl"


def test_class_attribute_access_returns_spec() -> None:
    assert IPv4.ihl.width_bits == 4


def test_name_override_and_snake_case() -> None:
    class OptMss(Header, name="opt_mss_x"):
        kind = bits(8)

    class OptSackOk(Header):
        kind = bits(8)

    assert OptMss._name == "opt_mss_x"
    # Splits only at lower/digit->Upper: IPv4 -> ipv4, OptSackOk -> opt_sack_ok.
    assert OptSackOk._name == "opt_sack_ok"


def test_to_pb_shape() -> None:
    ht = IPv4.to_pb()
    assert ht.name == "ipv4"
    assert ht.fields[0].width.bits == 4
    assert ht.fields[2].width.byte_len.bin.rhs.constant == 20
    assert ht.fields[1].display.doc == "in 32-bit words"


def test_empty_header_rejected() -> None:
    with pytest.raises(ValueError, match="declares no fields"):

        class Empty(Header):
            pass

from pakeles import Header, bits, var_bytes


def test_var_bytes_length_expression_shifts():
    class ExtOpt(Header):
        next_header = bits(8)
        hdr_ext_len = bits(8)
        body = var_bytes(((1 + hdr_ext_len) << 3) - 2)

    ht = ExtOpt.to_pb()
    body = ht.fields[2]
    # MUL( SUB( SHL( ADD(hdr_ext_len, 1), 3 ), 2 ), 8 ) — the authored
    # byte expression wrapped by var_bytes's ×8 bit-denomination sugar.
    assert body.width.HasField("bit_len")
    top = body.width.bit_len
    assert top.bin.op == 3  # BIN_OP_KIND_MUL (the ×8 sugar)
    assert top.bin.rhs.constant == 8
    inner = top.bin.lhs
    assert inner.bin.op  # BIN_OP_KIND_SUB
    assert inner.bin.rhs.constant == 2
    assert inner.bin.lhs.bin.rhs.constant == 3  # SHL by 3

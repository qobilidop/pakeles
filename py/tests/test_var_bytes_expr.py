from pakeles import Header, bits, var_bytes


def test_var_bytes_length_expression_shifts():
    class ExtOpt(Header):
        next_header = bits(8)
        hdr_ext_len = bits(8)
        body = var_bytes(((1 + hdr_ext_len) << 3) - 2)

    ht = ExtOpt.to_pb()
    body = ht.fields[2]
    # SUB( SHL( ADD(hdr_ext_len, 1), 3 ), 2 )
    assert body.width.HasField("byte_len")
    top = body.width.byte_len
    assert top.bin.op  # BIN_OP_KIND_SUB
    assert top.bin.rhs.constant == 2
    assert top.bin.lhs.bin.rhs.constant == 3  # SHL by 3

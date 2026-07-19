//! Built-in protocol descriptions. Slice 1: Ethernet -> IPv4 -> TCP.

use crate::builder::*;
use crate::ir::pb;

/// Ethernet II -> IPv4 (with options) -> TCP (fixed 20-byte portion).
///
/// `tshark.key` annotations mark numeric fields diffed against
/// `tshark -T json`; address-typed fields are not annotated in slice 1.
pub fn eth_ipv4_tcp() -> pb::Ir {
    ParserBuilder::new("eth_ipv4_tcp", 4)
        .header(
            HeaderTypeBuilder::new("ethernet")
                .bits("dst", 48)
                .bits("src", 48)
                .bits_ann("ethertype", 16, &[("tshark.key", "eth.type")]),
        )
        .header(
            HeaderTypeBuilder::new("ipv4")
                .bits_ann("version", 4, &[("tshark.key", "ip.version")])
                .bits("ihl", 4)
                .bits("dscp", 6)
                .bits("ecn", 2)
                .bits_ann("total_len", 16, &[("tshark.key", "ip.len")])
                .bits("id", 16)
                .bits("flags", 3)
                .bits("frag_offset", 13)
                .bits_ann("ttl", 8, &[("tshark.key", "ip.ttl")])
                .bits_ann("protocol", 8, &[("tshark.key", "ip.proto")])
                .bits_ann("checksum", 16, &[("tshark.key", "ip.checksum")])
                .bits("src", 32)
                .bits("dst", 32)
                .var_bytes("options", sub(mul(f("ipv4", "ihl"), c(4)), c(20))),
        )
        .header(
            HeaderTypeBuilder::new("tcp")
                .bits_ann("sport", 16, &[("tshark.key", "tcp.srcport")])
                .bits_ann("dport", 16, &[("tshark.key", "tcp.dstport")])
                .bits("seq", 32)
                .bits("ack", 32)
                .bits("data_offset", 4)
                .bits("reserved", 4)
                .bits("flags", 8)
                .bits("window", 16)
                .bits("checksum", 16)
                .bits("urgent", 16),
        )
        .state(StateBuilder::new("parse_ethernet").extract("ethernet").select(
            vec![f("ethernet", "ethertype")],
            vec![arm(vec![v(0x0800)], to("parse_ipv4"))],
            reject("unsupported ethertype"),
        ))
        .state(StateBuilder::new("parse_ipv4").extract("ipv4").select(
            vec![f("ipv4", "protocol")],
            vec![arm(vec![v(6)], to("parse_tcp"))],
            reject("unsupported ip protocol"),
        ))
        .state(StateBuilder::new("parse_tcp").extract("tcp").accept())
        .start("parse_ethernet")
        .build()
        .expect("eth_ipv4_tcp example must validate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_validates() {
        crate::ir::validate::validate(&eth_ipv4_tcp()).unwrap();
    }

    #[test]
    fn example_json_snapshot() {
        let json = crate::ir::to_json(&eth_ipv4_tcp()).unwrap();
        insta::assert_snapshot!(json);
    }
}

//! Built-in protocol descriptions: the `eth_ipvx_l4` hello-world stack.

use crate::builder::*;
use crate::ir::pb;
use pb::DisplayFormat as F;

/// Ethernet II -> {IPv4 (with options) | IPv6} -> {TCP | UDP}.
///
/// The canonical hello-world example. It *branches*: EtherType demuxes
/// to IPv4 or IPv6, and each IP header demuxes to a shared TCP or UDP
/// successor state (a join in the parse DAG) — so it teaches
/// demultiplexing, not just field-mapping.
///
/// Fully annotated: typed `Display` presentation (names, formats,
/// value labels) drives the generated dissector and docs; `tshark.key`
/// annotations mark fields diffed against tshark's built-in dissector.
/// IPv6 addresses are 128-bit, above the fixed-`bits` ceiling, so they
/// are `var_bytes` opaque runs (rendered as hex; not tshark-diffed).
/// Unknown next-protocol rejects are payload boundaries
/// (severity=info), not errors.
pub fn eth_ipvx_l4() -> pb::Ir {
    ParserBuilder::new("eth_ipvx_l4", 4)
        .header(
            HeaderTypeBuilder::new("ethernet")
                .bits_full(
                    "dst",
                    48,
                    disp("Destination", F::Ether),
                    &[("tshark.key", "eth.dst")],
                )
                .bits_full(
                    "src",
                    48,
                    disp("Source", F::Ether),
                    &[("tshark.key", "eth.src")],
                )
                .bits_full(
                    "ethertype",
                    16,
                    disp("Type", F::Hex).labels(&[
                        (0x0800, "IPv4"),
                        (0x0806, "ARP"),
                        (0x8100, "802.1Q VLAN"),
                        (0x86DD, "IPv6"),
                    ]),
                    &[("tshark.key", "eth.type")],
                ),
        )
        .header(
            HeaderTypeBuilder::new("ipv4")
                .bits_full(
                    "version",
                    4,
                    disp("Version", F::Dec),
                    &[("tshark.key", "ip.version")],
                )
                .bits_full(
                    "ihl",
                    4,
                    disp("Header Length", F::Dec).doc("in 32-bit words"),
                    &[],
                )
                .bits_full("dscp", 6, disp("DSCP", F::Dec), &[])
                .bits_full("ecn", 2, disp("ECN", F::Dec), &[])
                .bits_full(
                    "total_len",
                    16,
                    disp("Total Length", F::Dec),
                    &[("tshark.key", "ip.len")],
                )
                .bits_full("id", 16, disp("Identification", F::Hex), &[])
                .bits_full("flags", 3, disp("Flags", F::Hex), &[])
                .bits_full("frag_offset", 13, disp("Fragment Offset", F::Dec), &[])
                .bits_full(
                    "ttl",
                    8,
                    disp("Time to Live", F::Dec),
                    &[("tshark.key", "ip.ttl")],
                )
                .bits_full(
                    "protocol",
                    8,
                    disp("Protocol", F::Dec).labels(&[(1, "ICMP"), (6, "TCP"), (17, "UDP")]),
                    &[("tshark.key", "ip.proto")],
                )
                .bits_full(
                    "checksum",
                    16,
                    disp("Header Checksum", F::Hex),
                    &[("tshark.key", "ip.checksum")],
                )
                .bits_full(
                    "src",
                    32,
                    disp("Source Address", F::Ipv4),
                    &[("tshark.key", "ip.src")],
                )
                .bits_full(
                    "dst",
                    32,
                    disp("Destination Address", F::Ipv4),
                    &[("tshark.key", "ip.dst")],
                )
                .var_bytes("options", sub(mul(f("ipv4", "ihl"), c(4)), c(20))),
        )
        .header(
            HeaderTypeBuilder::new("ipv6")
                .bits_full(
                    "version",
                    4,
                    disp("Version", F::Dec),
                    &[("tshark.key", "ipv6.version")],
                )
                .bits_full("traffic_class", 8, disp("Traffic Class", F::Hex), &[])
                .bits_full("flow_label", 20, disp("Flow Label", F::Hex), &[])
                .bits_full(
                    "payload_length",
                    16,
                    disp("Payload Length", F::Dec),
                    &[("tshark.key", "ipv6.plen")],
                )
                .bits_full(
                    "next_header",
                    8,
                    disp("Next Header", F::Dec).labels(&[(1, "ICMP"), (6, "TCP"), (17, "UDP")]),
                    &[("tshark.key", "ipv6.nxt")],
                )
                .bits_full(
                    "hop_limit",
                    8,
                    disp("Hop Limit", F::Dec),
                    &[("tshark.key", "ipv6.hlim")],
                )
                // 128-bit addresses exceed the fixed-`bits` ceiling: opaque
                // 16-byte runs (hex-rendered; the u64 tshark oracle can't diff them).
                .var_bytes("src", c(16))
                .var_bytes("dst", c(16)),
        )
        .header(
            HeaderTypeBuilder::new("tcp")
                .bits_full(
                    "sport",
                    16,
                    disp("Source Port", F::Dec),
                    &[("tshark.key", "tcp.srcport")],
                )
                .bits_full(
                    "dport",
                    16,
                    disp("Destination Port", F::Dec),
                    &[("tshark.key", "tcp.dstport")],
                )
                .bits_full("seq", 32, disp("Sequence Number", F::Dec), &[])
                .bits_full("ack", 32, disp("Acknowledgment Number", F::Dec), &[])
                .bits_full(
                    "data_offset",
                    4,
                    disp("Data Offset", F::Dec).doc("in 32-bit words"),
                    &[],
                )
                .bits_full("reserved", 4, disp("Reserved", F::Hex), &[])
                .bits_full("flags", 8, disp("Flags", F::Hex), &[])
                .bits_full("window", 16, disp("Window", F::Dec), &[])
                .bits_full("checksum", 16, disp("Checksum", F::Hex), &[])
                .bits_full("urgent", 16, disp("Urgent Pointer", F::Dec), &[]),
        )
        .header(
            HeaderTypeBuilder::new("udp")
                .bits_full(
                    "sport",
                    16,
                    disp("Source Port", F::Dec),
                    &[("tshark.key", "udp.srcport")],
                )
                .bits_full(
                    "dport",
                    16,
                    disp("Destination Port", F::Dec),
                    &[("tshark.key", "udp.dstport")],
                )
                .bits_full("length", 16, disp("Length", F::Dec), &[])
                .bits_full("checksum", 16, disp("Checksum", F::Hex), &[]),
        )
        .state(
            StateBuilder::new("parse_ethernet")
                .extract("ethernet")
                .select(
                    vec![f("ethernet", "ethertype")],
                    vec![
                        arm(vec![v(0x0800)], to("parse_ipv4")),
                        arm(vec![v(0x86DD)], to("parse_ipv6")),
                    ],
                    reject_info("unsupported ethertype"),
                ),
        )
        .state(StateBuilder::new("parse_ipv4").extract("ipv4").select(
            vec![f("ipv4", "protocol")],
            vec![
                arm(vec![v(6)], to("parse_tcp")),
                arm(vec![v(17)], to("parse_udp")),
            ],
            reject_info("unsupported ip protocol"),
        ))
        .state(StateBuilder::new("parse_ipv6").extract("ipv6").select(
            vec![f("ipv6", "next_header")],
            vec![
                arm(vec![v(6)], to("parse_tcp")),
                arm(vec![v(17)], to("parse_udp")),
            ],
            reject_info("unsupported ip protocol"),
        ))
        .state(StateBuilder::new("parse_tcp").extract("tcp").accept())
        .state(StateBuilder::new("parse_udp").extract("udp").accept())
        .start("parse_ethernet")
        .build()
        .expect("eth_ipvx_l4 example must validate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_validates() {
        crate::ir::validate::validate(&eth_ipvx_l4()).unwrap();
    }

    #[test]
    fn committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/eth_ipvx_l4.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples"
        );
    }

    #[test]
    fn committed_ir_json_current() {
        let json = crate::ir::to_json(&eth_ipvx_l4()).unwrap();
        let committed =
            std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.ir.json").unwrap();
        assert_eq!(
            json, committed,
            "examples/ drifted; regenerate: ./dev.sh cargo run --bin gen_examples"
        );
    }
}

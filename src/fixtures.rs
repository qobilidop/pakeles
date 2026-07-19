//! Deterministic packet fixtures shared by tests and `gen_fixtures`.

/// 54-byte Ethernet + IPv4(ihl=5) + TCP packet.
pub fn tcp_packet() -> Vec<u8> {
    let mut p = Vec::new();
    // ethernet
    p.extend([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
    p.extend([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
    p.extend([0x08, 0x00]); // ethertype IPv4
                            // ipv4, ihl=5
    p.extend([0x45, 0x00]); // version/ihl, dscp/ecn
    p.extend([0x00, 0x28]); // total_len 40
    p.extend([0x12, 0x34]); // id
    p.extend([0x40, 0x00]); // flags DF, frag 0
    p.extend([0x40, 0x06]); // ttl 64, proto TCP
    p.extend([0xDE, 0xAD]); // checksum (raw value; validity irrelevant to the diff)
    p.extend([10, 0, 0, 1]); // src
    p.extend([10, 0, 0, 2]); // dst
                             // tcp
    p.extend([0x30, 0x39]); // sport 12345
    p.extend([0x01, 0xBB]); // dport 443
    p.extend([0x00, 0x00, 0x00, 0x01]); // seq
    p.extend([0x00, 0x00, 0x00, 0x00]); // ack
    p.extend([0x50, 0x18]); // data_offset 5, flags PSH|ACK
    p.extend([0xFF, 0xFF]); // window
    p.extend([0x00, 0x00]); // checksum
    p.extend([0x00, 0x00]); // urgent
    assert_eq!(p.len(), 54);
    p
}

/// Same flow but ihl=6: 4 bytes of IPv4 options (NOP NOP NOP EOL).
pub fn tcp_packet_ihl6() -> Vec<u8> {
    let mut p = tcp_packet();
    p[14] = 0x46; // version 4, ihl 6
    p[16..18].copy_from_slice(&[0x00, 0x2C]); // total_len 44
    p.splice(34..34, [0x01, 0x01, 0x01, 0x00]); // options after dst addr
    assert_eq!(p.len(), 58);
    p
}

/// UDP variant of tcp_packet (protocol byte 17).
pub fn udp_packet() -> Vec<u8> {
    let mut p = tcp_packet();
    p[23] = 17;
    p
}

/// Truncated mid-ethernet: 10 bytes.
pub fn truncated_packet() -> Vec<u8> {
    tcp_packet()[..10].to_vec()
}

/// The four packets of `testdata/basic.pcap`, in order. Expected
/// interpreter outcomes: Accept, Accept, Reject(proto), Reject(oob).
pub fn basic_pcap_packets() -> Vec<Vec<u8>> {
    vec![
        tcp_packet(),
        tcp_packet_ihl6(),
        udp_packet(),
        truncated_packet(),
    ]
}

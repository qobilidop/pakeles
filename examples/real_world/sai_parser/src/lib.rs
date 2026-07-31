//! SAI (SONiC PINS) differential oracle: our parse of the `sai_parser`
//! example, projected to the incumbent's (header-validity bitmap,
//! parser-error) format, vs goldens minted by the instrumented sonic-pins
//! parser (pin e77250b8) run on `simple_switch` via `oracle/sai_parser/`.
//!
//! The bitmap bit order is the contract pinned in the design doc §4 and
//! the incumbent's observation patch: bit 0 = the CPU packet_out_header
//! (never set here — that arm is a boundary), 1 = ethernet, 2 = vlan,
//! 3 = ipv4, 4 = ipv6, 5 = arp, 6 = icmp, 7 = tcp, 8 = udp. A v1model
//! parse has no reject: running off the packet raises
//! `error.PacketTooShort` (err 1), which our truncation reject maps onto;
//! the bitmap then carries the headers extracted BEFORE the failing read.

use pakeles::ir::pb;
use serde::{Deserialize, Serialize};

/// Bit position (in the incumbent's verdict bitmap) for each modeled
/// instance. `packet_out_header` (bit 0) is the unmodeled CPU arm.
fn instance_bit(inst: &str) -> Option<u32> {
    Some(match inst {
        "ethernet" => 1,
        "vlan" => 2,
        "ipv4" => 3,
        "ipv6" => 4,
        "arp" => 5,
        "icmp" => 6,
        "tcp" => 7,
        "udp" => 8,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Projection {
    pub bitmap: u16,
    pub err: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    pub bitmap: u16,
    #[serde(default)]
    pub err: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub sonic_pins_commit: String,
    pub entries: Vec<GoldenEntry>,
}

/// Project our `sai_parser` parse to the incumbent's (bitmap, err).
/// Accept ⇒ every extracted instance's bit, err 0. Truncation reject ⇒
/// the bits of instances completed BEFORE the failing read, err 1
/// (BMv2 records `PacketTooShort` and the partial header stays invalid).
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Projection> {
    let res = pakeles::interp::run(ir, packet)?;
    let (completed, err) = match &res.outcome {
        pakeles::interp::Outcome::Accept => (res.headers.len(), 0u8),
        pakeles::interp::Outcome::Reject { reason } => {
            anyhow::ensure!(
                reason == "out of bounds",
                "unexpected reject `{reason}` from sai_parser (only truncation exists)"
            );
            // The last header is the partial (failing) one — not extracted.
            (res.headers.len().saturating_sub(1), 1u8)
        }
    };
    let mut bitmap: u16 = 0;
    for h in res.headers.iter().take(completed) {
        if let Some(bit) = instance_bit(&h.instance) {
            bitmap |= 1 << bit;
        }
    }
    Ok(Projection { bitmap, err })
}

pub struct SaiDiffReport {
    pub compared: usize,
    pub mismatches: Vec<String>,
}

/// This example's directory (the crate manifest dir): the description,
/// committed IR, `gen/`, `conformance/`, and `factory/` all live here.
pub fn dir() -> &'static std::path::Path {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The committed conformance directory (goldens + vector suite).
pub fn conformance_dir() -> std::path::PathBuf {
    dir().join("conformance")
}

/// The example description, parsed from the committed IR (embedded at
/// compile time).
pub fn ir() -> pb::Ir {
    pakeles::ir::from_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/sai_parser.ir.json"
    )))
    .expect("committed sai_parser IR must parse")
}

/// Find the committed sonic-pins-minted golden (`sai.<pin>.golden.json`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sai.") && n.ends_with(".golden.json"))
        })
}

/// Diff our projection against a golden file: bitmap + err exact.
pub fn diff_goldens(ir: &pb::Ir, golden: &GoldenFile) -> anyhow::Result<SaiDiffReport> {
    let mut report = SaiDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = pakeles::testvec::hex_decode(&e.packet_hex)?;
        report.compared += 1;
        let ours = project(ir, &pkt)?;
        if ours.bitmap != e.bitmap {
            report.mismatches.push(format!(
                "vector {i}: bitmap: ours={:#05x} golden={:#05x}",
                ours.bitmap, e.bitmap
            ));
        }
        if ours.err != e.err {
            report.mismatches.push(format!(
                "vector {i}: err: ours={} golden={}",
                ours.err, e.err
            ));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    /// Definition of done: our projected (bitmap, err) agree with the
    /// committed golden minted by the instrumented sonic-pins parser on
    /// simple_switch. A failure is a real disagreement — investigate
    /// against the vendored parser; never edit the golden.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        assert!(
            g.sonic_pins_commit.starts_with("e77250b8"),
            "golden minted at sonic-pins {} — the claim is pinned to e77250b8",
            g.sonic_pins_commit
        );
        assert!(
            g.entries.len() >= 20,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&ir(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with the sonic-pins parser:\n{}",
            report.mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    fn p(hex: &str) -> Projection {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(&hex.replace([' ', '\n'], "")).unwrap();
        project(&ir, &pkt).unwrap()
    }

    const ETH: &str = "aabbccddeeff112233445566";
    // instance bits
    const B_ETH: u16 = 1 << 1;
    const B_VLAN: u16 = 1 << 2;
    const B_IPV4: u16 = 1 << 3;
    const B_IPV6: u16 = 1 << 4;
    const B_ARP: u16 = 1 << 5;
    const B_ICMP: u16 = 1 << 6;
    const B_TCP: u16 = 1 << 7;
    const B_UDP: u16 = 1 << 8;

    const V4TCP: &str =
        "45000028123400004006dead0a0000010a000002303901bb00000001000000005010ffff00000000";
    const V6UDP: &str = "600000000008114020010db8000000000000000000000001\
                         20010db8000000000000000000000002303901bb00080000";

    #[test]
    fn v4_tcp() {
        let r = p(&format!("{ETH}0800{V4TCP}"));
        assert_eq!(r.bitmap, B_ETH | B_IPV4 | B_TCP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn v6_udp() {
        let r = p(&format!("{ETH}86dd{V6UDP}"));
        assert_eq!(r.bitmap, B_ETH | B_IPV6 | B_UDP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn v4_icmp() {
        let r = p(&format!(
            "{ETH}080045000028123400004001dead0a0000010a0000020800dead00000000"
        ));
        assert_eq!(r.bitmap, B_ETH | B_IPV4 | B_ICMP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn v4_other_proto_accepts_no_l4() {
        let r = p(&format!(
            "{ETH}080045000028123400004059dead0a0000010a000002"
        ));
        assert_eq!(r.bitmap, B_ETH | B_IPV4);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn arp() {
        let r = p(&format!(
            "{ETH}08060001080006040001112233445566 0a000001 aabbccddeeff 0a000002"
        ));
        assert_eq!(r.bitmap, B_ETH | B_ARP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn unknown_ethertype_eth_only() {
        let r = p(&format!("{ETH}88b5{}", "00".repeat(20)));
        assert_eq!(r.bitmap, B_ETH);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn vlan_v4_tcp() {
        let r = p(&format!("{ETH}810000640800{V4TCP}"));
        assert_eq!(r.bitmap, B_ETH | B_VLAN | B_IPV4 | B_TCP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn eth_truncated() {
        let r = p("aabbccddeeff11223344");
        assert_eq!(r.bitmap, 0);
        assert_eq!(r.err, 1);
    }

    #[test]
    fn ipv4_truncated() {
        let r = p(&format!("{ETH}080045000028123400004006"));
        assert_eq!(r.bitmap, B_ETH);
        assert_eq!(r.err, 1);
    }

    #[test]
    fn tcp_truncated_after_ip() {
        // proto=TCP but no L4 bytes: ipv4 extracted, tcp fails.
        let r = p(&format!(
            "{ETH}080045000028123400004006dead0a0000010a000002"
        ));
        assert_eq!(r.bitmap, B_ETH | B_IPV4);
        assert_eq!(r.err, 1);
    }

    #[test]
    fn vlan_truncated() {
        let r = p(&format!("{ETH}810000"));
        assert_eq!(r.bitmap, B_ETH);
        assert_eq!(r.err, 1);
    }
}

#[cfg(test)]
mod gallery_tests {
    use super::*;

    #[test]
    fn embedded_ir_parses_and_validates() {
        pakeles::ir::validate::validate(&ir()).unwrap();
    }

    /// The committed ir.json must be exactly what the Rust canonical
    /// serializer emits — the anti-drift "canonical form" guard.
    #[test]
    fn committed_ir_json_is_canonical() {
        let committed = std::fs::read_to_string(dir().join("sai_parser.ir.json")).unwrap();
        let round = pakeles::ir::to_json(&pakeles::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    /// The mirrored .py must match the authoritative eDSL module.
    #[test]
    fn committed_py_example_current() {
        let canonical =
            std::fs::read_to_string(dir().join("../../../py/src/pakeles/examples/sai_parser.py"))
                .unwrap();
        let mirrored = std::fs::read_to_string(dir().join("sai_parser.py")).unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn committed_gen_artifacts_current() {
        pakeles_testkit::committed_artifacts_current(&ir(), dir());
    }

    #[test]
    fn c_backend_conformance_full_suite() {
        pakeles_testkit::c_backend_conformance(
            &ir(),
            pakeles_testkit::committed_suite(dir()).as_ref(),
        );
    }

    #[test]
    fn bpf_backend_conformance_full_suite() {
        pakeles_testkit::bpf_backend_conformance(
            &ir(),
            pakeles_testkit::committed_suite(dir()).as_ref(),
        );
    }

    #[test]
    fn lua_backend_conformance_full_suite() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::lua_backend_conformance(&ir(), &suite, 20);
    }

    #[test]
    fn bmv2_backend_conformance_byte_aligned() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::bmv2_backend_conformance(&ir(), &suite, 12);
    }
}

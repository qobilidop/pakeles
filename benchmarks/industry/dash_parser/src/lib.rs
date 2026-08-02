//! DASH differential oracle: our parse of the `dash_parser` example,
//! projected to the incumbent's observation-verdict format (a
//! header-validity bitmap over the 18 parser-touched `headers_t`
//! instances, the v1model parser-error code, and four key parsed
//! fields), vs goldens minted by the instrumented DASH BMv2 parser
//! (pin d5c003dd7774) run on `simple_switch` via `factory/`.
//!
//! The bitmap bit order and the error-code table are the contract
//! pinned in `factory/instrument.py` (INSTANCE_BITS / ERROR_CODES) —
//! keep the two files identical. Two projection rules carry the
//! source's non-graph semantics:
//!
//! - **`packet_meta` is valid on every packet** (bit 0 always set):
//!   the source's `start` state pre-sets it valid with default field
//!   values before extracting anything; the wire header (EtherType
//!   0x876d) merely overwrites it. A failed wire re-extract leaves the
//!   defaults in place on BMv2, which matches our "partial extract
//!   drops the instance" rule because the bit is set unconditionally.
//! - **verify() rejects keep their header.** BMv2 runs `verify` after
//!   the extract completes, so an IPv4 with a bad version/IHL is
//!   *valid* in the incumbent's bitmap; only a truncation
//!   (`PacketTooShort`, our "out of bounds") loses the in-flight
//!   header. The reject reason strings in the description are the
//!   source's own error names, mapped to codes here.

use pakeles::ir::pb;
use serde::{Deserialize, Serialize};

/// Bit position (in the incumbent's verdict bitmap) for each modeled
/// instance — `headers_t` declaration order over the parser-touched
/// instances, identical to `INSTANCE_BITS` in `factory/instrument.py`.
fn instance_bit(inst: &str) -> Option<u32> {
    Some(match inst {
        "packet_meta" => 0,
        "flow_key" => 1,
        "flow_data" => 2,
        "flow_overlay_data" => 3,
        "flow_u0_encap_data" => 4,
        "flow_u1_encap_data" => 5,
        "u0_ethernet" => 6,
        "u0_ipv4" => 7,
        "u0_ipv4options" => 8,
        "u0_ipv6" => 9,
        "u0_udp" => 10,
        "u0_tcp" => 11,
        "u0_vxlan" => 12,
        "customer_ethernet" => 13,
        "customer_ipv4" => 14,
        "customer_ipv6" => 15,
        "customer_udp" => 16,
        "customer_tcp" => 17,
        _ => return None,
    })
}

/// Parser-error byte, identical to `ERROR_CODES` in
/// `factory/instrument.py`: our reject reasons are the source's error
/// names, so the mapping is a rename, not an interpretation.
fn err_code(reason: &str) -> Option<u8> {
    Some(match reason {
        "out of bounds" => 1, // error.PacketTooShort
        "IPv4IncorrectVersion" => 2,
        "IPv4OptionsNotSupported" => 3,
        "InvalidIPv4Header" => 4,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Projection {
    pub bitmap: u32,
    pub err: u8,
    pub subtype: u8,
    pub u0_ihl: u8,
    pub u0_udp_dst: u16,
    pub customer_ether_type: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    pub bitmap: u32,
    #[serde(default)]
    pub err: u8,
    #[serde(default)]
    pub subtype: u8,
    #[serde(default)]
    pub u0_ihl: u8,
    #[serde(default)]
    pub u0_udp_dst: u16,
    #[serde(default)]
    pub customer_ether_type: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub dash_commit: String,
    pub entries: Vec<GoldenEntry>,
}

fn field_u(h: &pakeles::interp::ParsedHeader, f: &str) -> Option<u64> {
    h.fields
        .iter()
        .find(|x| x.name == f)
        .and_then(|x| match &x.value {
            pakeles::interp::FieldValue::Uint(v) => Some(*v),
            _ => None,
        })
}

/// Project our `dash_parser` parse to the incumbent's verdict.
/// Accept ⇒ every extracted instance's bit, err 0. Truncation reject ⇒
/// the bits of instances completed BEFORE the failing read, err 1
/// (BMv2 records `PacketTooShort`; the partial header stays invalid).
/// Named (verify) rejects ⇒ every extracted instance's bit — the
/// verify runs after the extract on BMv2 — plus the mapped err code.
/// Bit 0 (`packet_meta`) is set unconditionally (the source's `start`
/// pre-sets it valid with defaults); the emitted fields come from
/// completed instances only, mirroring BMv2's isValid()-guarded reads
/// (the defaults are all-zero, so a missing wire header reads 0 on
/// both sides).
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Projection> {
    let res = pakeles::interp::run(ir, packet)?;
    let (completed, err) = match &res.outcome {
        pakeles::interp::Outcome::Accept => (res.headers.len(), 0u8),
        pakeles::interp::Outcome::Reject { reason } => {
            let code = err_code(reason)
                .ok_or_else(|| anyhow::anyhow!("unexpected reject `{reason}` from dash_parser"))?;
            if code == 1 {
                // The last header is the partial (failing) one.
                (res.headers.len().saturating_sub(1), code)
            } else {
                (res.headers.len(), code)
            }
        }
    };
    let done = &res.headers[..completed];
    let mut bitmap: u32 = 1 << 0; // packet_meta: pre-set valid in start
    for h in done {
        if let Some(bit) = instance_bit(&h.instance) {
            bitmap |= 1 << bit;
        }
    }
    let get = |inst: &str, field: &str| -> u64 {
        done.iter()
            .find(|h| h.instance == inst)
            .and_then(|h| field_u(h, field))
            .unwrap_or(0)
    };
    Ok(Projection {
        bitmap,
        err,
        subtype: get("packet_meta", "packet_subtype") as u8,
        u0_ihl: get("u0_ipv4", "ihl") as u8,
        u0_udp_dst: get("u0_udp", "dst_port") as u16,
        customer_ether_type: get("customer_ethernet", "ether_type") as u16,
    })
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
        "/dash_parser.ir.json"
    )))
    .expect("committed dash_parser IR must parse")
}

/// Find the committed DASH-minted golden (`dash.<pin>.golden.json`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut hits: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("dash.") && n.ends_with(".golden.json"))
        })
        .collect();
    // `read_dir` order is unspecified, so an unsorted `find` could
    // pick a different golden run-to-run once a second capture
    // exists. Pin the choice, and say so when there is more than
    // one — silently diffing against a stale incumbent version is
    // the failure mode worth shouting about.
    hits.sort();
    if hits.len() > 1 {
        eprintln!(
            "warning: {} goldens under {}; using `{}` (remove stale captures)",
            hits.len(),
            dir.display(),
            hits[0].display()
        );
    }
    hits.into_iter().next()
}

/// Diff our projection against a golden file: every verdict field
/// exact (no laxness rows — the diff run needed none).
pub fn diff_goldens(
    ir: &pb::Ir,
    golden: &GoldenFile,
) -> anyhow::Result<pakeles::oracle::GoldenDiffReport> {
    let mut report = pakeles::oracle::GoldenDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = pakeles::testvec::hex_decode(&e.packet_hex)?;
        report.compared += 1;
        let ours = project(ir, &pkt)?;
        let theirs = Projection {
            bitmap: e.bitmap,
            err: e.err,
            subtype: e.subtype,
            u0_ihl: e.u0_ihl,
            u0_udp_dst: e.u0_udp_dst,
            customer_ether_type: e.customer_ether_type,
        };
        if ours != theirs {
            report
                .mismatches
                .push(format!("vector {i}: ours={ours:?} golden={theirs:?}"));
        }
    }
    Ok(report)
}

/// The example's diff command (`src/main.rs` calls this): the
/// default IR, committed-golden discovery, and the diff. Everything
/// about diffing this incumbent lives in this crate.
pub fn cli_diff(
    ir: Option<&std::path::Path>,
    goldens: Option<&std::path::Path>,
) -> anyhow::Result<pakeles::oracle::GoldenDiffReport> {
    use anyhow::Context as _;
    let ir = match ir {
        None => self::ir(),
        Some(p) => pakeles::ir::load(p)?,
    };
    let goldens = match goldens {
        Some(p) => p.to_path_buf(),
        None => discover_committed_golden(&conformance_dir()).context(
            "no --goldens given and no committed dash.*.golden.json found under dash_parser/conformance/",
        )?,
    };
    let golden: GoldenFile = serde_json::from_str(
        &std::fs::read_to_string(&goldens)
            .with_context(|| format!("reading goldens from {}", goldens.display()))?,
    )?;
    diff_goldens(&ir, &golden)
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    /// The diff binary's default path: discover the committed golden,
    /// diff, come back clean.
    #[test]
    fn cli_diff_discovers_committed_golden_and_agrees() {
        let report = cli_diff(None, None).unwrap();
        assert!(report.compared > 0);
        assert!(
            report.mismatches.is_empty(),
            "{}",
            report.mismatches.join("\n")
        );
    }

    /// Definition of done: our projected verdict agrees with the
    /// committed golden minted by the instrumented DASH parser on
    /// simple_switch. A failure is a real disagreement — investigate
    /// against the vendored parser; never edit the golden.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        assert!(
            g.dash_commit.starts_with("d5c003dd7774"),
            "golden minted at DASH {} — the claim is pinned to d5c003dd7774",
            g.dash_commit
        );
        assert!(
            g.entries.len() >= 40,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&ir(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with the DASH parser:\n{}",
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

    const ETH_V4: &str = "aabbccddeeff112233445566 0800";
    // instance bits
    const B_META: u32 = 1 << 0;
    const B_FLOW_KEY: u32 = 1 << 1;
    const B_FLOW_DATA: u32 = 1 << 2;
    const B_OVERLAY: u32 = 1 << 3;
    const B_ENCAP_U0: u32 = 1 << 4;
    const B_ENCAP_U1: u32 = 1 << 5;
    const B_U0_ETH: u32 = 1 << 6;
    const B_U0_IPV4: u32 = 1 << 7;
    const B_U0_OPTS: u32 = 1 << 8;
    const B_U0_UDP: u32 = 1 << 10;
    const B_U0_TCP: u32 = 1 << 11;
    const B_U0_VXLAN: u32 = 1 << 12;
    const B_C_ETH: u32 = 1 << 13;
    const B_C_IPV4: u32 = 1 << 14;
    const B_C_TCP: u32 = 1 << 17;

    const V4_TCP: &str =
        "45000028123440004006dead0a0000010a000002 303901bb00000001000000005010ffff00000000";

    #[test]
    fn v4_tcp() {
        let r = p(&format!("{ETH_V4}{V4_TCP}"));
        assert_eq!(r.bitmap, B_META | B_U0_ETH | B_U0_IPV4 | B_U0_TCP);
        assert_eq!((r.err, r.subtype, r.u0_ihl), (0, 0, 5));
    }

    #[test]
    fn ihl6_options_then_tcp() {
        let r = p(&format!(
            "{ETH_V4}4600002c123440004006dead0a0000010a000002 01010101 303901bb00000001000000005010ffff00000000"
        ));
        assert_eq!(
            r.bitmap,
            B_META | B_U0_ETH | B_U0_IPV4 | B_U0_OPTS | B_U0_TCP
        );
        assert_eq!((r.err, r.u0_ihl), (0, 6));
    }

    #[test]
    fn bad_version_rejects_but_keeps_ipv4() {
        // verify(version == 4) fails AFTER the extract: the header is
        // valid on BMv2, so its bit and its ihl field both surface.
        let r = p(&format!("{ETH_V4}65000014123440004006dead0a0000010a000002"));
        assert_eq!(r.bitmap, B_META | B_U0_ETH | B_U0_IPV4);
        assert_eq!((r.err, r.u0_ihl), (2, 5));
    }

    #[test]
    fn ihl4_invalid_header() {
        let r = p(&format!("{ETH_V4}44000014123440004006dead0a0000010a000002"));
        assert_eq!(r.bitmap, B_META | B_U0_ETH | B_U0_IPV4);
        assert_eq!((r.err, r.u0_ihl), (4, 4));
    }

    #[test]
    fn tcp_port_4789_stays_tcp() {
        // The VXLAN port opens the customer layer from UDP only.
        let r = p(&format!(
            "{ETH_V4}45000028123440004006dead0a0000010a000002 303912b500000001000000005010ffff00000000"
        ));
        assert_eq!(r.bitmap, B_META | B_U0_ETH | B_U0_IPV4 | B_U0_TCP);
        assert_eq!(r.err, 0);
    }

    #[test]
    fn vxlan_customer_v4_tcp() {
        let r = p(&format!(
            "{ETH_V4}45000078123440004011dead0a0000010a000002 303912b500640000 0800000000006400 c0ffee000001c0ffee000002 0800 {V4_TCP}"
        ));
        assert_eq!(
            r.bitmap,
            B_META | B_U0_ETH | B_U0_IPV4 | B_U0_UDP | B_U0_VXLAN | B_C_ETH | B_C_IPV4 | B_C_TCP
        );
        assert_eq!(
            (r.err, r.u0_udp_dst, r.customer_ether_type),
            (0, 4789, 0x0800)
        );
    }

    #[test]
    fn customer_ihl6_options_not_supported() {
        let r = p(&format!(
            "{ETH_V4}45000078123440004011dead0a0000010a000002 303912b500640000 0800000000006400 c0ffee000001c0ffee000002 0800 46000018123440004006dead0a0000010a00000201010101"
        ));
        assert_eq!(
            r.bitmap,
            B_META | B_U0_ETH | B_U0_IPV4 | B_U0_UDP | B_U0_VXLAN | B_C_ETH | B_C_IPV4
        );
        assert_eq!(r.err, 3);
    }

    #[test]
    fn dash_delete_both_encaps() {
        let flow_key = "020000000001 0001 000000000000000000000000 0a000001 000000000000000000000000 0a000002 03e8 07d0 06 00";
        let flow_data = "00 0001 00000001 00000003 00000000 00000000";
        let overlay = format!(
            "020000000002 000000000000000000000000 0a000001 000000000000000000000000 0a000002 {}{} 0bb8 0fa0 00",
            "ff".repeat(16),
            "ff".repeat(16)
        );
        let encap = "000065 00 c0a80001 c0a80002 02000000000a 02000000000b 0001";
        let r = p(&format!(
            "aabbccddeeff112233445566 876d 00 03 0004 {flow_key} {flow_data} {overlay} {encap} {encap} c0ffee000001c0ffee000002 0800 {V4_TCP}"
        ));
        assert_eq!(
            r.bitmap,
            B_META
                | B_FLOW_KEY
                | B_FLOW_DATA
                | B_OVERLAY
                | B_ENCAP_U0
                | B_ENCAP_U1
                | B_U0_ETH
                | B_C_ETH
                | B_C_IPV4
                | B_C_TCP
        );
        assert_eq!((r.err, r.subtype), (0, 3));
    }

    #[test]
    fn eth_truncated() {
        // Only the start-state packet_meta default survives.
        let r = p("aabbccddeeff11223344");
        assert_eq!(r.bitmap, B_META);
        assert_eq!(r.err, 1);
    }

    #[test]
    fn packet_meta_truncated_keeps_default_bit() {
        // The wire re-extract fails; BMv2 keeps the valid defaults.
        let r = p("aabbccddeeff112233445566 876d 0000");
        assert_eq!(r.bitmap, B_META | B_U0_ETH);
        assert_eq!((r.err, r.subtype), (1, 0));
    }

    #[test]
    fn empty_packet() {
        let r = p("");
        assert_eq!(r.bitmap, B_META);
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
        let committed = std::fs::read_to_string(dir().join("dash_parser.ir.json")).unwrap();
        let round = pakeles::ir::to_json(&pakeles::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
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

    /// This description's 18 instances were the driver for widening
    /// the BMv2 oracle's bitmap decode past u16 (oracle/bmv2.rs) to
    /// match the P4 codegen's wider verdict tiers.
    #[test]
    fn bmv2_backend_conformance_byte_aligned() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::bmv2_backend_conformance(&ir(), &suite, 12);
    }
}

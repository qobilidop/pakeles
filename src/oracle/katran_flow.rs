//! Katran differential oracle: our parse of the `katran_flow` example,
//! projected to katran's parsed keys + XDP verdict, vs goldens minted by
//! the pinned katran balancer (dd915fd2, default build, empty maps) under
//! BPF_PROG_TEST_RUN via `oracle/katran_flow/factory/` (with the pakeles
//! observation patch exporting `packet_description`).
//!
//! Katran classifies every packet with an XDP verdict; the parse-relevant
//! set is {XDP_PASS, XDP_DROP, XDP_TX}. Our reject maps to XDP_DROP on the
//! modeled drop causes (ihl!=5, fragment, inner ihl!=5, truncation at/
//! after L3); our accept maps to PASS/TX by the trace shape. The ICMP
//! error path inverts src/dst and ports (katran's flow affinity for
//! errors), driven by the `is_icmp` metadata bit.

use crate::ir::pb;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "XDP_PASS")]
    Pass,
    #[serde(rename = "XDP_DROP")]
    Drop,
    #[serde(rename = "XDP_TX")]
    Tx,
}

/// The parsed katran flow keys (subset of `packet_description.flow` +
/// flags/tos). Addresses are lowercase hex of the 16-byte union (v4 =
/// 4-byte address then zero-filled, matching katran's zero-initialized
/// `struct packet_description pckt = {}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Flow {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub flags: u8,
    pub tos: u8,
    pub l4_reached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub verdict: Verdict,
    pub stage: u8,
    pub flow: Option<Flow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub stage: u8,
    #[serde(default)]
    pub out_hex: String,
    #[serde(default)]
    pub flow: Option<Flow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub katran_commit: String,
    pub kernel_version: String,
    pub map_config: String,
    pub entries: Vec<GoldenEntry>,
}

// katran F_* packet flags (balancer_consts.h).
const F_ICMP: u8 = 1 << 0;
const F_SYN_SET: u8 = 1 << 1;
const F_RST_SET: u8 = 1 << 2;

fn field_u(h: &crate::interp::ParsedHeader, f: &str) -> Option<u64> {
    h.fields
        .iter()
        .find(|x| x.name == f)
        .and_then(|x| match &x.value {
            crate::interp::FieldValue::Uint(v) => Some(*v),
            _ => None,
        })
}

fn field_bytes(h: &crate::interp::ParsedHeader, f: &str) -> Option<Vec<u8>> {
    h.fields
        .iter()
        .find(|x| x.name == f)
        .and_then(|x| match &x.value {
            crate::interp::FieldValue::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// v4 address (u32) → the 16-byte union hex: 4 network-order bytes then
/// 12 zero bytes.
fn v4_addr_hex(v: u64) -> String {
    let mut b = ((v as u32).to_be_bytes()).to_vec();
    b.resize(16, 0);
    hex(&b)
}

/// Project our `katran_flow` parse to (verdict, stage, flow).
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Projection> {
    let res = crate::interp::run(ir, packet)?;

    // A reject is always one of the modeled XDP_DROP causes (ihl!=5,
    // fragment, inner ihl!=5, truncation at/after L3) — the graph emits
    // no other reject.
    if !matches!(res.outcome, crate::interp::Outcome::Accept) {
        return Ok(Projection {
            verdict: Verdict::Drop,
            stage: 0,
            flow: None,
        });
    }

    let last_state = res
        .trace
        .last()
        .map(|t| t.state.as_str())
        .unwrap_or("parse_ethernet");
    let is_icmp = res.metadata.iter().any(|(n, v)| n == "is_icmp" && *v != 0);

    let find = |inst: &str| res.headers.iter().find(|h| h.instance == inst);
    let find_last = |inst: &str| res.headers.iter().rev().find(|h| h.instance == inst);
    let outer_ipv4 = find("ipv4");
    let inner_ipv4 = find("inner_ipv4");
    let first_ipv6 = find("ipv6");
    let last_ipv6 = find_last("ipv6");
    let icmp = find("icmp");
    let terminal = res.headers.last();

    // Non-IP EtherType: accepted at parse_ethernet → XDP_PASS, stage 0,
    // no keys (katran never enters process_packet).
    if last_state == "parse_ethernet" {
        return Ok(Projection {
            verdict: Verdict::Pass,
            stage: 0,
            flow: None,
        });
    }

    // Terminal ICMP header with no inner parse: echo → XDP_TX; any other
    // type → XDP_PASS, stage 0 (parse_icmp returned before the export).
    if !is_icmp
        && (last_state == "parse_icmp" || last_state == "parse_icmp6")
        && terminal.map(|h| h.instance.as_str()) == Some("icmp")
    {
        let ty = icmp.and_then(|h| field_u(h, "type")).unwrap_or(0);
        // v4 ICMP echo request = 8; ICMPv6 echo request = 128.
        let is_echo =
            (last_state == "parse_icmp" && ty == 8) || (last_state == "parse_icmp6" && ty == 128);
        return Ok(Projection {
            verdict: if is_echo { Verdict::Tx } else { Verdict::Pass },
            stage: 0,
            flow: None,
        });
    }

    // The flow-bearing IP header: inner on the ICMP path, outer otherwise.
    let flow_v4 = if is_icmp { inner_ipv4 } else { outer_ipv4 };
    // On the ICMP-v6 path there are two `ipv6` extractions (outer +
    // inner) — the inner (last) wins, exactly as katran overwrites.
    let flow_v6 = if is_icmp {
        // last_ipv6 is the inner one iff two exist; else there is no v6.
        if res.headers.iter().filter(|h| h.instance == "ipv6").count() >= 2 {
            last_ipv6
        } else {
            None
        }
    } else {
        first_ipv6
    };

    let mut flow = Flow::default();
    // tos: always the OUTER IP (katran sets pckt->tos before the ICMP
    // branch). v4 = (dscp<<2)|ecn; v6 = the traffic_class byte.
    if let Some(ip) = outer_ipv4 {
        flow.tos =
            ((field_u(ip, "dscp").unwrap_or(0) << 2) | field_u(ip, "ecn").unwrap_or(0)) as u8;
    } else if let Some(ip) = first_ipv6 {
        flow.tos = field_u(ip, "traffic_class").unwrap_or(0) as u8;
    }

    // Addresses + proto from the flow IP (swapped under ICMP).
    let swap = is_icmp;
    if let Some(ip) = flow_v4 {
        let s = field_u(ip, "src").unwrap_or(0);
        let d = field_u(ip, "dst").unwrap_or(0);
        let (s, d) = if swap { (d, s) } else { (s, d) };
        flow.src = v4_addr_hex(s);
        flow.dst = v4_addr_hex(d);
        flow.proto = field_u(ip, "protocol").unwrap_or(0) as u8;
    } else if let Some(ip) = flow_v6 {
        let s = field_bytes(ip, "src").unwrap_or_default();
        let d = field_bytes(ip, "dst").unwrap_or_default();
        let (s, d) = if swap { (d, s) } else { (s, d) };
        flow.src = hex(&s);
        flow.dst = hex(&d);
        flow.proto = field_u(ip, "next_header").unwrap_or(0) as u8;
    }
    if is_icmp {
        flow.flags |= F_ICMP;
    }

    // L4: ports (swapped under ICMP) + TCP flag lift. Terminal tcp/udp
    // means stage 3; an L3-only accept (proto dispatch default) is stage 1.
    let stage;
    match terminal.map(|h| h.instance.as_str()) {
        Some("tcp") => {
            let th = terminal.unwrap();
            let sp = field_u(th, "sport").unwrap_or(0) as u16;
            let dp = field_u(th, "dport").unwrap_or(0) as u16;
            let (sp, dp) = if swap { (dp, sp) } else { (sp, dp) };
            flow.sport = sp;
            flow.dport = dp;
            let tf = field_u(th, "flags").unwrap_or(0);
            if tf & 0x02 != 0 {
                flow.flags |= F_SYN_SET;
            }
            if tf & 0x04 != 0 {
                flow.flags |= F_RST_SET;
            }
            flow.l4_reached = true;
            stage = 3;
        }
        Some("udp") => {
            let uh = terminal.unwrap();
            let sp = field_u(uh, "sport").unwrap_or(0) as u16;
            let dp = field_u(uh, "dport").unwrap_or(0) as u16;
            let (sp, dp) = if swap { (dp, sp) } else { (sp, dp) };
            flow.sport = sp;
            flow.dport = dp;
            flow.l4_reached = true;
            stage = 3;
        }
        // L3-only accept (unknown proto): stage 1, ports 0.
        _ => {
            stage = 1;
        }
    }

    Ok(Projection {
        verdict: Verdict::Pass,
        stage,
        flow: Some(flow),
    })
}

/// Report from diffing our projection against a `GoldenFile`.
pub struct KatranDiffReport {
    pub compared: usize,
    pub mismatches: Vec<String>,
}

/// The conformance directory holding the committed goldens.
pub const CONFORMANCE_DIR: &str = "examples/real_world/katran_flow/conformance";

/// Find the committed katran-minted golden file (`katran.<pin>.golden.json`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("katran.") && n.ends_with(".golden.json"))
        })
}

/// Diff our projection against a golden file: verdict, stage, and every
/// flow field exact. `out_hex` (the XDP_TX mutation) and `quic` (a
/// boundary) are deliberately not compared.
pub fn diff_goldens(ir: &pb::Ir, golden: &GoldenFile) -> anyhow::Result<KatranDiffReport> {
    let mut report = KatranDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = crate::testvec::hex_decode(&e.packet_hex)?;
        report.compared += 1;
        let ours = project(ir, &pkt)?;
        if ours.verdict != e.verdict {
            report.mismatches.push(format!(
                "vector {i}: verdict: ours={:?} golden={:?}",
                ours.verdict, e.verdict
            ));
        }
        if ours.stage != e.stage {
            report.mismatches.push(format!(
                "vector {i}: stage: ours={} golden={}",
                ours.stage, e.stage
            ));
        }
        // Flow is compared only when the golden has one (stage&1); a
        // stage-0 verdict carries no flow on either side.
        match (&ours.flow, &e.flow) {
            (Some(o), Some(g)) if o != g => report
                .mismatches
                .push(format!("vector {i}: flow: ours={o:?} golden={g:?}")),
            (Some(_), None) if e.stage & 1 != 0 => report
                .mismatches
                .push(format!("vector {i}: flow: ours=Some golden=None")),
            (None, Some(_)) => report
                .mismatches
                .push(format!("vector {i}: flow: ours=None golden=Some")),
            _ => {}
        }
    }
    Ok(report)
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    /// Definition of done: our projected katran keys + verdict agree with
    /// the committed golden minted by the pinned balancer. A failure is a
    /// real disagreement — investigate against katran's source; never
    /// edit the golden.
    #[test]
    fn committed_goldens_agree() {
        let dir = std::path::Path::new(CONFORMANCE_DIR);
        let golden_path = discover_committed_golden(dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        assert!(
            g.katran_commit.starts_with("dd915fd2"),
            "golden minted at katran {} — the agreement claim is pinned to dd915fd2",
            g.katran_commit
        );
        assert!(
            g.entries.len() >= 28,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&crate::examples::katran_flow(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with katran:\n{}",
            report.mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    fn p(hex: &str) -> Projection {
        let ir = crate::examples::katran_flow();
        let pkt = crate::testvec::hex_decode(&hex.replace([' ', '\n'], "")).unwrap();
        project(&ir, &pkt).unwrap()
    }

    const ETH: &str = "aabbccddeeff112233445566";

    #[test]
    fn v4_tcp_pass() {
        let r = p(&format!(
            "{ETH}0800 450000281234000040 06 dead 0a000001 0a000002 \
             303901bb00000001000000005010ffff00000000"
        ));
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.stage, 3);
        let f = r.flow.unwrap();
        assert_eq!(f.src, "0a000001000000000000000000000000");
        assert_eq!(f.dst, "0a000002000000000000000000000000");
        assert_eq!(f.sport, 12345);
        assert_eq!(f.dport, 443);
        assert_eq!(f.proto, 6);
        assert_eq!(f.flags, 0);
        assert!(f.l4_reached);
    }

    #[test]
    fn v4_tcp_syn_flag() {
        let r = p(&format!(
            "{ETH}0800 450000281234000040 06 dead 0a000001 0a000002 \
             303901bb00000001000000005002ffff00000000"
        ));
        assert_eq!(r.flow.unwrap().flags, super::F_SYN_SET);
    }

    #[test]
    fn v4_ihl6_drops() {
        let r = p(&format!(
            "{ETH}0800 46000028123400000040 06 dead 0a000001 0a000002 01010101 \
             303901bb00000001000000005010ffff00000000"
        ));
        assert_eq!(r.verdict, Verdict::Drop);
        assert_eq!(r.stage, 0);
        assert!(r.flow.is_none());
    }

    #[test]
    fn v4_fragment_drops() {
        let r = p(&format!(
            "{ETH}0800 45000028123420000040 06 dead 0a000001 0a000002 \
             303901bb00000001000000005010ffff00000000"
        ));
        assert_eq!(r.verdict, Verdict::Drop);
    }

    #[test]
    fn v4_unknown_proto_pass_stage1() {
        let r = p(&format!(
            "{ETH}0800 450000281234000040 59 dead 0a000001 0a000002"
        ));
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.stage, 1);
        let f = r.flow.unwrap();
        assert_eq!(f.proto, 0x59);
        assert_eq!(f.sport, 0);
        assert!(!f.l4_reached);
    }

    #[test]
    fn arp_pass_stage0() {
        let r = p(&format!(
            "{ETH}0806 0001080006040001112233445566 0a000001 aabbccddeeff 0a000002"
        ));
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.stage, 0);
        assert!(r.flow.is_none());
    }

    #[test]
    fn icmp_echo_tx() {
        let r = p(&format!(
            "{ETH}0800 450000241234000040 01 dead 0a000001 0a000002 0800dead00000000"
        ));
        assert_eq!(r.verdict, Verdict::Tx);
        assert_eq!(r.stage, 0);
    }

    #[test]
    fn icmp_other_type_pass() {
        let r = p(&format!(
            "{ETH}0800 450000241234000040 01 dead 0a000001 0a000002 0500dead00000000"
        ));
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.stage, 0);
    }

    #[test]
    fn icmp_inner_v4_tcp_swapped() {
        // ICMPv4 dest-unreach + inner v4 (src 0a000005 dst 0a000006) / TCP.
        let r = p(&format!(
            "{ETH}0800 450000241234000040 01 dead 0a000001 0a000002 \
             0300dead00000000 \
             450000281234000040 06 dead 0a000005 0a000006 \
             303901bb00000001000000005010ffff00000000"
        ));
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.stage, 3);
        let f = r.flow.unwrap();
        // Inner addresses AND ports swapped, F_ICMP set.
        assert_eq!(f.src, "0a000006000000000000000000000000");
        assert_eq!(f.dst, "0a000005000000000000000000000000");
        assert_eq!(f.sport, 443);
        assert_eq!(f.dport, 12345);
        assert_eq!(f.proto, 6);
        assert_eq!(f.flags, super::F_ICMP);
    }

    #[test]
    fn v6_tcp_pass() {
        let r = p(&format!(
            "{ETH}86dd 6000000000000640 \
             20010db8000000000000000000000001 20010db8000000000000000000000002 \
             303901bb00000001000000005010ffff00000000"
        ));
        let f = r.flow.unwrap();
        assert_eq!(f.src, "20010db8000000000000000000000001");
        assert_eq!(f.proto, 6);
        assert_eq!(f.sport, 12345);
    }

    #[test]
    fn v6_fragment_drops() {
        let r = p(&format!(
            "{ETH}86dd 6000000000002c40 \
             20010db8000000000000000000000001 20010db8000000000000000000000002 \
             3b00000000000001"
        ));
        assert_eq!(r.verdict, Verdict::Drop);
    }
}

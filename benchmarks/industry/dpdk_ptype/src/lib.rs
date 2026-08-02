//! DPDK ptype differential oracle: our parse of the `dpdk_ptype` example,
//! projected to `(RTE_PTYPE_* mask, rte_net_hdr_lens)`, vs goldens minted
//! by DPDK's own `rte_net_get_ptype()` (v23.11.4) via
//! `factory/capture.c` (in this example's directory).
//!
//! There is no drop verdict: DPDK classifies every packet, stopping early
//! with a partial mask when a header read fails. Our parser trunc-rejects
//! at the same read boundaries; the projection maps those reject traces
//! onto DPDK's partial answers (the laxness rule, design doc §3). Reject
//! classes whose DPDK answer needs bytes we never extracted (regions DPDK
//! arithmetic-skips: IPv4 options, IPv6 ext bodies, GRE optionals,
//! mid-fragment truncation, and the ihl<5 cursor rewind) are UNMAPPABLE:
//! `project` returns an error, so a corpus line in an excluded class is a
//! red gate, never a silent skip.

use pakeles::ir::pb;
use serde::{Deserialize, Serialize};

// RTE_PTYPE_* constants, values from the pinned v23.11.4
// lib/mbuf/rte_mbuf_ptype.h. Note the L3/INNER_L3/INNER_L2 values are
// enumerated nibbles, not independent bits — each nibble is written once.
pub const L2_ETHER: u32 = 0x0000_0001;
pub const L2_ETHER_VLAN: u32 = 0x0000_0006;
pub const L2_ETHER_QINQ: u32 = 0x0000_0007;
pub const L2_MASK: u32 = 0x0000_000f;
pub const L3_IPV4: u32 = 0x0000_0010;
pub const L3_IPV4_EXT: u32 = 0x0000_0030;
pub const L3_IPV6: u32 = 0x0000_0040;
pub const L3_IPV6_EXT: u32 = 0x0000_00c0;
pub const L3_MASK: u32 = 0x0000_00f0;
pub const L4_TCP: u32 = 0x0000_0100;
pub const L4_UDP: u32 = 0x0000_0200;
pub const L4_FRAG: u32 = 0x0000_0300;
pub const L4_SCTP: u32 = 0x0000_0400;
pub const TUNNEL_IP: u32 = 0x0000_1000;
pub const TUNNEL_GRE: u32 = 0x0000_2000;
pub const TUNNEL_NVGRE: u32 = 0x0000_4000;
pub const INNER_L2_ETHER: u32 = 0x0001_0000;
pub const INNER_L2_ETHER_VLAN: u32 = 0x0002_0000;
pub const INNER_L2_ETHER_QINQ: u32 = 0x0003_0000;
pub const INNER_L2_MASK: u32 = 0x000f_0000;
pub const INNER_L3_IPV4: u32 = 0x0010_0000;
pub const INNER_L3_IPV4_EXT: u32 = 0x0020_0000;
pub const INNER_L3_IPV6: u32 = 0x0030_0000;
pub const INNER_L3_IPV6_EXT: u32 = 0x0050_0000;
pub const INNER_L3_MASK: u32 = 0x00f0_0000;
pub const INNER_L4_TCP: u32 = 0x0100_0000;
pub const INNER_L4_UDP: u32 = 0x0200_0000;
pub const INNER_L4_FRAG: u32 = 0x0300_0000;
pub const INNER_L4_SCTP: u32 = 0x0400_0000;

/// `struct rte_net_hdr_lens`, the subset rte_net_get_ptype writes.
/// Fields off the taken path are zero (the harness zero-initializes,
/// mirroring what a correct caller must do).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HdrLens {
    pub l2_len: u32,
    pub l3_len: u32,
    pub l4_len: u32,
    pub tunnel_len: u32,
    pub inner_l2_len: u32,
    pub inner_l3_len: u32,
    pub inner_l4_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub ptype: u32,
    pub hdr_lens: HdrLens,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    pub ptype: u32,
    /// Human-readable decode from rte_get_ptype_name — informational,
    /// never compared.
    #[serde(default)]
    pub ptype_name: String,
    pub hdr_lens: HdrLens,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub dpdk_version: String,
    pub entries: Vec<GoldenEntry>,
}

/// IPv6 next-header values `ptype_l3_ip6` maps to the EXT nibble.
/// (ESP/AH are in the map but `rte_net_skip_ip6_ext` default-returns
/// them without skipping — EXT bit, no walk.)
const IP6_EXT_PROTOS: [u64; 6] = [0, 43, 44, 50, 51, 60];

fn field_u(h: &pakeles::interp::ParsedHeader, f: &str) -> Option<u64> {
    h.fields
        .iter()
        .find(|x| x.name == f)
        .and_then(|x| match &x.value {
            pakeles::interp::FieldValue::Uint(v) => Some(*v),
            _ => None,
        })
}

fn is_inner_state(s: &str) -> bool {
    s.starts_with("parse_inner_")
}

/// The dispatch value a state hands to rte_net.c's next comparison: the
/// leftover proto after this header. None for states that don't dispatch.
fn dispatch_value(state: &str, h: &pakeles::interp::ParsedHeader) -> Option<u64> {
    match state {
        "parse_ethernet" | "parse_inner_ethernet" => field_u(h, "ethertype"),
        "parse_vlan" | "parse_qinq" | "parse_inner_vlan" | "parse_inner_qinq" => {
            field_u(h, "proto")
        }
        "parse_ipv4" | "parse_inner_ipv4" => field_u(h, "protocol"),
        "parse_ipv6" | "parse_inner_ipv6" => field_u(h, "next_header"),
        s if s.starts_with("parse_ext_opt") || s.starts_with("parse_inner_ext_opt") => {
            field_u(h, "next_header")
        }
        _ => None,
    }
}

/// Run the `dpdk_ptype` parser and project the result to DPDK's
/// `(ptype, hdr_lens)`, replaying rte_net.c's writes over our trace.
/// `Err` = the IR is malformed OR the packet falls in an unmappable
/// reject class (design §3) — the latter must never appear in the corpus.
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Projection> {
    let res = pakeles::interp::run(ir, packet)?;

    // Every state in this example extracts exactly one header, so trace
    // step i pairs with headers[i]; on an out-of-bounds reject the
    // failing state's PARTIAL header is also pushed (fields read so far).
    let failing: Option<&pakeles::interp::ParseError> = match &res.outcome {
        pakeles::interp::Outcome::Accept => None,
        pakeles::interp::Outcome::Reject { reason } => {
            anyhow::ensure!(
                reason == "out of bounds",
                "unexpected reject `{reason}` from dpdk_ptype (only truncation rejects exist)"
            );
            Some(res.error.as_ref().expect("reject carries error forensics"))
        }
    };
    let completed = if failing.is_some() {
        res.headers.len().saturating_sub(1)
    } else {
        res.headers.len()
    };
    anyhow::ensure!(
        res.trace.len() == res.headers.len(),
        "trace/header pairing broke: {} steps vs {} headers",
        res.trace.len(),
        res.headers.len()
    );

    let mut ptype: u32 = 0;
    let mut hl = HdrLens::default();

    // Tunnel-entry rule, applied on every transition (including into the
    // failing state — DPDK's ptype_tunnel runs before the inner read):
    // prev's dispatch value decides TUNNEL_IP. GRE bits are added by the
    // gre_opt pair itself. The byte-swap arms (design §2b): from L2
    // states, BE 0x0400/0x2900 read as host IPPROTO 4/41; from IP
    // states the u8 values 4/41 are the real thing; 8/129 reach the
    // inner section but MISS ptype_tunnel — no bit.
    let tunnel_ip_dispatch = |state: &str, v: u64| -> bool {
        match state {
            "parse_ethernet" | "parse_vlan" | "parse_qinq" => v == 0x0400 || v == 0x2900,
            "parse_ipv4" | "parse_ipv6" => v == 4 || v == 41,
            s if s.starts_with("parse_ext_opt") => v == 4 || v == 41,
            _ => false,
        }
    };

    for i in 0..res.headers.len() {
        let state = res.trace[i].state.as_str();
        let h = &res.headers[i];
        // Transition INTO an inner-section state from a non-inner state:
        // rte_net.c already ran ptype_tunnel on the dispatch value.
        if i > 0 && is_inner_state(state) && !is_inner_state(res.trace[i - 1].state.as_str()) {
            let prev_state = res.trace[i - 1].state.as_str();
            if prev_state != "parse_gre_opt" {
                if let Some(v) = dispatch_value(prev_state, &res.headers[i - 1]) {
                    if tunnel_ip_dispatch(prev_state, v) {
                        ptype |= TUNNEL_IP; // tunnel_len stays 0: no bytes
                    }
                }
            }
        }
        if i >= completed {
            break; // the failing pair: handled by the reject mapping below
        }
        match state {
            "parse_ethernet" => {
                ptype = L2_ETHER;
                hl.l2_len = 14;
            }
            "parse_vlan" => {
                ptype = (ptype & !L2_MASK) | L2_ETHER_VLAN;
                hl.l2_len += 4;
            }
            "parse_qinq" => {
                ptype = (ptype & !L2_MASK) | L2_ETHER_QINQ;
                hl.l2_len += 8;
            }
            "parse_ipv4" | "parse_inner_ipv4" => {
                let vihl =
                    (field_u(h, "version").unwrap_or(0) << 4) | field_u(h, "ihl").unwrap_or(0);
                let inner = state == "parse_inner_ipv4";
                let bit = match (vihl, inner) {
                    (0x45, false) => L3_IPV4,
                    (0x46..=0x4F, false) => L3_IPV4_EXT,
                    (0x45, true) => INNER_L3_IPV4,
                    (0x46..=0x4F, true) => INNER_L3_IPV4_EXT,
                    _ => 0, // version_ihl outside the map: no L3 bit, walk continues
                };
                ptype |= bit;
                let l3 = (field_u(h, "ihl").unwrap_or(0) as u32) * 4;
                if inner {
                    hl.inner_l3_len = l3;
                } else {
                    hl.l3_len = l3;
                }
            }
            "parse_ipv6" | "parse_inner_ipv6" => {
                let next = field_u(h, "next_header").unwrap_or(0);
                let inner = state == "parse_inner_ipv6";
                let ext = IP6_EXT_PROTOS.contains(&next);
                ptype |= match (ext, inner) {
                    (false, false) => L3_IPV6,
                    (true, false) => L3_IPV6_EXT,
                    (false, true) => INNER_L3_IPV6,
                    (true, true) => INNER_L3_IPV6_EXT,
                };
                if inner {
                    hl.inner_l3_len = 40;
                } else {
                    hl.l3_len = 40;
                }
            }
            s if s.starts_with("parse_ext_opt") || s.starts_with("parse_inner_ext_opt") => {
                let step = ((1 + field_u(h, "hdr_ext_len").unwrap_or(0)) * 8) as u32;
                if s.starts_with("parse_inner_") {
                    hl.inner_l3_len += step;
                } else {
                    hl.l3_len += step;
                }
            }
            "parse_ext_frag" | "parse_inner_ext_frag" => {
                if state == "parse_inner_ext_frag" {
                    hl.inner_l3_len += 8;
                } else {
                    hl.l3_len += 8;
                }
            }
            "parse_gre" => {} // bits/lens decided by gre_opt (or R=1: nothing)
            "parse_gre_opt" => {
                let gre = res.headers[..i]
                    .iter()
                    .rev()
                    .find(|x| x.instance == "gre")
                    .expect("gre_opt follows gre");
                let opt = (field_u(gre, "c").unwrap_or(0)
                    + field_u(gre, "k").unwrap_or(0)
                    + field_u(gre, "s").unwrap_or(0)) as u32;
                hl.tunnel_len = 4 + 4 * opt;
                ptype |= if field_u(gre, "proto") == Some(0x6558) {
                    TUNNEL_NVGRE
                } else {
                    TUNNEL_GRE
                };
            }
            "parse_tcp" | "parse_inner_tcp" => {
                let l4 = (field_u(h, "data_offset").unwrap_or(0) as u32) * 4;
                if state == "parse_inner_tcp" {
                    ptype |= INNER_L4_TCP;
                    hl.inner_l4_len = l4;
                } else {
                    ptype |= L4_TCP;
                    hl.l4_len = l4;
                }
            }
            "parse_inner_ethernet" => {
                ptype |= INNER_L2_ETHER;
                hl.inner_l2_len = 14;
            }
            "parse_inner_vlan" => {
                ptype = (ptype & !INNER_L2_MASK) | INNER_L2_ETHER_VLAN;
                hl.inner_l2_len += 4;
            }
            "parse_inner_qinq" => {
                ptype = (ptype & !INNER_L2_MASK) | INNER_L2_ETHER_QINQ;
                hl.inner_l2_len += 8;
            }
            other => anyhow::bail!("unknown dpdk_ptype state `{other}`"),
        }
    }

    if let Some(err) = failing {
        // The laxness rule: map the truncation onto DPDK's early return.
        let partial = res.headers.last().expect("failing partial header pushed");
        let avail = packet.len().saturating_sub(partial.start_bit / 8);
        let unmappable = |what: &str| {
            anyhow::bail!(
                "unmappable reject class at {} (avail {avail}B): {what} — excluded from the \
                 corpus by design (see the dpdk_ptype design doc §3)",
                err.state
            )
        };
        match err.state.as_str() {
            // eh read fails: rte_net.c returns literal 0, lens unwritten.
            "parse_ethernet" => {
                return Ok(Projection {
                    ptype: 0,
                    hdr_lens: HdrLens::default(),
                })
            }
            // Claim-before-read: the VLAN/QINQ bit is set before the tag
            // read; l2_len advances only after.
            "parse_vlan" => ptype = (ptype & !L2_MASK) | L2_ETHER_VLAN,
            "parse_qinq" => ptype = (ptype & !L2_MASK) | L2_ETHER_QINQ,
            "parse_ipv4" | "parse_inner_ipv4" => {
                if avail >= 20 {
                    return unmappable("IPv4 options region truncated or ihl<5 rewind");
                }
                // 20-byte struct read fails: mask/lens so far.
            }
            "parse_ipv6" | "parse_inner_ipv6" => {
                debug_assert!(avail < 40);
            }
            s if s.starts_with("parse_ext_opt") || s.starts_with("parse_inner_ext_opt") => {
                if avail >= 2 {
                    return unmappable("IPv6 ext-header body truncated");
                }
                // Walk read fails: l3_len snaps to the pre-walk 40
                // (rte_net.c only writes the final l3_len on success).
                if s.starts_with("parse_inner_") {
                    hl.inner_l3_len = 40;
                } else {
                    hl.l3_len = 40;
                }
            }
            s @ ("parse_ext_frag" | "parse_inner_ext_frag") => {
                if avail >= 2 {
                    return unmappable("fragment header truncated mid-way");
                }
                if s == "parse_inner_ext_frag" {
                    hl.inner_l3_len = 40;
                } else {
                    hl.l3_len = 40;
                }
            }
            // GRE base read fails inside ptype_tunnel: returns 0 — no
            // tunnel bit, no advance; mask/lens so far.
            "parse_gre" => {}
            "parse_gre_opt" => return unmappable("GRE optional region truncated"),
            // TCP truncation strips the L4 bit (outer) or wipes
            // EVERYTHING but the inner L2/L3 bits (inner) — rte_net.c
            // :360-363 / :496-499.
            "parse_tcp" => ptype &= L2_MASK | L3_MASK,
            "parse_inner_tcp" => ptype &= INNER_L2_MASK | INNER_L3_MASK,
            "parse_inner_ethernet" => {}
            "parse_inner_vlan" => ptype = (ptype & !INNER_L2_MASK) | INNER_L2_ETHER_VLAN,
            "parse_inner_qinq" => ptype = (ptype & !INNER_L2_MASK) | INNER_L2_ETHER_QINQ,
            other => anyhow::bail!("unknown failing state `{other}`"),
        }
        return Ok(Projection {
            ptype,
            hdr_lens: hl,
        });
    }

    // Accept: terminal blind writes — L4 protocols DPDK reports without
    // reading (UDP/SCTP), the fragment stops, and the 5-link ext bail.
    let last_state = res.trace.last().expect("nonempty trace").state.as_str();
    let last = res.headers.last().expect("nonempty headers");
    match last_state {
        "parse_ipv4" | "parse_inner_ipv4" => {
            let inner = last_state == "parse_inner_ipv4";
            if field_u(last, "mf_frag_off").unwrap_or(0) != 0 {
                ptype |= if inner { INNER_L4_FRAG } else { L4_FRAG };
            } else {
                blind_l4(&mut ptype, &mut hl, field_u(last, "protocol"), inner);
            }
        }
        "parse_ipv6" | "parse_inner_ipv6" => {
            blind_l4(
                &mut ptype,
                &mut hl,
                field_u(last, "next_header"),
                last_state == "parse_inner_ipv6",
            );
        }
        "parse_ext_opt5" => hl.l3_len = 40, // MAX_EXT_HDRS bail: l3 snaps back
        "parse_inner_ext_opt5" => hl.inner_l3_len = 40,
        s if s.starts_with("parse_ext_opt") || s.starts_with("parse_inner_ext_opt") => {
            blind_l4(
                &mut ptype,
                &mut hl,
                field_u(last, "next_header"),
                s.starts_with("parse_inner_"),
            );
        }
        // A fragment is always terminal — but the FRAG bit is granted
        // only when the walk's returned proto != 0: a fragment whose
        // next_header is 0 (HOPOPTS) hits rte_net.c's `proto == 0` early
        // return and LOSES the bit (harness-verified quirk).
        "parse_ext_frag" | "parse_inner_ext_frag"
            if field_u(last, "next_header").unwrap_or(0) != 0 =>
        {
            ptype |= if last_state == "parse_inner_ext_frag" {
                INNER_L4_FRAG
            } else {
                L4_FRAG
            };
        }
        _ => {}
    }

    Ok(Projection {
        ptype,
        hdr_lens: hl,
    })
}

/// The blind terminal L4 writes: UDP/SCTP lengths are reported without a
/// single L4 byte being read (or present).
fn blind_l4(ptype: &mut u32, hl: &mut HdrLens, proto: Option<u64>, inner: bool) {
    match (proto, inner) {
        (Some(17), false) => {
            *ptype |= L4_UDP;
            hl.l4_len = 8;
        }
        (Some(132), false) => {
            *ptype |= L4_SCTP;
            hl.l4_len = 12;
        }
        (Some(17), true) => {
            *ptype |= INNER_L4_UDP;
            hl.inner_l4_len = 8;
        }
        (Some(132), true) => {
            *ptype |= INNER_L4_SCTP;
            hl.inner_l4_len = 12;
        }
        _ => {}
    }
}

/// The conformance directory holding the committed goldens.
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
        "/dpdk_ptype.ir.json"
    )))
    .expect("committed dpdk_ptype IR must parse")
}

/// Find the committed DPDK-minted golden file under `dir` (filename
/// starts with `ptype.dpdk-`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut hits: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ptype.dpdk-"))
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

/// Diff our projection against a golden file: ptype exact, every
/// hdr_lens field exact. An unmappable projection is a mismatch (the
/// corpus must stay inside the mappable classes).
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
        let ours = match project(ir, &pkt) {
            Ok(p) => p,
            Err(err) => {
                report.mismatches.push(format!("vector {i}: {err}"));
                continue;
            }
        };
        if ours.ptype != e.ptype {
            report.mismatches.push(format!(
                "vector {i}: ptype: ours={:#010x} golden={:#010x} ({})",
                ours.ptype, e.ptype, e.ptype_name
            ));
        }
        if ours.hdr_lens != e.hdr_lens {
            report.mismatches.push(format!(
                "vector {i}: hdr_lens: ours={:?} golden={:?}",
                ours.hdr_lens, e.hdr_lens
            ));
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
            "no --goldens given and no committed ptype.dpdk-*.golden.json found under dpdk_ptype/conformance/",
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

    /// The definition of done: our projected `(ptype, hdr_lens)` agree
    /// with the DPDK-minted goldens committed in
    /// `benchmarks/industry/dpdk_ptype/conformance/` over the whole corpus —
    /// accepts exactly, truncations via the laxness rule. If this
    /// fails, that's a real disagreement between our parse/projection
    /// and DPDK 23.11 — investigate against rte_net.c; do NOT edit the
    /// golden file to force green.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        // Floors: only ratchet up. The version pin guards against a
        // silent re-mint under a different DPDK.
        assert!(
            g.dpdk_version.starts_with("DPDK 23.11"),
            "golden minted under `{}` — the agreement claim is pinned to DPDK 23.11",
            g.dpdk_version
        );
        assert!(
            g.entries.len() >= 78,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&ir(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with rte_net_get_ptype:\n{}",
            report.mismatches.join("\n")
        );
    }

    /// Live differential (no staleness): when the container has DPDK +
    /// gcc, rebuild the capture harness, re-run the corpus, and require
    /// the fresh capture to byte-match the committed golden. Skipped
    /// where the toolchain is absent (BMv2-precedent gating).
    #[test]
    fn live_dpdk_capture_matches_committed_golden() {
        let have_tools = std::process::Command::new("pkg-config")
            .args(["--exists", "libdpdk"])
            .status()
            .is_ok_and(|s| s.success())
            && std::process::Command::new("gcc")
                .arg("--version")
                .output()
                .is_ok();
        if !have_tools {
            eprintln!("skipping: libdpdk/gcc not available");
            return;
        }
        let dir = std::env::temp_dir().join("pakeles_dpdk_ptype_live");
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("capture");
        let cflags = std::process::Command::new("pkg-config")
            .args(["--cflags", "--libs", "libdpdk"])
            .output()
            .unwrap();
        let mut args: Vec<String> = vec![
            "-O2".into(),
            "-o".into(),
            bin.to_str().unwrap().into(),
            super::dir()
                .join("factory/capture.c")
                .to_str()
                .unwrap()
                .into(),
        ];
        args.extend(
            String::from_utf8_lossy(&cflags.stdout)
                .split_whitespace()
                .map(|s| s.to_string()),
        );
        let cc = std::process::Command::new("gcc")
            .args(&args)
            .output()
            .unwrap();
        assert!(
            cc.status.success(),
            "harness build failed:\n{}",
            String::from_utf8_lossy(&cc.stderr)
        );
        let out = std::process::Command::new(&bin)
            .arg(super::dir().join("factory/corpus.txt"))
            .output()
            .unwrap();
        assert!(out.status.success(), "capture run failed");
        let fresh = String::from_utf8(out.stdout).unwrap();
        let committed_path = discover_committed_golden(&conformance_dir()).unwrap();
        let committed = std::fs::read_to_string(&committed_path).unwrap();
        assert_eq!(
            fresh, committed,
            "live rte_net_get_ptype output drifted from the committed golden — \
             re-mint via factory/capture.sh and investigate"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_file_roundtrips() {
        let g = GoldenFile {
            dpdk_version: "DPDK 23.11.4".into(),
            entries: vec![GoldenEntry {
                packet_hex: "aabb".into(),
                ptype: 0x11,
                ptype_name: "L2_ETHER L3_IPV4 ".into(),
                hdr_lens: HdrLens {
                    l2_len: 14,
                    ..Default::default()
                },
            }],
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: GoldenFile = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entries[0].ptype, 0x11);
        assert_eq!(back.entries[0].hdr_lens.l2_len, 14);
    }
}

// Projection unit tests: byte-identical twins of the corpus matrix
// lines. Expected values hand-derived from the pinned rte_net.c (and
// cross-checked against harness probe runs, 2026-07-29); the golden
// mint is the independent authority the gate compares against.
#[cfg(test)]
mod project_tests {
    use super::*;

    const SRC6: &str = "20010db8000000000000000000000001";
    const DST6: &str = "20010db8000000000000000000000002";
    const TCP20: &str = "303901bb00000001000000005018ffff00000000"; // doff=5

    fn p(hex: &str) -> Projection {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(&hex.replace([' ', '\n'], "")).unwrap();
        project(&ir, &pkt).unwrap()
    }

    fn lens(v: [u32; 7]) -> HdrLens {
        HdrLens {
            l2_len: v[0],
            l3_len: v[1],
            l4_len: v[2],
            tunnel_len: v[3],
            inner_l2_len: v[4],
            inner_l3_len: v[5],
            inner_l4_len: v[6],
        }
    }

    // ---- plain accepts --------------------------------------------------

    #[test]
    fn v4_tcp() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 20, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn v4_udp() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004011dead0a0000010a000002 303901bb00140001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_UDP);
        assert_eq!(r.hdr_lens, lens([14, 20, 8, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_tcp() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000140640 {SRC6} {DST6} {TCP20}"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6 | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 40, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn v4_sctp_zero_l4_bytes() {
        // Blind l4_len 12: not a single SCTP byte present.
        let r = p("aabbccddeeff112233445566 0800 45000028123440004084dead0a0000010a000002");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_SCTP);
        assert_eq!(r.hdr_lens, lens([14, 20, 12, 0, 0, 0, 0]));
    }

    #[test]
    fn udp_zero_l4_bytes() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004011dead0a0000010a000002");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_UDP);
        assert_eq!(r.hdr_lens, lens([14, 20, 8, 0, 0, 0, 0]));
    }

    #[test]
    fn vlan_v4_tcp() {
        let r = p("aabbccddeeff112233445566 81000064 0800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER_VLAN | L3_IPV4 | L4_TCP);
        assert_eq!(r.hdr_lens, lens([18, 20, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn qinq_v6_udp() {
        let r = p(&format!(
            "aabbccddeeff112233445566 88a80064 81000065 86dd 6000000000141140 {SRC6} {DST6} 303901bb00140000"
        ));
        assert_eq!(r.ptype, L2_ETHER_QINQ | L3_IPV6 | L4_UDP);
        assert_eq!(r.hdr_lens, lens([22, 40, 8, 0, 0, 0, 0]));
    }

    #[test]
    fn v4_options_ext() {
        // ihl=6 (one options word, present): L3_IPV4_EXT, l3 24.
        let r = p("aabbccddeeff112233445566 0800 4600002c123440004006dead0a0000010a000002 01010101 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4_EXT | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 24, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn v4_unknown_proto_stops() {
        let r = p("aabbccddeeff112233445566 0800 4500002812344000403ddead0a0000010a000002");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    // ---- quirk accepts --------------------------------------------------

    #[test]
    fn mpls_dead_code() {
        // MPLS label present — and still plain L2_ETHER, l2 14.
        let r =
            p("aabbccddeeff112233445566 8847 00064140 45000028123440004006dead0a0000010a000002");
        assert_eq!(r.ptype, L2_ETHER);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn mpls_truncated_same() {
        let r = p("aabbccddeeff112233445566 8847 0006");
        assert_eq!(r.ptype, L2_ETHER);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn arp_l2_stop() {
        let r = p("aabbccddeeff112233445566 0806 0001080006040001112233445566 0a000001 aabbccddeeff 0a000002");
        assert_eq!(r.ptype, L2_ETHER);
    }

    #[test]
    fn bare_qinq_misreads_blind_tag() {
        // 0x88A8 followed directly by IPv4: rte_net.c still claims QINQ
        // (l2 22), misreading IPv4 bytes as the second tag; the misread
        // "proto" (0x2812) matches nothing.
        let r = p("aabbccddeeff112233445566 88a8 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER_QINQ);
        assert_eq!(r.hdr_lens, lens([22, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn double_vlan_inner_path() {
        // Q/Q: the second tag lands in the INNER section — no tunnel.
        let r = p("aabbccddeeff112233445566 81000064 81000065 0800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER_VLAN | INNER_L2_ETHER_VLAN | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([18, 0, 0, 0, 4, 20, 20]));
    }

    #[test]
    fn teb_at_top_no_tunnel() {
        let r = p("aabbccddeeff112233445566 6558 b1b2b3b4b5b6c1c2c3c4c5c6 0800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | INNER_L2_ETHER | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 14, 20, 20]));
    }

    #[test]
    fn version_ihl_0x55_no_l3_bit() {
        let r = p("aabbccddeeff112233445566 0800 55000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 20, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn tcp_doff8_without_options_bytes() {
        // doff=8 but zero options bytes present: blind l4_len 32.
        let r = p("aabbccddeeff112233445566 0800 45000028123440004006dead0a0000010a000002 303901bb00000001000000008018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 20, 32, 0, 0, 0, 0]));
    }

    #[test]
    fn v4_mf_frag() {
        let r = p("aabbccddeeff112233445566 0800 45000028123420004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | L4_FRAG);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_frag_first() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000082c40 {SRC6} {DST6} 3b00000000000001"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT | L4_FRAG);
        assert_eq!(r.hdr_lens, lens([14, 48, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_frag_next0_loses_frag_bit() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000082c40 {SRC6} {DST6} 0000000000000001"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT); // no L4_FRAG
        assert_eq!(r.hdr_lens, lens([14, 48, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_esp_ext_no_skip() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000083240 {SRC6} {DST6} 0102030405060708"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT);
        assert_eq!(r.hdr_lens, lens([14, 40, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_nh59_plain_stop() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000003b40 {SRC6} {DST6}"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6); // 59 not in the EXT map
        assert_eq!(r.hdr_lens, lens([14, 40, 0, 0, 0, 0, 0]));
    }

    // ---- ext chains -----------------------------------------------------

    #[test]
    fn opt_then_none() {
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000080040 {SRC6} {DST6} 3b00000000000000"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT);
        assert_eq!(r.hdr_lens, lens([14, 48, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn four_opts_tcp() {
        let opts = "0000000000000000".repeat(3) + "0600000000000000";
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000000040 {SRC6} {DST6} {opts} {TCP20}"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT | L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 72, 20, 0, 0, 0, 0]));
    }

    #[test]
    fn five_opts_bail() {
        // MAX_EXT_HDRS: 5 consumed links exhaust the walk — l3 snaps to
        // 40, no L4, whatever the 5th link promises.
        let opts = "0000000000000000".repeat(4) + "0600000000000000";
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000000040 {SRC6} {DST6} {opts} {TCP20}"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT);
        assert_eq!(r.hdr_lens, lens([14, 40, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn four_opts_then_frag() {
        let opts = "0000000000000000".repeat(3) + "2c00000000000000";
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000000040 {SRC6} {DST6} {opts} 0600000000000001"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT | L4_FRAG);
        assert_eq!(r.hdr_lens, lens([14, 80, 0, 0, 0, 0, 0]));
    }

    // ---- tunnels --------------------------------------------------------

    #[test]
    fn ipip() {
        let r = p("aabbccddeeff112233445566 0800 4500003c123440004004dead0a0000010a000002 45000028123440004006deadc0a80001c0a80002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_IP | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 20, 20]));
    }

    #[test]
    fn ip6ip_mixed() {
        let r = p(&format!(
            "aabbccddeeff112233445566 0800 45000050123440004029dead0a0000010a000002 6000000000140640 {SRC6} {DST6} {TCP20}"
        ));
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_IP | INNER_L3_IPV6 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 40, 20]));
    }

    #[test]
    fn gre_plain() {
        let r = p("aabbccddeeff112233445566 0800 4500004012344000402fdead0a0000010a000002 00000800 45000028123440004006deadc0a80001c0a80002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_GRE | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 0, 20, 20]));
    }

    #[test]
    fn gre_cks_optionals() {
        let r = p("aabbccddeeff112233445566 0800 4500004c12344000402fdead0a0000010a000002 b0000800 000000000000000100000002 45000028123440004006deadc0a80001c0a80002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_GRE | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 16, 0, 20, 20]));
    }

    #[test]
    fn gre_rbit_not_a_tunnel() {
        let r =
            p("aabbccddeeff112233445566 0800 4500002812344000402fdead0a0000010a000002 40000800");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn gre_version_ignored() {
        // version=1 with C+K+S and optionals+inner present: DPDK never
        // looks at version (contrast: the kernel accept-stops).
        let r = p("aabbccddeeff112233445566 0800 4500002812344000402fdead0a0000010a000002 b0010800 000000000000000000000000 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_GRE | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens.tunnel_len, 16);
    }

    #[test]
    fn nvgre_teb() {
        let r = p("aabbccddeeff112233445566 0800 4500004e12344000402fdead0a0000010a000002 00006558 b1b2b3b4b5b6c1c2c3c4c5c6 0800 45000028123440004006deadc0a80001c0a80002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_NVGRE | INNER_L2_ETHER | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 14, 20, 20]));
    }

    #[test]
    fn nvgre_inner_vlan_replaces() {
        let r = p(&format!(
            "aabbccddeeff112233445566 0800 4500006612344000402fdead0a0000010a000002 00006558 b1b2b3b4b5b6c1c2c3c4c5c6 8100 006586dd 6000000000140640 {SRC6} {DST6} {TCP20}"
        ));
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_NVGRE | INNER_L2_ETHER_VLAN | INNER_L3_IPV6 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 18, 40, 20]));
    }

    #[test]
    fn gre_proto_vlan_inner() {
        let r = p("aabbccddeeff112233445566 0800 4500002812344000402fdead0a0000010a000002 00008100 00640800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_GRE | INNER_L2_ETHER_VLAN | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 4, 20, 20]));
    }

    #[test]
    fn gre_mpls_stops_after_tunnel() {
        let r = p("aabbccddeeff112233445566 0800 4500002812344000402fdead0a0000010a000002 00008847 00064140");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | TUNNEL_GRE);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 0, 0, 0]));
    }

    #[test]
    fn double_ipip_one_level() {
        let r = p("aabbccddeeff112233445566 0800 45000050123440004004dead0a0000010a000002 45000028123440004004dead0a0000010a000002 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | TUNNEL_IP | INNER_L3_IPV4);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 20, 0]));
    }

    #[test]
    fn inner_v4_frag() {
        let r = p("aabbccddeeff112233445566 0800 4500003c123440004004dead0a0000010a000002 45000028123420004006deadc0a80001c0a80002");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | TUNNEL_IP | INNER_L3_IPV4 | INNER_L4_FRAG
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 20, 0]));
    }

    // ---- byte-swap quirks (little-endian hosts) -------------------------

    #[test]
    fn byteswap_ethertype_0400_is_ipip() {
        let r = p("aabbccddeeff112233445566 0400 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(r.ptype, L2_ETHER | TUNNEL_IP | INNER_L3_IPV4 | INNER_L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 20, 20]));
    }

    #[test]
    fn byteswap_ethertype_2900_is_ip6ip() {
        let r = p(&format!(
            "aabbccddeeff112233445566 2900 6000000000140640 {SRC6} {DST6} {TCP20}"
        ));
        assert_eq!(r.ptype, L2_ETHER | TUNNEL_IP | INNER_L3_IPV6 | INNER_L4_TCP);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 40, 20]));
    }

    #[test]
    fn byteswap_ethertype_2f00_is_gre() {
        let r = p("aabbccddeeff112233445566 2f00 00000800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | TUNNEL_GRE | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 4, 0, 20, 20]));
    }

    #[test]
    fn byteswap_proto8_inner_ipv4_no_tunnel() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004008dead0a0000010a000002 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | INNER_L3_IPV4 | INNER_L4_TCP // no TUNNEL bit
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 20, 20]));
    }

    #[test]
    fn byteswap_proto129_inner_vlan() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004081dead0a0000010a000002 00640800 45000028123440004006dead0a0000010a000002 303901bb00000001000000005018ffff00000000");
        assert_eq!(
            r.ptype,
            L2_ETHER | L3_IPV4 | INNER_L2_ETHER_VLAN | INNER_L3_IPV4 | INNER_L4_TCP
        );
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 4, 20, 20]));
    }

    // ---- the laxness rule: mapped truncations ---------------------------

    #[test]
    fn trunc_eth() {
        let r = p("aabbccddeeff11223344");
        assert_eq!(r.ptype, 0);
        assert_eq!(r.hdr_lens, lens([0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_vlan_claims_bit() {
        let r = p("aabbccddeeff112233445566 8100 0064");
        assert_eq!(r.ptype, L2_ETHER_VLAN);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_qinq_claims_bit() {
        let r = p("aabbccddeeff112233445566 88a8 006481");
        assert_eq!(r.ptype, L2_ETHER_QINQ);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_ipv4() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004006");
        assert_eq!(r.ptype, L2_ETHER);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_ipv6() {
        let r = p("aabbccddeeff112233445566 86dd 60000000001406");
        assert_eq!(r.ptype, L2_ETHER);
        assert_eq!(r.hdr_lens, lens([14, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_tcp_strips_l4() {
        let r = p(
            "aabbccddeeff112233445566 0800 45000028123440004006dead0a0000010a000002 303901bb0000",
        );
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4); // L4_TCP stripped
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_gre_base() {
        let r = p("aabbccddeeff112233445566 0800 4500002812344000402fdead0a0000010a000002 0000");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4); // no tunnel bit
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_inner_eth_behind_teb() {
        let r = p("aabbccddeeff112233445566 0800 4500002012344000402fdead0a0000010a000002 00006558 b1b2b3b4b5b6c1c2");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | TUNNEL_NVGRE);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 0, 0, 0]));
    }

    #[test]
    fn trunc_inner_ipv4_behind_gre() {
        let r = p("aabbccddeeff112233445566 0800 4500002612344000402fdead0a0000010a000002 00000800 45000028123440");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | TUNNEL_GRE);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 4, 0, 0, 0]));
    }

    #[test]
    fn trunc_inner_tcp_wipes_outer() {
        // The flagship quirk: rte_net.c :496-499 returns
        // pkt_type & (INNER_L2 | INNER_L3) — outer L2/L3/tunnel GONE.
        let r = p("aabbccddeeff112233445566 0800 45000028123440004004dead0a0000010a000002 45000028123440004006dead0a0000010a000002 303901bb000000010000");
        assert_eq!(r.ptype, INNER_L3_IPV4); // nothing else survives
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 20, 0]));
    }

    #[test]
    fn trunc_ext_prefix() {
        // 1 byte of ext header: walk read fails, l3 stays 40.
        let r = p(&format!(
            "aabbccddeeff112233445566 86dd 6000000000010040 {SRC6} {DST6} 06"
        ));
        assert_eq!(r.ptype, L2_ETHER | L3_IPV6_EXT);
        assert_eq!(r.hdr_lens, lens([14, 40, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn trunc_inner_ipv6_behind_ipip() {
        let r = p("aabbccddeeff112233445566 0800 45000028123440004029dead0a0000010a000002 6000000000140640010203");
        assert_eq!(r.ptype, L2_ETHER | L3_IPV4 | TUNNEL_IP);
        assert_eq!(r.hdr_lens, lens([14, 20, 0, 0, 0, 0, 0]));
    }

    // ---- unmappable classes hard-error ----------------------------------

    #[test]
    fn unmappable_gre_optionals_truncated() {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(
            "aabbccddeeff1122334455660800\
             4500002812344000402fdead0a0000010a000002\
             b0010800",
        )
        .unwrap();
        let err = project(&ir, &pkt).unwrap_err().to_string();
        assert!(err.contains("unmappable"), "{err}");
    }

    #[test]
    fn unmappable_ihl_wrap() {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(
            "aabbccddeeff1122334455660800\
             44000028123440004006dead0a0000010a000002\
             303901bb00000001000000005018ffff00000000",
        )
        .unwrap();
        let err = project(&ir, &pkt).unwrap_err().to_string();
        assert!(err.contains("unmappable"), "{err}");
    }

    #[test]
    fn unmappable_ext_body_absent() {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(
            &format!("aabbccddeeff11223344556686dd6000000000080040{SRC6}{DST6}1101000000000000")
                .replace(' ', ""),
        )
        .unwrap();
        let err = project(&ir, &pkt).unwrap_err().to_string();
        assert!(err.contains("unmappable"), "{err}");
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
        let committed = std::fs::read_to_string(dir().join("dpdk_ptype.ir.json")).unwrap();
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
        pakeles_testkit::lua_backend_conformance(&ir(), &suite, 200);
    }

    #[test]
    fn bmv2_backend_conformance_byte_aligned() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::bmv2_backend_conformance(&ir(), &suite, 50);
    }
}

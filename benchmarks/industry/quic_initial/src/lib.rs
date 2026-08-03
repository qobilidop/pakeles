//! quiche differential oracle (with a quinn-proto secondary lane): our
//! parse of the `quic_initial` example, projected to (kind, version,
//! CIDs, token, length), vs goldens minted by the pinned quiche
//! `Header::from_slice` and quinn-proto `ProtectedHeader::decode` via
//! `factory/`.
//!
//! Two lanes, per the design doc
//! (2026-07-31-quic-initial-design.md):
//!
//! **quiche (primary — the agreement claim).** quiche is the shape
//! match: no fixed-bit policy, no version allow-list, tolerant of
//! unknown versions. Named boundaries where we stop earlier than
//! quiche keep the matrix honest instead of silently lax:
//!   - Retry: we classify only (the token tail needs `remaining()-16`,
//!     v1-banned), so quiche's Retry token — and its InvalidPacket on
//!     a short Retry tail — are boundary rows.
//!   - Version negotiation: we do not walk the version list (quinn's
//!     stance), so quiche's BufferTooShort inside the list is a
//!     boundary row.
//!   - Unknown versions: we classify after the CIDs; quiche keeps
//!     parsing with v1 type bits, so its deeper errors are boundary
//!     rows.
//!
//! **quinn-proto (secondary — pinned divergences).** quinn is stricter
//! by design; every place it disagrees with us (and quiche) is PINNED
//! by a precondition rule, not ignored: fixed-bit-clear packets,
//! unsupported versions, and the unconditional 20-byte CID cap must
//! make quinn error — if such an entry ever parses OK, the lane
//! fails. In exchange quinn checks the one field quiche never parses:
//! the payload `length` varint.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    UnknownVersion,
    Short,
}

impl Kind {
    fn from_meta(v: u64) -> Option<Kind> {
        match v {
            1 => Some(Kind::Initial),
            2 => Some(Kind::ZeroRtt),
            3 => Some(Kind::Handshake),
            4 => Some(Kind::Retry),
            5 => Some(Kind::VersionNegotiation),
            6 => Some(Kind::UnknownVersion),
            7 => Some(Kind::Short),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OurClass {
    Parsed {
        kind: Kind,
        /// `None` for short headers (no version field on the wire).
        version: Option<u32>,
        /// `None` for short headers (DCID length is LB config).
        dcid: Option<Vec<u8>>,
        scid: Option<Vec<u8>>,
        /// `Some` only for Initial (empty token = `Some(vec![])`).
        token: Option<Vec<u8>>,
        /// `Some` for Initial / 0-RTT / Handshake (the payload-length
        /// varint value; quiche never parses it, quinn checks it).
        length: Option<u64>,
    },
    /// Buffer-truncation reject ("out of bounds") — quiche: BufferTooShort.
    Truncation,
    /// Structural reject (v1 CID caps + unreachable-arm guards).
    Structural { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
pub enum Lane {
    Ok {
        ty: String,
        #[serde(default)]
        version: Option<u32>,
        #[serde(default)]
        dcid: Option<String>,
        #[serde(default)]
        scid: Option<String>,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        len: Option<u64>,
        #[serde(default)]
        versions: Option<Vec<u32>>,
    },
    Err {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub hex: String,
    pub quiche: Lane,
    pub quinn: Lane,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    #[serde(rename = "quiche")]
    pub quiche_version: String,
    #[serde(rename = "quinn-proto")]
    pub quinn_version: String,
    pub entries: Vec<GoldenEntry>,
}

fn hdr_bytes(res: &pakeles::interp::ParseResult, inst: &str, field: &str) -> Option<Vec<u8>> {
    res.headers
        .iter()
        .find(|h| h.instance == inst)
        .and_then(|h| {
            h.fields
                .iter()
                .find(|f| f.name == field)
                .map(|f| match &f.value {
                    pakeles::interp::FieldValue::Bits(b) => b.clone(),
                    pakeles::interp::FieldValue::Uint(u) => u.to_be_bytes().to_vec(),
                })
        })
}

fn meta(res: &pakeles::interp::ParseResult, name: &str) -> Option<u64> {
    res.metadata
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| *v)
}

/// Project our `quic_initial` parse to the diffable class.
pub fn project(ir: &pakeles::ir::ValidatedIr, packet: &[u8]) -> anyhow::Result<OurClass> {
    let res = pakeles::interp::run(ir, packet)?;
    match res.outcome {
        pakeles::interp::Outcome::Accept => {
            let kind = meta(&res, "kind")
                .and_then(Kind::from_meta)
                .ok_or_else(|| anyhow::anyhow!("accepted parse without a packet kind"))?;
            let version = res
                .headers
                .iter()
                .find(|h| h.instance == "version")
                .and_then(|h| h.fields.iter().find(|f| f.name == "v"))
                .and_then(|f| match f.value {
                    pakeles::interp::FieldValue::Uint(u) => Some(u as u32),
                    pakeles::interp::FieldValue::Bits(_) => None,
                });
            let dcid =
                hdr_bytes(&res, "dcid", "cid").or_else(|| hdr_bytes(&res, "other_cids", "dcid"));
            let scid =
                hdr_bytes(&res, "scid", "cid").or_else(|| hdr_bytes(&res, "other_cids", "scid"));
            let token = if kind == Kind::Initial {
                ["tok0", "tok1", "tok2", "tok3"]
                    .iter()
                    .find_map(|i| hdr_bytes(&res, i, "body"))
            } else {
                None
            };
            let length = match kind {
                Kind::Initial | Kind::ZeroRtt | Kind::Handshake => meta(&res, "length"),
                _ => None,
            };
            Ok(OurClass::Parsed {
                kind,
                version,
                dcid,
                scid,
                token,
                length,
            })
        }
        pakeles::interp::Outcome::Reject { reason } if reason == "out of bounds" => {
            Ok(OurClass::Truncation)
        }
        pakeles::interp::Outcome::Reject { reason } => Ok(OurClass::Structural { reason }),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Ok-lane `ty` string vs our kind; each lane speaks its oracle's own
/// vocabulary (quiche "ZeroRTT"/"VersionNegotiation", quinn
/// "ZeroRtt"/"VersionNegotiate").
fn kind_matches_ty(kind: Kind, ty: &str) -> bool {
    matches!(
        (kind, ty),
        (Kind::Initial, "Initial")
            | (Kind::ZeroRtt, "ZeroRTT" | "ZeroRtt")
            | (Kind::Handshake, "Handshake")
            | (Kind::Retry, "Retry")
            | (
                Kind::VersionNegotiation,
                "VersionNegotiation" | "VersionNegotiate"
            )
            | (Kind::Short, "Short")
    )
}

/// Primary lane: `None` = compatible with quiche, `Some` = mismatch.
fn check_quiche(ours: &OurClass, lane: &Lane) -> Option<String> {
    match (ours, lane) {
        (
            OurClass::Parsed {
                kind,
                version,
                dcid,
                scid,
                token,
                ..
            },
            Lane::Ok {
                ty,
                version: g_version,
                dcid: g_dcid,
                scid: g_scid,
                token: g_token,
                ..
            },
        ) => {
            // Unknown versions: quiche parses on through with v1 type
            // bits; we classify. Compare version + CIDs only.
            if *kind == Kind::UnknownVersion {
                if version != g_version {
                    return Some(format!("version: ours={version:?} quiche={g_version:?}"));
                }
            } else if !kind_matches_ty(*kind, ty) {
                return Some(format!("kind: ours={kind:?} quiche ty={ty}"));
            }
            if *kind == Kind::Short {
                return None; // classify-only: DCID length is config
            }
            if !matches!(kind, Kind::UnknownVersion | Kind::VersionNegotiation)
                && version != g_version
            {
                return Some(format!("version: ours={version:?} quiche={g_version:?}"));
            }
            let ours_dcid = dcid.as_deref().map(hex).unwrap_or_default();
            if ours_dcid != g_dcid.clone().unwrap_or_default() {
                return Some(format!("dcid: ours={ours_dcid} quiche={g_dcid:?}"));
            }
            let ours_scid = scid.as_deref().map(hex).unwrap_or_default();
            if ours_scid != g_scid.clone().unwrap_or_default() {
                return Some(format!("scid: ours={ours_scid} quiche={g_scid:?}"));
            }
            // Token: compared for Initial only; quiche's Retry token is
            // a named boundary (we classify Retry after the SCID).
            if *kind == Kind::Initial {
                let ours_tok = token.as_deref().map(hex).unwrap_or_default();
                let g_tok = g_token.clone().unwrap_or_default();
                if ours_tok != g_tok {
                    return Some(format!("token: ours={ours_tok} quiche={g_tok}"));
                }
            }
            None
        }
        // Boundary rows: we stop earlier than quiche by design.
        (
            OurClass::Parsed {
                kind: Kind::Retry, ..
            },
            Lane::Err { error },
        ) if error.contains("InvalidPacket") => {
            None // Retry tail (< 16 bytes) — token unmodeled
        }
        (
            OurClass::Parsed {
                kind: Kind::VersionNegotiation,
                ..
            },
            Lane::Err { error },
        ) if error.contains("BufferTooShort") => {
            None // version-list walk — deliberately not modeled
        }
        (
            OurClass::Parsed {
                kind: Kind::UnknownVersion,
                ..
            },
            Lane::Err { .. },
        ) => {
            None // quiche parses unknown versions deeper than our classify
        }
        (OurClass::Truncation, Lane::Err { error }) if error.contains("BufferTooShort") => None,
        (OurClass::Structural { .. }, Lane::Err { error }) if error.contains("InvalidPacket") => {
            None
        }
        _ => Some(format!("class: ours={ours:?} quiche={lane:?}")),
    }
}

/// Secondary lane: quinn's strictness is PINNED — entries meeting a
/// divergence precondition must make quinn error.
fn check_quinn(ours: &OurClass, lane: &Lane, packet: &[u8]) -> Option<String> {
    let fixed_bit_clear = packet.first().is_some_and(|b| b & 0x40 == 0);
    match (ours, lane) {
        (
            OurClass::Parsed {
                kind,
                version,
                dcid,
                scid,
                token,
                length,
            },
            Lane::Ok {
                ty,
                version: g_version,
                dcid: g_dcid,
                scid: g_scid,
                token: g_token,
                len: g_len,
                ..
            },
        ) => {
            if fixed_bit_clear {
                return Some(
                    "pinned divergence stopped firing: quinn parsed a fixed-bit-clear packet"
                        .into(),
                );
            }
            if *kind == Kind::UnknownVersion {
                return Some(
                    "pinned divergence stopped firing: quinn parsed an unsupported version".into(),
                );
            }
            if !kind_matches_ty(*kind, ty) {
                return Some(format!("kind: ours={kind:?} quinn ty={ty}"));
            }
            if matches!(kind, Kind::Short | Kind::VersionNegotiation) {
                return None; // kind-only lanes (quinn: dcid_len config / no list)
            }
            if version != g_version {
                return Some(format!("version: ours={version:?} quinn={g_version:?}"));
            }
            let ours_dcid = dcid.as_deref().map(hex).unwrap_or_default();
            if ours_dcid != g_dcid.clone().unwrap_or_default() {
                return Some(format!("dcid: ours={ours_dcid} quinn={g_dcid:?}"));
            }
            let ours_scid = scid.as_deref().map(hex).unwrap_or_default();
            if ours_scid != g_scid.clone().unwrap_or_default() {
                return Some(format!("scid: ours={ours_scid} quinn={g_scid:?}"));
            }
            if *kind == Kind::Initial {
                let ours_tok = token.as_deref().map(hex).unwrap_or_default();
                let g_tok = g_token.clone().unwrap_or_default();
                if ours_tok != g_tok {
                    return Some(format!("token: ours={ours_tok} quinn={g_tok}"));
                }
            }
            // The one field ONLY this lane checks: the payload length.
            if matches!(kind, Kind::Initial | Kind::ZeroRtt | Kind::Handshake) && length != g_len {
                return Some(format!("length: ours={length:?} quinn={g_len:?}"));
            }
            None
        }
        (
            OurClass::Parsed {
                kind, dcid, scid, ..
            },
            Lane::Err { .. },
        ) => {
            // A quinn error against our successful parse must match a
            // pinned strictness rule.
            let oversized_cid = matches!(kind, Kind::VersionNegotiation | Kind::UnknownVersion)
                && (dcid.as_deref().is_some_and(|c| c.len() > 20)
                    || scid.as_deref().is_some_and(|c| c.len() > 20));
            if fixed_bit_clear || *kind == Kind::UnknownVersion || oversized_cid {
                None
            } else {
                Some(format!(
                    "unpinned quinn strictness: ours={ours:?} quinn={lane:?}"
                ))
            }
        }
        (OurClass::Truncation, Lane::Err { .. }) => None,
        (OurClass::Structural { .. }, Lane::Err { .. }) => None,
        _ => Some(format!("class: ours={ours:?} quinn={lane:?}")),
    }
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
pub fn ir() -> pakeles::ir::ValidatedIr {
    let raw = pakeles::ir::from_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/quic_initial.ir.json"
    )))
    .expect("committed quic_initial IR must parse");
    pakeles::ir::ValidatedIr::new(raw).expect("committed quic_initial IR must validate")
}

/// Find the committed quiche-minted golden (`initial.quiche-*.golden.json`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut hits: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("initial.quiche-") && n.ends_with(".golden.json"))
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

pub fn diff_goldens(
    ir: &pakeles::ir::ValidatedIr,
    golden: &GoldenFile,
) -> anyhow::Result<pakeles::oracle::GoldenDiffReport> {
    let mut report = pakeles::oracle::GoldenDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = pakeles::testvec::hex_decode(&e.hex)?;
        report.compared += 1;
        let ours = project(ir, &pkt)?;
        // Parse-extent gap row: quiche stops after the Initial token
        // and never reads the payload-length varint; we and quinn do.
        // A cut inside the length field is therefore quiche-Ok but
        // ours-Truncation — compatible ONLY when quinn confirms the
        // truncation (quinn Ok would mean we truncated a valid packet).
        if matches!(ours, OurClass::Truncation)
            && matches!(e.quiche, Lane::Ok { .. })
            && matches!(e.quinn, Lane::Err { .. })
        {
            continue;
        }
        if let Some(m) = check_quiche(&ours, &e.quiche) {
            report.mismatches.push(format!("vector {i} [quiche]: {m}"));
        }
        if let Some(m) = check_quinn(&ours, &e.quinn, &pkt) {
            report.mismatches.push(format!("vector {i} [quinn]: {m}"));
        }
    }
    Ok(report)
}

/// The example's diff command (`src/main.rs` calls this): the
/// default IR, committed-golden discovery, and the diff.
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
            "no --goldens given and no committed initial.quiche-*.golden.json found under quic_initial/conformance/",
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

    /// Definition of done: our projection is matrix-compatible with the
    /// committed quiche/quinn-minted golden over the whole corpus. A
    /// failure is a real disagreement — investigate against the
    /// oracles; never edit the golden.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        assert!(
            g.quiche_version.starts_with("0.29"),
            "golden minted at quiche {} — the agreement claim pins the 0.29 line",
            g.quiche_version
        );
        assert!(
            g.entries.len() >= 60,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&ir(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with quiche/quinn:\n{}",
            report.mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    fn p(hex: &str) -> OurClass {
        let ir = ir();
        let pkt = pakeles::testvec::hex_decode(&hex.replace([' ', '\n'], "")).unwrap();
        project(&ir, &pkt).unwrap()
    }

    #[test]
    fn minimal_initial_all_1byte_varints() {
        // c0: long/fixed/Initial. v1. Empty cids, empty token, length 0.
        assert_eq!(
            p("c0 00000001 00 00 00 00"),
            OurClass::Parsed {
                kind: Kind::Initial,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: Some(vec![]),
                length: Some(0),
            }
        );
    }

    #[test]
    fn two_byte_token_varint_carries_value_and_bytes() {
        // Token-length varint 0x4005 (2-byte form of 5) + 5 token bytes;
        // length varint 0x00.
        assert_eq!(
            p("c0 00000001 0102 00 4005 aabbccddee 00"),
            OurClass::Parsed {
                kind: Kind::Initial,
                version: Some(1),
                dcid: Some(vec![0x02]),
                scid: Some(vec![]),
                token: Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                length: Some(0),
            }
        );
    }

    #[test]
    fn eight_byte_length_varint() {
        // Length varint 0xc0000000000000fa: 8-byte form, value 250.
        assert_eq!(
            p("c0 00000001 00 00 00 c0000000000000fa"),
            OurClass::Parsed {
                kind: Kind::Initial,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: Some(vec![]),
                length: Some(250),
            }
        );
    }

    #[test]
    fn non_minimal_length_varint_accepted() {
        // 4-byte varint encoding of 0 (non-minimal): 80000000.
        assert_eq!(
            p("c0 00000001 00 00 00 80000000"),
            OurClass::Parsed {
                kind: Kind::Initial,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: Some(vec![]),
                length: Some(0),
            }
        );
    }

    #[test]
    fn handshake_routes_to_length_without_token() {
        // e0: long/fixed/Handshake (ty=2).
        assert_eq!(
            p("e0 00000001 00 00 00"),
            OurClass::Parsed {
                kind: Kind::Handshake,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: None,
                length: Some(0),
            }
        );
    }

    #[test]
    fn retry_is_classify_only() {
        // f0: long/fixed/Retry; anything after the SCID is unmodeled.
        assert_eq!(
            p("f0 00000001 00 00 ff ff ff"),
            OurClass::Parsed {
                kind: Kind::Retry,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: None,
                length: None,
            }
        );
    }

    #[test]
    fn short_header_is_classify_only() {
        assert_eq!(
            p("40"),
            OurClass::Parsed {
                kind: Kind::Short,
                version: None,
                dcid: None,
                scid: None,
                token: None,
                length: None,
            }
        );
    }

    #[test]
    fn version_negotiation_parses_uncapped_cids_not_the_list() {
        // Version 0; 21-byte DCID legal here (no v1 cap off-v1).
        let dcid = "ff".repeat(21);
        assert_eq!(
            p(&format!("80 00000000 15{dcid} 00 0000000100000002")),
            OurClass::Parsed {
                kind: Kind::VersionNegotiation,
                version: Some(0),
                dcid: Some(vec![0xff; 21]),
                scid: Some(vec![]),
                token: None,
                length: None,
            }
        );
    }

    #[test]
    fn unknown_version_classifies_after_cids() {
        assert_eq!(
            p("c0 deadbeef 0111 00"),
            OurClass::Parsed {
                kind: Kind::UnknownVersion,
                version: Some(0xdeadbeef),
                dcid: Some(vec![0x11]),
                scid: Some(vec![]),
                token: None,
                length: None,
            }
        );
    }

    #[test]
    fn fixed_bit_clear_still_parses() {
        // 80: long header, fixed bit 0 — quiche's stance; the quinn
        // lane pins the rejection.
        assert_eq!(
            p("80 00000001 00 00 00 00"),
            OurClass::Parsed {
                kind: Kind::Initial,
                version: Some(1),
                dcid: Some(vec![]),
                scid: Some(vec![]),
                token: Some(vec![]),
                length: Some(0),
            }
        );
    }

    #[test]
    fn v1_dcid_cap_is_structural() {
        assert_eq!(
            p(&format!("c0 00000001 15 {}", "ff".repeat(21))),
            OurClass::Structural {
                reason: "dcid too long for v1".into()
            }
        );
    }

    #[test]
    fn truncated_inside_token_is_truncation_class() {
        // Token-length varint says 5, only 2 token bytes present.
        assert_eq!(p("c0 00000001 00 00 05 aabb"), OurClass::Truncation);
    }

    #[test]
    fn truncated_varint_tail_is_truncation_class() {
        // 8-byte length varint lead with a missing tail.
        assert_eq!(p("c0 00000001 00 00 00 c0"), OurClass::Truncation);
    }

    #[test]
    fn empty_packet_is_truncation_class() {
        assert_eq!(p(""), OurClass::Truncation);
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
        let committed = std::fs::read_to_string(dir().join("quic_initial.ir.json")).unwrap();
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

    /// `gen lua` refuses this description by design: QUIC varint tails
    /// are up to 56 bits and their composed values up to 62, past Lua
    /// 5.2's bit32/53-bit-mantissa number model. The committed
    /// LUA-UNSUPPORTED.txt marker is equality-guarded by
    /// `committed_gen_artifacts_current`; this pins the refusal itself.
    #[test]
    fn lua_backend_refuses_wide_varint_fields() {
        let err = pakeles::codegen::lua::generate_lua(&ir())
            .expect_err("gen lua must refuse >32-bit varint tail fields");
        assert!(
            err.to_string().contains("not supported by the Lua backend"),
            "unexpected refusal: {err}"
        );
    }
}

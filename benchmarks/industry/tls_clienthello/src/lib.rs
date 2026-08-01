//! rustls differential oracle: our parse of the `tls_clienthello`
//! example, projected to (verdict-class, SNI), vs goldens minted by the
//! pinned rustls (factory Cargo.lock) public `Acceptor` API via
//! `oracle/tls_clienthello/factory/`.
//!
//! rustls's three-way surface maps onto ours through the design doc's
//! compatibility matrix (2026-07-29-tls-clienthello-design.md):
//!   accept          <-> our Accept (+ SNI string equality)
//!   incomplete      <-> our truncation-class reject ("out of bounds")
//!   InvalidMessage  <-> our structural rejects (region classes +
//!                       authored rejects)
//!   PeerMisbehaved  <-> our structural rejects (SNI-content rules,
//!                       trailing record fragments)
//!   PeerIncompatible <-> our Accept — the POLICY laxness: rustls
//!                       decoded the ClientHello fine and then rejected
//!                       it post-parse (missing signature_algorithms
//!                       etc.); a parse-layer model accepts. The SNI is
//!                       unobservable on that rustls path, so it is not
//!                       compared there.

use pakeles::ir::pb;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OurClass {
    Accept {
        sni: Option<String>,
    },
    /// Buffer-truncation reject ("out of bounds") — rustls: incomplete.
    Truncation,
    /// Structural reject: region classes + authored rejects.
    Structural {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub hex: String,
    pub verdict: String, // "accept" | "incomplete" | "reject"
    #[serde(default)]
    pub err: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub cipher_suites: Option<Vec<u16>>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub rustls_version: String,
    pub entries: Vec<GoldenEntry>,
}

/// Project our `tls_clienthello` parse to the diffable class.
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<OurClass> {
    let res = pakeles::interp::run(ir, packet)?;
    match res.outcome {
        pakeles::interp::Outcome::Accept => {
            let sni = res
                .headers
                .iter()
                .find(|h| h.instance == "host")
                .and_then(|h| {
                    h.fields
                        .iter()
                        .find(|f| f.name == "name")
                        .map(|f| match &f.value {
                            pakeles::interp::FieldValue::Bits(b) => {
                                String::from_utf8_lossy(b).into_owned()
                            }
                            pakeles::interp::FieldValue::Uint(u) => u.to_string(),
                        })
                });
            Ok(OurClass::Accept { sni })
        }
        pakeles::interp::Outcome::Reject { reason } if reason == "out of bounds" => {
            Ok(OurClass::Truncation)
        }
        pakeles::interp::Outcome::Reject { reason } => Ok(OurClass::Structural { reason }),
    }
}

/// One golden entry vs our projection: `None` = compatible, `Some` =
/// the mismatch description. Implements the design doc's matrix.
fn check(ours: &OurClass, golden: &GoldenEntry) -> Option<String> {
    let err_class = golden
        .err
        .as_deref()
        .map(|e| e.split('(').next().unwrap_or(e).trim().to_string())
        .unwrap_or_default();
    match (ours, golden.verdict.as_str()) {
        (OurClass::Accept { sni }, "accept") => {
            if *sni != golden.sni {
                Some(format!("sni: ours={sni:?} rustls={:?}", golden.sni))
            } else {
                None
            }
        }
        // Policy laxness: rustls decoded fine, rejected post-parse.
        (OurClass::Accept { .. }, "reject") if err_class.starts_with("PeerIncompatible") => None,
        (OurClass::Truncation, "incomplete") => None,
        (OurClass::Structural { .. }, "reject")
            if err_class.starts_with("InvalidMessage")
                || err_class.starts_with("PeerMisbehaved") =>
        {
            None
        }
        // read_tls-level framing errors are InvalidMessage-class too
        // (the factory prefixes them "read_tls:"), and a well-formed
        // record of the WRONG content type surfaces as
        // InappropriateMessage — also structural on our side.
        (OurClass::Structural { .. }, "reject")
            if err_class.starts_with("read_tls")
                || err_class.starts_with("InappropriateMessage") =>
        {
            None
        }
        _ => Some(format!(
            "class: ours={ours:?} rustls={} err={:?}",
            golden.verdict, golden.err
        )),
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
        "/tls_clienthello.ir.json"
    )))
    .expect("committed tls_clienthello IR must parse")
}

/// Find the committed rustls-minted golden (`clienthello.rustls-*.golden.json`).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with("clienthello.rustls-") && n.ends_with(".golden.json")
            })
        })
}

pub fn diff_goldens(
    ir: &pb::Ir,
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
        if let Some(m) = check(&ours, e) {
            report.mismatches.push(format!("vector {i}: {m}"));
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
            "no --goldens given and no committed clienthello.rustls-*.golden.json found under tls_clienthello/conformance/",
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
    /// committed rustls-minted golden over the whole corpus. A failure
    /// is a real disagreement — investigate against rustls; never edit
    /// the golden.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        assert!(
            g.rustls_version.starts_with("0.23"),
            "golden minted at rustls {} — the agreement claim pins the 0.23 line",
            g.rustls_version
        );
        assert!(
            g.entries.len() >= 28,
            "corpus shrank: {} entries",
            g.entries.len()
        );
        let report = diff_goldens(&ir(), &g).unwrap();
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with rustls:\n{}",
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

    // Byte-identical twins of factory corpus.txt lines (generated by
    // mk_corpus.py; rustls verdicts in the committed golden).
    const MINIMAL_SNI: &str = "160301003e0100003a03031111111111111111111111111111111111111111111111111111111111111111000002c02f0100000f0000000b0009000006612e74657374";
    const GREASE_SNI: &str = "16030100500100004c030311111111111111111111111111111111111111111111111111111111111111110000040a0ac02f0100001f1a1a00000000000b0009000006612e74657374000d00080006040308040401";
    const NO_EXTENSIONS: &str = "160301002d0100002903031111111111111111111111111111111111111111111111111111111111111111000002c02f0100";
    const DUP_SNI: &str = "16030100590100005503031111111111111111111111111111111111111111111111111111111111111111000002c02f0100002a0000000b0009000006612e746573740000000b0009000006622e74657374000d00080006040308040401";

    #[test]
    fn minimal_ch_accepts_with_sni() {
        assert_eq!(
            p(MINIMAL_SNI),
            OurClass::Accept {
                sni: Some("a.test".into())
            }
        );
    }

    #[test]
    fn grease_cipher_and_extension_ignored() {
        assert_eq!(
            p(GREASE_SNI),
            OurClass::Accept {
                sni: Some("a.test".into())
            }
        );
    }

    #[test]
    fn extensionless_legacy_ch_accepts_without_sni() {
        // rustls: PeerIncompatible(SignatureAlgorithmsExtensionRequired)
        // — the policy-laxness cell of the matrix.
        assert_eq!(p(NO_EXTENSIONS), OurClass::Accept { sni: None });
    }

    #[test]
    fn duplicate_sni_is_structural() {
        assert_eq!(
            p(DUP_SNI),
            OurClass::Structural {
                reason: "duplicate sni".into()
            }
        );
    }

    #[test]
    fn truncated_ch_is_truncation_class() {
        // First 40 bytes of MINIMAL_SNI: rustls incomplete.
        let hex: String = MINIMAL_SNI
            .replace([' ', '\n'], "")
            .chars()
            .take(80)
            .collect();
        assert_eq!(p(&hex), OurClass::Truncation);
    }

    #[test]
    fn record_length_lie_is_truncation_class() {
        // Record claims 2 more bytes than sent: rustls waits (incomplete);
        // our record region reaches past the buffer and a read dies at
        // the buffer end.
        let lie = format!("1603010040{}", &MINIMAL_SNI.replace([' ', '\n'], "")[10..]);
        assert_eq!(p(&lie), OurClass::Truncation);
    }

    #[test]
    fn trailing_byte_in_record_is_structural() {
        // Record len +1 with a stray byte after the handshake: rustls
        // PeerMisbehaved(KeyEpochWithPendingFragment); our record-region
        // exact pop.
        let t = format!(
            "160301003f{}ff",
            &MINIMAL_SNI.replace([' ', '\n'], "")[10..]
        );
        assert_eq!(
            p(&t),
            OurClass::Structural {
                reason: "region not exhausted".into()
            }
        );
    }

    #[test]
    fn garbage_is_structural() {
        assert_eq!(
            p("deadbeefdeadbeef"),
            OurClass::Structural {
                reason: "not a handshake record".into()
            }
        );
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
        let committed = std::fs::read_to_string(dir().join("tls_clienthello.ir.json")).unwrap();
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
        pakeles_testkit::lua_backend_conformance(&ir(), &suite, 10);
    }
}

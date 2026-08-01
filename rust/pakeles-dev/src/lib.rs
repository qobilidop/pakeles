//! Shared plumbing for the repo maintenance bins: the gallery table
//! (which example lives where) and the vector-suite writer.

use std::path::{Path, PathBuf};

/// Repo root, derived from this crate's manifest dir — the bins work
/// from any CWD.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// The real-world gallery examples. The dev tools address them by
/// path (keep in step with the workspace members and
/// scripts/gen-examples.sh) so that they — like the CLI — carry no
/// dependency on the example crates.
pub const REAL_WORLD: [&str; 6] = [
    "linux_flow_dissector",
    "dpdk_ptype",
    "katran_parser",
    "sai_parser",
    "tls_clienthello",
    "quic_initial",
];

/// The academic gallery examples: descriptions reproduced from
/// published evaluations (see examples/academic/README.md for the
/// naming and licensing rules). Same keep-in-step rule as REAL_WORLD.
pub const ACADEMIC: [&str; 8] = [
    "gibb_simple",
    "gibb_enterprise",
    "gibb_datacenter",
    "gibb_edge",
    "gibb_service_provider",
    "gibb_big_union",
    "kangaroo_parse_tree",
    "p4lang_switch_parser",
];

/// Every gallery example and its directory.
pub fn gallery() -> Vec<(&'static str, PathBuf)> {
    let root = repo_root();
    pakeles::examples::SYNTHETIC
        .iter()
        .map(|n| (*n, root.join("examples/synthetic").join(n)))
        .chain(
            REAL_WORLD
                .iter()
                .map(|n| (*n, root.join("examples/real_world").join(n))),
        )
        .chain(
            ACADEMIC
                .iter()
                .map(|n| (*n, root.join("examples/academic").join(n))),
        )
        .collect()
}

/// Generate an example's conformance suite from its committed IR and
/// write `conformance/vectors.{json,pcap}`. This is the ONLY gallery
/// artifact CI regenerates before testing: the suites are gitignored
/// (they churn on every IR/testgen change), so without this step every
/// backend-conformance test would skip on a fresh checkout. Everything
/// under `gen/` stays committed and untouched — regenerating it here
/// would make the equality guards compare fresh against fresh.
#[cfg(feature = "symex")]
pub fn write_vector_suite(name: &str, dir: &Path) -> anyhow::Result<()> {
    let conformance = dir.join("conformance");
    std::fs::create_dir_all(&conformance)?;
    let ir = pakeles::ir::load(&dir.join(format!("{name}.ir.json")))?;
    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        conformance.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&conformance.join("vectors.pcap"), &packets)?;
    Ok(())
}

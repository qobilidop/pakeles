//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

use std::path::PathBuf;

/// Repo root, derived from this crate's manifest dir — the bin works
/// from any CWD.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Every gallery example and its directory: synthetic from the core
/// crate's list, real-world from each example crate (the directory a
/// crate reports for itself is the single source of truth).
fn gallery() -> Vec<(&'static str, PathBuf)> {
    let root = repo_root();
    pakeles::examples::SYNTHETIC
        .iter()
        .map(|n| (*n, root.join("examples/synthetic").join(n)))
        .chain([
            (
                "linux_flow_dissector",
                pakeles_example_linux_flow_dissector::dir().to_path_buf(),
            ),
            (
                "dpdk_ptype",
                pakeles_example_dpdk_ptype::dir().to_path_buf(),
            ),
            (
                "katran_flow",
                pakeles_example_katran_flow::dir().to_path_buf(),
            ),
            (
                "sai_parser",
                pakeles_example_sai_parser::dir().to_path_buf(),
            ),
            (
                "tls_clienthello",
                pakeles_example_tls_clienthello::dir().to_path_buf(),
            ),
        ])
        .collect()
}

fn regenerate(name: &str, dir: &std::path::Path) -> anyhow::Result<()> {
    let gen = dir.join("gen");
    let conformance = dir.join("conformance");
    std::fs::create_dir_all(&gen)?;
    std::fs::create_dir_all(&conformance)?;
    let ir = pakeles::ir::from_json(&std::fs::read_to_string(
        dir.join(format!("{name}.ir.json")),
    )?)?;
    std::fs::copy(
        repo_root().join(format!("python/src/pakeles/examples/{name}.py")),
        dir.join(format!("{name}.py")),
    )?;
    std::fs::write(
        gen.join("dissector.lua"),
        pakeles::codegen::lua::generate_lua(&ir)?,
    )?;
    std::fs::write(gen.join("doc.md"), pakeles::docgen::generate_markdown(&ir)?)?;
    std::fs::write(gen.join("graph.dot"), pakeles::viz::to_dot(&ir))?;
    let c = pakeles::codegen::c::generate_c(&ir)?;
    std::fs::write(gen.join("parser.h"), c.header)?;
    std::fs::write(gen.join("parser.c"), c.source)?;
    std::fs::write(
        gen.join("parser.bpf.c"),
        pakeles::codegen::c::generate_bpf(&ir)?,
    )?;
    // gen p4 refuses sized-region IR by design (a P4-16 parser cannot
    // parse inside a length-bounded window) — commit the refusal as a
    // marker artifact instead of a parser.p4. Keep the marker format in
    // step with the guard in pakeles-testkit.
    match pakeles::codegen::p4::generate_p4(&ir) {
        Ok(p4) => std::fs::write(gen.join("parser.p4"), p4)?,
        Err(e) if e.to_string().contains("P4-16 parser expressiveness") => {
            std::fs::write(
                gen.join("P4-UNSUPPORTED.txt"),
                format!("gen p4: {e}\n(see docs/superpowers/specs/2026-07-29-sized-region-tlv-ir-design.md)\n"),
            )?;
        }
        Err(e) => return Err(e),
    }
    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        conformance.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&conformance.join("vectors.pcap"), &packets)?;
    // Synthetic examples are embedded by the core crate from in-crate
    // mirrors (self-contained packaging); keep the mirror current.
    if pakeles::examples::SYNTHETIC.contains(&name) {
        std::fs::copy(
            dir.join(format!("{name}.ir.json")),
            repo_root().join(format!("rust/pakeles/src/examples/{name}.ir.json")),
        )?;
    }
    let _ = std::process::Command::new("dot")
        .arg("-Tsvg")
        .arg("-o")
        .arg(gen.join("graph.svg"))
        .arg(gen.join("graph.dot"))
        .status();
    println!("{} regenerated", dir.display());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let all = gallery();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names: Vec<&str> = if args.is_empty() {
        all.iter().map(|(n, _)| *n).collect()
    } else {
        for a in &args {
            anyhow::ensure!(all.iter().any(|(n, _)| n == a), "unknown example `{a}`");
        }
        args.iter().map(|s| s.as_str()).collect()
    };
    for name in names {
        let (_, dir) = all.iter().find(|(n, _)| *n == name).unwrap();
        regenerate(name, dir)?;
    }
    Ok(())
}

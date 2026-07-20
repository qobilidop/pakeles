//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

fn regenerate(name: &str) -> anyhow::Result<()> {
    let dir = std::path::Path::new("examples").join(name);
    let gen = dir.join("gen");
    let conformance = dir.join("conformance");
    std::fs::create_dir_all(&gen)?;
    std::fs::create_dir_all(&conformance)?;
    let ir = pakeles::ir::from_json(&std::fs::read_to_string(
        dir.join(format!("{name}.ir.json")),
    )?)?;
    std::fs::copy(
        format!("py/src/pakeles/examples/{name}.py"),
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
    std::fs::write(
        gen.join("parser.p4"),
        pakeles::codegen::p4::generate_p4(&ir)?,
    )?;
    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(
        conformance.join("vectors.json"),
        pakeles::testvec::suite_to_json(&suite)?,
    )?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&conformance.join("vectors.pcap"), &packets)?;
    let _ = std::process::Command::new("dot")
        .arg("-Tsvg")
        .arg("-o")
        .arg(gen.join("graph.svg"))
        .arg(gen.join("graph.dot"))
        .status();
    println!("examples/{name} regenerated");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    for name in ["eth_ipvx_l4", "linux_flow_dissector"] {
        regenerate(name)?;
    }
    Ok(())
}

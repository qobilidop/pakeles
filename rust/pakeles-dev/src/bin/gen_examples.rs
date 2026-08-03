//! Regenerates the examples/ gallery: every artifact one description
//! yields, committed for browsing and equality-guarded by tests.

use pakeles_dev::gallery;

fn regenerate(name: &str, dir: &std::path::Path) -> anyhow::Result<()> {
    let gen = dir.join("gen");
    std::fs::create_dir_all(&gen)?;
    let ir = pakeles::ir::load(&dir.join(format!("{name}.ir.json")))?;
    // gen lua refuses fields wider than 32 bits by design (Lua 5.2's
    // number model: bit32 semantics and a 53-bit double mantissa can't
    // carry 62-bit varint values faithfully) — commit the refusal as a
    // marker artifact, the gen p4 precedent. Keep the marker format in
    // step with the guard in pakeles-testkit.
    match pakeles::codegen::lua::generate_lua(&ir) {
        Ok(lua) => pakeles::fsutil::atomic_write(&gen.join("dissector.lua"), lua)?,
        Err(e) if e.to_string().contains("not supported by the Lua backend") => {
            pakeles::fsutil::atomic_write(
                &gen.join("LUA-UNSUPPORTED.txt"),
                format!("gen lua: {e}\n(see docs/designs/2026-07-31-quic-initial-design.md)\n"),
            )?;
        }
        Err(e) => return Err(e),
    }
    pakeles::fsutil::atomic_write(
        &gen.join("doc.md"),
        pakeles::docgen::generate_markdown(&ir)?,
    )?;
    pakeles::fsutil::atomic_write(&gen.join("graph.dot"), pakeles::viz::to_dot(&ir))?;
    let c = pakeles::codegen::c::generate_c(&ir)?;
    pakeles::fsutil::atomic_write(&gen.join("parser.h"), c.header)?;
    pakeles::fsutil::atomic_write(&gen.join("parser.c"), c.source)?;
    pakeles::fsutil::atomic_write(
        &gen.join("parser.bpf.c"),
        pakeles::codegen::c::generate_bpf(&ir)?,
    )?;
    // gen p4 refuses sized-region IR by design (a P4-16 parser cannot
    // parse inside a length-bounded window) — commit the refusal as a
    // marker artifact instead of a parser.p4. Keep the marker format in
    // step with the guard in pakeles-testkit.
    match pakeles::codegen::p4::generate_p4(&ir) {
        Ok(p4) => pakeles::fsutil::atomic_write(&gen.join("parser.p4"), p4)?,
        Err(e) if e.to_string().contains("P4-16 parser expressiveness") => {
            pakeles::fsutil::atomic_write(
                &gen.join("P4-UNSUPPORTED.txt"),
                format!("gen p4: {e}\n(see docs/superpowers/specs/2026-07-29-sized-region-tlv-ir-design.md)\n"),
            )?;
        }
        Err(e) => return Err(e),
    }
    pakeles_dev::write_vector_suite(name, dir)?;
    let dot = pakeles::process::run(
        std::process::Command::new("dot")
            .arg("-Tsvg")
            .arg(gen.join("graph.dot")),
        pakeles::process::ProcessLimits::default(),
    )?;
    anyhow::ensure!(
        dot.status.success(),
        "dot failed: {}",
        String::from_utf8_lossy(&dot.stderr)
    );
    anyhow::ensure!(!dot.stdout_truncated, "dot SVG output exceeded its limit");
    pakeles::fsutil::atomic_write(&gen.join("graph.svg"), dot.stdout)?;
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

//! Regenerates every gallery example's conformance suite
//! (`conformance/vectors.{json,pcap}`) from its committed IR — and
//! nothing else. CI runs this before `cargo test` so the
//! backend-conformance tests, which skip when a suite is absent,
//! always run against a fresh suite on a fresh checkout. The committed
//! `gen/` artifacts are deliberately not touched (their equality
//! guards must keep comparing committed against fresh).

fn main() -> anyhow::Result<()> {
    for (name, dir) in pakeles_dev::gallery() {
        pakeles_dev::write_vector_suite(name, &dir)?;
        println!("{name}: vectors regenerated");
    }
    Ok(())
}

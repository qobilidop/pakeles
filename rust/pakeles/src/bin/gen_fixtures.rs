//! Regenerates testdata/basic.pcap deterministically.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    std::fs::create_dir_all(&testdata)?;
    let out = testdata.join("basic.pcap");
    pakeles::pcapio::write_pcap(&out, &pakeles::fixtures::basic_pcap_packets())?;
    println!("wrote {}", out.display());
    Ok(())
}

//! Regenerates testdata/basic.pcap deterministically.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    let out = Path::new("testdata/basic.pcap");
    std::fs::create_dir_all("testdata")?;
    pakeles::pcapio::write_pcap(out, &pakeles::fixtures::basic_pcap_packets())?;
    println!("wrote {}", out.display());
    Ok(())
}

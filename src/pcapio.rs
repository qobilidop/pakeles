//! Minimal pcap io: classic-format writer for deterministic fixtures,
//! pcap-parser-backed reader (legacy + pcapng).

use anyhow::{bail, Result};
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use std::io::Write;
use std::path::Path;

/// Write a classic pcap (LINKTYPE_ETHERNET, snaplen 65535, zero
/// timestamps so output is byte-for-byte deterministic).
pub fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    f.write_all(&2u16.to_le_bytes())?; // version major
    f.write_all(&4u16.to_le_bytes())?; // version minor
    f.write_all(&0i32.to_le_bytes())?; // thiszone
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&1u32.to_le_bytes())?; // LINKTYPE_ETHERNET
    for p in packets {
        f.write_all(&0u32.to_le_bytes())?; // ts_sec
        f.write_all(&0u32.to_le_bytes())?; // ts_usec
        f.write_all(&(p.len() as u32).to_le_bytes())?; // incl_len
        f.write_all(&(p.len() as u32).to_le_bytes())?; // orig_len
        f.write_all(p)?;
    }
    Ok(())
}

pub fn read_packets(path: &Path) -> Result<Vec<Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = create_reader(65536, file)?;
    let mut out = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(b) => {
                        out.push(b.data[..b.caplen as usize].to_vec());
                    }
                    PcapBlockOwned::NG(pcap_parser::Block::EnhancedPacket(ref epb)) => {
                        out.push(epb.data[..epb.caplen as usize].to_vec());
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    bail!("pcap refill failed");
                }
            }
            Err(e) => bail!("pcap read error: {e:?}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn write_read_roundtrip() {
        let packets = fixtures::basic_pcap_packets();
        let path = std::env::temp_dir().join("pakeles_roundtrip.pcap");
        write_pcap(&path, &packets).unwrap();
        assert_eq!(read_packets(&path).unwrap(), packets);
    }

    #[test]
    fn reads_committed_fixture() {
        let packets = read_packets(Path::new("testdata/basic.pcap")).unwrap();
        assert_eq!(packets, fixtures::basic_pcap_packets());
        assert_eq!(packets[0].len(), 54);
    }
}

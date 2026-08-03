//! Minimal pcap io: classic-format writer for deterministic fixtures,
//! pcap-parser-backed reader (legacy + pcapng).

use anyhow::Result;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use std::io::Write;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct PcapLimits {
    pub max_packets: usize,
    pub max_packet_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for PcapLimits {
    fn default() -> Self {
        Self {
            max_packets: 1_000_000,
            max_packet_bytes: crate::testvec::DEFAULT_MAX_PACKET_BYTES,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

pub struct PacketReader {
    reader: Box<dyn pcap_parser::traits::PcapReaderIterator>,
    limits: PcapLimits,
    packets: usize,
    total_bytes: usize,
    done: bool,
}

impl Iterator for PacketReader {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let packet: Result<Option<Vec<u8>>> = match block {
                        PcapBlockOwned::Legacy(b) => {
                            packet_bytes(b.data, b.caplen as usize, self.limits.max_packet_bytes)
                                .map(Some)
                        }
                        PcapBlockOwned::NG(pcap_parser::Block::EnhancedPacket(ref epb)) => {
                            packet_bytes(
                                epb.data,
                                epb.caplen as usize,
                                self.limits.max_packet_bytes,
                            )
                            .map(Some)
                        }
                        _ => Ok(None),
                    };
                    self.reader.consume(offset);
                    let Some(packet) = (match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            self.done = true;
                            return Some(Err(error));
                        }
                    }) else {
                        continue;
                    };
                    self.packets = match self.packets.checked_add(1) {
                        Some(packets) => packets,
                        None => {
                            self.done = true;
                            return Some(Err(anyhow::anyhow!("pcap packet count overflow")));
                        }
                    };
                    self.total_bytes = match self.total_bytes.checked_add(packet.len()) {
                        Some(total) => total,
                        None => {
                            self.done = true;
                            return Some(Err(anyhow::anyhow!("pcap aggregate size overflow")));
                        }
                    };
                    if self.packets > self.limits.max_packets
                        || self.total_bytes > self.limits.max_total_bytes
                    {
                        self.done = true;
                        return Some(Err(anyhow::anyhow!(
                            "pcap resource limit exceeded (packets {}, packet bytes {}, total bytes {})",
                            self.packets,
                            packet.len(),
                            self.total_bytes
                        )));
                    }
                    return Some(Ok(packet));
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_)) => {
                    if self.reader.refill().is_err() {
                        self.done = true;
                        return Some(Err(anyhow::anyhow!("pcap refill failed")));
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(anyhow::anyhow!("pcap read error: {e:?}")));
                }
            }
        }
    }
}

fn packet_bytes(data: &[u8], caplen: usize, max_packet_bytes: usize) -> Result<Vec<u8>> {
    if caplen > max_packet_bytes {
        anyhow::bail!("pcap packet size {caplen} exceeds limit {max_packet_bytes}");
    }
    let packet = data
        .get(..caplen)
        .ok_or_else(|| anyhow::anyhow!("pcap packet caplen {caplen} exceeds captured data"))?;
    Ok(packet.to_vec())
}

pub fn packet_reader(path: &Path, limits: PcapLimits) -> Result<PacketReader> {
    let file = std::fs::File::open(path)?;
    let reader = create_reader(65536, file).map_err(|e| anyhow::anyhow!("pcap open: {e:?}"))?;
    Ok(PacketReader {
        reader,
        limits,
        packets: 0,
        total_bytes: 0,
        done: false,
    })
}

/// Write a classic pcap (LINKTYPE_ETHERNET, snaplen 65535, zero
/// timestamps so output is byte-for-byte deterministic).
pub fn write_pcap(path: &Path, packets: &[Vec<u8>]) -> Result<()> {
    for p in packets {
        if p.len() > 65_535 {
            anyhow::bail!("packet length {} exceeds pcap snaplen 65535", p.len());
        }
    }
    crate::fsutil::atomic_write_with(path, |f| {
        f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
        f.write_all(&2u16.to_le_bytes())?; // version major
        f.write_all(&4u16.to_le_bytes())?; // version minor
        f.write_all(&0i32.to_le_bytes())?; // thiszone
        f.write_all(&0u32.to_le_bytes())?; // sigfigs
        f.write_all(&65535u32.to_le_bytes())?; // snaplen
        f.write_all(&1u32.to_le_bytes())?; // LINKTYPE_ETHERNET
        for p in packets {
            let packet_len = u32::try_from(p.len()).expect("pcap packet length checked above");
            f.write_all(&0u32.to_le_bytes())?; // ts_sec
            f.write_all(&0u32.to_le_bytes())?; // ts_usec
            f.write_all(&packet_len.to_le_bytes())?; // incl_len
            f.write_all(&packet_len.to_le_bytes())?; // orig_len
            f.write_all(p)?;
        }
        Ok(())
    })
}

pub fn read_packets(path: &Path) -> Result<Vec<Vec<u8>>> {
    packet_reader(path, PcapLimits::default())?.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn write_read_roundtrip() {
        let packets = fixtures::basic_pcap_packets();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.pcap");
        write_pcap(&path, &packets).unwrap();
        assert_eq!(read_packets(&path).unwrap(), packets);
    }

    #[test]
    fn reads_committed_fixture() {
        let packets = read_packets(&crate::test_repo_path("testdata/basic.pcap")).unwrap();
        assert_eq!(packets, fixtures::basic_pcap_packets());
        assert_eq!(packets[0].len(), 54);
    }

    #[test]
    fn packet_reader_enforces_limits_before_returning_data() {
        let packets = fixtures::basic_pcap_packets();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limited_roundtrip.pcap");
        write_pcap(&path, &packets).unwrap();

        let limits = PcapLimits {
            max_packets: usize::MAX,
            max_packet_bytes: 1,
            max_total_bytes: usize::MAX,
        };
        let error = packet_reader(&path, limits)
            .unwrap()
            .next()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("exceeds limit 1"));
    }

    #[test]
    fn oversized_packet_does_not_replace_existing_capture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.pcap");
        std::fs::write(&path, b"existing").unwrap();
        let error = write_pcap(&path, &[vec![0; 65_536]]).unwrap_err();
        assert!(error.to_string().contains("exceeds pcap snaplen"));
        assert_eq!(std::fs::read(path).unwrap(), b"existing");
    }
}

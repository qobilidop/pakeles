//! Differential oracles: our interpreter vs `tshark -T json` (below)
//! and vs BMv2 `simple_switch` (`bmv2` submodule). The oracle is the
//! boss — a mismatch means our description (or our semantics) is wrong
//! until proven otherwise.

// The incumbent-specific oracles live with their examples (one crate
// per `examples/real_world/<X>/`); only the toolchain-generic oracles
// (tshark below, BMv2 here) are part of the core.
pub mod bmv2;

use crate::interp::{run, FieldValue, Outcome};
use crate::ir::pb;
use anyhow::{bail, Context, Result};
use std::path::Path;

/// The uniform result of diffing our parse against an incumbent-minted
/// golden file. Every example crate's `diff_goldens` returns this, so
/// the CLI prints one way and exits one way for every incumbent.
#[derive(Debug, Default)]
pub struct GoldenDiffReport {
    pub compared: usize,
    pub mismatches: Vec<String>,
}

impl std::fmt::Display for GoldenDiffReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} vectors compared, {} mismatches",
            self.compared,
            self.mismatches.len()
        )?;
        for m in &self.mismatches {
            writeln!(f, "  {m}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FieldDiff {
    pub packet: usize,
    pub tshark_key: String,
    pub ours: u64,
    pub theirs: Option<u64>,
    pub raw: String,
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub packets: usize,
    pub compared: usize,
    pub mismatches: Vec<FieldDiff>,
}

/// Parse tshark's string field rendering: `"0x0800"` (hex) or `"443"`
/// (decimal). Anything else (addresses, times) is not comparable.
pub fn normalize(raw: &str) -> Option<u64> {
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse().ok()
    }
}

/// Format-aware normalization: addresses become their big-endian
/// numeric value, everything else falls back to `normalize`.
pub fn normalize_typed(raw: &str, format: pb::DisplayFormat) -> Option<u64> {
    match format {
        pb::DisplayFormat::Ipv4 => {
            let octets: Vec<u64> = raw
                .split('.')
                .map(|p| p.parse().ok())
                .collect::<Option<_>>()?;
            if octets.len() != 4 || octets.iter().any(|o| *o > 255) {
                return None;
            }
            Some(octets.iter().fold(0, |acc, o| (acc << 8) | o))
        }
        pb::DisplayFormat::Ether => {
            let parts: Vec<u64> = raw
                .split(':')
                .map(|p| u64::from_str_radix(p, 16).ok())
                .collect::<Option<_>>()?;
            if parts.len() != 6 || parts.iter().any(|p| *p > 255) {
                return None;
            }
            Some(parts.iter().fold(0, |acc, p| (acc << 8) | p))
        }
        _ => normalize(raw),
    }
}

/// Find `key` in the layer object named by `key`'s prefix (before the
/// first '.'), searching nested objects; arrays take the first element.
pub fn lookup<'a>(layers: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    let layer_name = key.split('.').next()?;
    let layer = layers.get(layer_name)?;
    fn search<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(hit) = map.get(key) {
                    return match hit {
                        serde_json::Value::String(s) => Some(s),
                        serde_json::Value::Array(a) => a.first().and_then(|x| x.as_str()),
                        _ => None,
                    };
                }
                map.values().find_map(|child| search(child, key))
            }
            _ => None,
        }
    }
    search(layer, key)
}

fn tshark_json(pcap: &Path) -> Result<Vec<serde_json::Value>> {
    let limits = crate::process::ProcessLimits {
        timeout: std::time::Duration::from_secs(300),
        max_output_bytes_per_stream: 512 * 1024 * 1024,
    };
    let out = crate::process::run(
        std::process::Command::new("tshark")
            .args(["-r"])
            .arg(pcap)
            .args(["-T", "json"]),
        limits,
    )
    .context("failed to run tshark — is it installed?")?;
    if !out.status.success() {
        bail!("tshark failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    if out.stdout_truncated {
        bail!("tshark JSON exceeded the 512 MiB output limit");
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// Diff every Accept-outcome packet's annotated fields against tshark.
/// Reject-outcome packets are skipped (tshark still dissects malformed
/// input; matching that asymmetry is diagnose mode's job, slice 3).
pub fn diff_pcap(ir: &crate::ir::ValidatedIr, pcap: &Path) -> Result<DiffReport> {
    let packets = crate::pcapio::read_packets(pcap)?;
    let dissected = tshark_json(pcap)?;
    if dissected.len() != packets.len() {
        bail!(
            "tshark saw {} packets, pcap reader saw {}",
            dissected.len(),
            packets.len()
        );
    }

    let mut report = DiffReport {
        packets: packets.len(),
        ..Default::default()
    };

    for (idx, (packet, dis)) in packets.iter().zip(&dissected).enumerate() {
        let result = run(ir, packet)?;
        if result.outcome != Outcome::Accept {
            continue;
        }
        let layers = &dis["_source"]["layers"];
        for header in &result.headers {
            let ht = ir
                .parser
                .as_ref()
                .and_then(|p| p.header_types.iter().find(|h| h.name == header.header_type));
            let Some(ht) = ht else { continue };
            for field in &header.fields {
                let Some(ir_field) = ht.fields.iter().find(|f| f.name == field.name) else {
                    continue;
                };
                let Some(key) = ir_field.annotations.get("tshark.key") else {
                    continue;
                };
                let format = ir_field
                    .display
                    .as_ref()
                    .and_then(|d| pb::DisplayFormat::try_from(d.format).ok())
                    .unwrap_or(pb::DisplayFormat::Unspecified);
                let FieldValue::Uint(ours) = field.value else {
                    continue;
                };
                report.compared += 1;
                let raw = lookup(layers, key);
                let theirs = raw.and_then(|r| normalize_typed(r, format));
                if theirs != Some(ours) {
                    report.mismatches.push(FieldDiff {
                        packet: idx,
                        tshark_key: key.clone(),
                        ours,
                        theirs,
                        raw: raw.unwrap_or("<absent>").to_string(),
                    });
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hex_and_decimal() {
        assert_eq!(normalize("0x0800"), Some(0x0800));
        assert_eq!(normalize("443"), Some(443));
        assert_eq!(normalize("10.0.0.1"), None);
        assert_eq!(normalize("aa:bb"), None);
    }

    #[test]
    fn normalizes_addresses_by_format() {
        use crate::ir::pb::DisplayFormat as F;
        assert_eq!(normalize_typed("10.0.0.1", F::Ipv4), Some(0x0A000001));
        assert_eq!(normalize_typed("256.0.0.1", F::Ipv4), None);
        assert_eq!(
            normalize_typed("aa:bb:cc:dd:ee:ff", F::Ether),
            Some(0xAABBCCDDEEFF)
        );
        assert_eq!(normalize_typed("aa:bb", F::Ether), None);
        assert_eq!(normalize_typed("443", F::Dec), Some(443));
    }

    #[test]
    fn lookup_finds_nested_and_array_values() {
        let layers = serde_json::json!({
            "eth": { "eth.type": "0x0800", "eth.dst_tree": { "eth.addr": "aa:bb" } },
            "ip": { "ip.flags_tree": { "ip.flags.df": "1" }, "ip.proto": ["6", "7"] }
        });
        assert_eq!(lookup(&layers, "eth.type"), Some("0x0800"));
        assert_eq!(lookup(&layers, "eth.addr"), Some("aa:bb"));
        assert_eq!(lookup(&layers, "ip.proto"), Some("6"));
        assert_eq!(lookup(&layers, "ip.flags.df"), Some("1"));
        assert_eq!(lookup(&layers, "tcp.sport"), None);
    }

    #[test]
    fn fixture_pcap_diffs_green() {
        if !crate::process::is_available("tshark", &["--version"]) {
            eprintln!("skipping: tshark not available");
            return;
        }
        let report = diff_pcap(
            &crate::fixtures::eth_ipvx_l4(),
            &crate::test_repo_path("testdata/basic.pcap"),
        )
        .unwrap();
        assert_eq!(report.packets, 4);
        assert_eq!(
            report.compared, 36,
            "12 annotated fields x 3 accepted packets (tcp, tcp+options, udp)"
        );
        assert!(
            report.mismatches.is_empty(),
            "oracle mismatches: {:#?}",
            report.mismatches
        );
    }
}

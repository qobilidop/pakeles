//! Test-vector artifacts: generated pb types plus the Rust-native
//! `Bits` input type and BitString canonicalization.

// Vendored generated code — see the note in src/ir/mod.rs.
#[allow(clippy::all)]
pub mod pb {
    include!("gen/pakeles.testvec.v1alpha1.rs");
    include!("gen/pakeles.testvec.v1alpha1.serde.rs");
}

use anyhow::Result;
use std::ops::Deref;

pub const DEFAULT_MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct TestSuiteLimits {
    pub max_vectors: usize,
    pub max_packet_bytes: usize,
    pub max_total_packet_bytes: usize,
}

impl Default for TestSuiteLimits {
    fn default() -> Self {
        Self {
            // An order of magnitude above the gallery's largest suite
            // (`p4lang_switch_parser`, 93,727 vectors) — see
            // `symex::engine::SymexLimits` for why the headroom matters.
            max_vectors: 1_000_000,
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
            max_total_packet_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedTestSuite(pb::TestSuite);

impl ValidatedTestSuite {
    pub fn new(suite: pb::TestSuite) -> Result<Self> {
        Self::new_with_limits(suite, &TestSuiteLimits::default())
    }

    pub fn new_with_limits(suite: pb::TestSuite, limits: &TestSuiteLimits) -> Result<Self> {
        validate_suite(&suite, limits)?;
        Ok(Self(suite))
    }

    pub fn as_pb(&self) -> &pb::TestSuite {
        &self.0
    }

    pub fn into_inner(self) -> pb::TestSuite {
        self.0
    }
}

impl Deref for ValidatedTestSuite {
    type Target = pb::TestSuite;

    fn deref(&self) -> &Self::Target {
        self.as_pb()
    }
}

impl AsRef<pb::TestSuite> for ValidatedTestSuite {
    fn as_ref(&self) -> &pb::TestSuite {
        self.as_pb()
    }
}

/// Rust-native bit string used throughout the toolchain internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bits {
    pub bytes: Vec<u8>,
    pub bit_len: usize,
}

impl Bits {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            bit_len: bytes.len() * 8,
        }
    }

    /// Canonicalize per the BitString contract: pad short data with
    /// zeros, truncate long data, zero unused trailing bits. Returns
    /// warnings describing every correction made (empty = canonical).
    pub fn from_pb(bs: &pb::BitString) -> Result<(Self, Vec<String>)> {
        Self::from_pb_with_limit(bs, DEFAULT_MAX_PACKET_BYTES)
    }

    pub fn from_pb_with_limit(bs: &pb::BitString, max_bytes: usize) -> Result<(Self, Vec<String>)> {
        let mut warnings = Vec::new();
        let bit_len = usize::try_from(bs.bit_len)
            .map_err(|_| anyhow::anyhow!("bit_len {} does not fit this platform", bs.bit_len))?;
        let want_bytes = bit_len.div_ceil(8);
        if want_bytes > max_bytes {
            anyhow::bail!("bit string needs {want_bytes} bytes, exceeding limit {max_bytes}");
        }
        if bs.data_hex.len() > max_bytes.saturating_mul(2) {
            anyhow::bail!(
                "bit string hex has {} characters, exceeding limit {}",
                bs.data_hex.len(),
                max_bytes.saturating_mul(2)
            );
        }
        let mut bytes = match hex_decode(&bs.data_hex) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("bad hex ({e}); treating as empty"));
                Vec::new()
            }
        };
        match bytes.len().cmp(&want_bytes) {
            std::cmp::Ordering::Less => {
                warnings.push(format!(
                    "data shorter than bit_len ({} < {} bytes); zero-padded",
                    bytes.len(),
                    want_bytes
                ));
                bytes.resize(want_bytes, 0);
            }
            std::cmp::Ordering::Greater => {
                warnings.push(format!(
                    "data longer than bit_len ({} > {} bytes); truncated",
                    bytes.len(),
                    want_bytes
                ));
                bytes.truncate(want_bytes);
            }
            std::cmp::Ordering::Equal => {}
        }
        let pad_bits = want_bytes * 8 - bit_len;
        if pad_bits > 0 {
            let mask = !((1u16 << pad_bits) - 1) as u8;
            let last = bytes.len() - 1;
            if bytes[last] & !mask != 0 {
                warnings.push("nonzero pad bits; zeroed".into());
                bytes[last] &= mask;
            }
        }
        Ok((Self { bytes, bit_len }, warnings))
    }

    /// Emit canonical wire form (writers must only ever produce this).
    pub fn to_pb(&self) -> pb::BitString {
        debug_assert_eq!(self.bytes.len(), self.bit_len.div_ceil(8));
        pb::BitString {
            data_hex: hex_encode(&self.bytes),
            bit_len: self.bit_len as u64,
        }
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("odd hex length {}", s.len());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| anyhow::anyhow!("hex at {}: {e}", 2 * i))
        })
        .collect()
}

/// Byte-aligned vectors as raw packets (pcap is byte-granular), in
/// suite order, with their vector indices. Callers must report the
/// skipped count — no silent drops.
pub fn suite_to_packets(s: &ValidatedTestSuite) -> Result<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut packets = Vec::new();
    let mut indices = Vec::new();
    for (i, v) in s.vectors.iter().enumerate() {
        if let Some(bs) = &v.packet {
            if bs.bit_len.is_multiple_of(8) {
                let (bits, _) = Bits::from_pb(bs)?;
                packets.push(bits.bytes);
                indices.push(i);
            }
        }
    }
    Ok((packets, indices))
}

pub fn suite_to_json(s: &pb::TestSuite) -> Result<String> {
    Ok(serde_json::to_string_pretty(s)?)
}

pub fn suite_from_json(s: &str) -> Result<ValidatedTestSuite> {
    ValidatedTestSuite::new(serde_json::from_str(s)?)
}

fn validate_suite(suite: &pb::TestSuite, limits: &TestSuiteLimits) -> Result<()> {
    if suite.parser_name.is_empty() {
        anyhow::bail!("test suite has empty parser_name");
    }
    if suite.ir_version != crate::ir::IR_VERSION {
        anyhow::bail!(
            "test suite ir_version `{}` does not match `{}`",
            suite.ir_version,
            crate::ir::IR_VERSION
        );
    }
    if suite.vectors.len() > limits.max_vectors {
        anyhow::bail!(
            "test suite has {} vectors, exceeding limit {}",
            suite.vectors.len(),
            limits.max_vectors
        );
    }
    let mut ids = std::collections::HashSet::new();
    let mut total_bytes = 0usize;
    for (index, vector) in suite.vectors.iter().enumerate() {
        if vector.id.is_empty() {
            anyhow::bail!("test vector {index} has empty id");
        }
        if !ids.insert(vector.id.as_str()) {
            anyhow::bail!("duplicate test vector id `{}`", vector.id);
        }
        let category = pb::Category::try_from(vector.category).map_err(|_| {
            anyhow::anyhow!(
                "vector `{}` has unknown category {}",
                vector.id,
                vector.category
            )
        })?;
        if category == pb::Category::Unspecified {
            anyhow::bail!("vector `{}` has unspecified category", vector.id);
        }
        let packet = vector
            .packet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vector `{}` has no packet", vector.id))?;
        let (bits, warnings) = Bits::from_pb_with_limit(packet, limits.max_packet_bytes)?;
        if !warnings.is_empty() {
            anyhow::bail!(
                "vector `{}` packet is not canonical: {}",
                vector.id,
                warnings.join("; ")
            );
        }
        total_bytes = total_bytes
            .checked_add(bits.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("test suite packet size overflow"))?;
        if total_bytes > limits.max_total_packet_bytes {
            anyhow::bail!(
                "test suite packets total {total_bytes} bytes, exceeding limit {}",
                limits.max_total_packet_bytes
            );
        }
        let outcome = vector
            .expected
            .as_ref()
            .and_then(|expected| expected.outcome.as_ref())
            .ok_or_else(|| anyhow::anyhow!("vector `{}` has no expected outcome", vector.id))?;
        let category_matches = matches!(
            (category, outcome),
            (pb::Category::Accept, pb::expected::Outcome::Accept(_))
                | (
                    pb::Category::Reject | pb::Category::Truncation,
                    pb::expected::Outcome::Reject(_)
                )
        );
        if !category_matches {
            anyhow::bail!(
                "vector `{}` category does not match expected outcome",
                vector.id
            );
        }
        if let pb::expected::Outcome::Accept(accepted) = outcome {
            for header in &accepted.headers {
                for field in &header.fields {
                    if let Some(pb::expected_field::Value::Bits(value)) = &field.value {
                        let (_, warnings) =
                            Bits::from_pb_with_limit(value, limits.max_packet_bytes)?;
                        if !warnings.is_empty() {
                            anyhow::bail!(
                                "vector `{}` expected field `{}.{}` is not canonical: {}",
                                vector.id,
                                header.instance,
                                field.name,
                                warnings.join("; ")
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Load a committed conformance suite, or `None` when its `vectors.json` is
/// absent. The suite is a generated artifact that is gitignored during fast
/// iteration (it churns on every IR/testgen change), so differential and
/// conformance tests SKIP when it hasn't been regenerated. Regenerate with
/// `./dev.sh scripts/gen-examples.sh`; the suite is re-committed once the
/// codebase stabilizes.
#[cfg(test)]
pub(crate) fn committed_suite_or_skip(name: &str) -> Option<ValidatedTestSuite> {
    // Synthetic gallery only: the real-world examples' suites are
    // loaded by their own crates via pakeles-testkit.
    let path = crate::test_repo_path(&format!(
        "examples/synthetic/{name}/conformance/vectors.json"
    ));
    if !path.exists() {
        eprintln!(
            "skipping: {} not generated (run ./dev.sh scripts/gen-examples.sh)",
            path.display()
        );
        return None;
    }
    Some(suite_from_json(&std::fs::read_to_string(&path).unwrap()).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrips_without_warnings() {
        let bits = Bits {
            bytes: vec![0xAB, 0xC0],
            bit_len: 12,
        };
        let pb = bits.to_pb();
        assert_eq!(pb.data_hex, "abc0");
        let (back, warnings) = Bits::from_pb(&pb).unwrap();
        assert_eq!(back, bits);
        assert!(warnings.is_empty());
    }

    #[test]
    fn short_data_zero_padded_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "ab".into(),
            bit_len: 24,
        })
        .unwrap();
        assert_eq!(bits.bytes, vec![0xAB, 0, 0]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("zero-padded"));
    }

    #[test]
    fn long_data_truncated_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "aabbcc".into(),
            bit_len: 8,
        })
        .unwrap();
        assert_eq!(bits.bytes, vec![0xAA]);
        assert!(w[0].contains("truncated"));
    }

    #[test]
    fn nonzero_pad_bits_zeroed_with_warning() {
        let (bits, w) = Bits::from_pb(&pb::BitString {
            data_hex: "ff".into(),
            bit_len: 4,
        })
        .unwrap();
        assert_eq!(bits.bytes, vec![0xF0]);
        assert!(w[0].contains("pad bits"));
    }

    #[test]
    fn suite_to_packets_selects_byte_aligned() {
        let Some(suite) = committed_suite_or_skip("eth_ipvx_l4") else {
            return;
        };
        let (packets, indices) = suite_to_packets(&suite).unwrap();
        assert_eq!(packets.len(), indices.len());
        assert!(!packets.is_empty());
        for (p, i) in packets.iter().zip(&indices) {
            let bs = suite.vectors[*i].packet.as_ref().unwrap();
            assert_eq!(bs.bit_len as usize, p.len() * 8);
        }
        // Every accept vector is byte-aligned and therefore exported.
        let accepts = suite
            .vectors
            .iter()
            .enumerate()
            .filter(|(_, v)| v.category == pb::Category::Accept as i32)
            .count();
        assert!(indices.len() >= accepts);
    }

    #[test]
    fn committed_vectors_pcap_current() {
        let pcap_path =
            crate::test_repo_path("examples/synthetic/eth_ipvx_l4/conformance/vectors.pcap");
        let Some(suite) = committed_suite_or_skip("eth_ipvx_l4") else {
            return;
        };
        if !pcap_path.exists() {
            eprintln!("skipping: {} not generated", pcap_path.display());
            return;
        }
        let (packets, _) = suite_to_packets(&suite).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("gallery_check.pcap");
        crate::pcapio::write_pcap(&tmp, &packets).unwrap();
        let fresh = std::fs::read(&tmp).unwrap();
        let committed = std::fs::read(&pcap_path).unwrap();
        assert_eq!(
            fresh, committed,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn suite_json_roundtrip() {
        let suite = pb::TestSuite {
            parser_name: "p".into(),
            ir_version: crate::ir::IR_VERSION.into(),
            vectors: vec![pb::TestVector {
                id: "s/arm0".into(),
                category: pb::Category::Accept as i32,
                packet: Some(Bits::from_bytes(&[1, 2]).to_pb()),
                expected: Some(pb::Expected {
                    outcome: Some(pb::expected::Outcome::Accept(pb::Accepted::default())),
                }),
            }],
        };
        let parsed = suite_from_json(&suite_to_json(&suite).unwrap()).unwrap();
        assert_eq!(parsed.as_pb(), &suite);
    }

    #[test]
    fn oversized_bit_strings_and_invalid_suites_are_rejected() {
        let err = Bits::from_pb_with_limit(
            &pb::BitString {
                data_hex: String::new(),
                bit_len: 17,
            },
            2,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeding limit"));

        let suite = pb::TestSuite {
            parser_name: "p".into(),
            ir_version: crate::ir::IR_VERSION.into(),
            vectors: vec![pb::TestVector {
                id: "bad".into(),
                category: pb::Category::Accept as i32,
                packet: Some(Bits::from_bytes(&[]).to_pb()),
                expected: Some(pb::Expected {
                    outcome: Some(pb::expected::Outcome::Reject(pb::Rejected {
                        reason: "no".into(),
                    })),
                }),
            }],
        };
        let err = ValidatedTestSuite::new(suite).unwrap_err();
        assert!(err.to_string().contains("category does not match"));
    }
}

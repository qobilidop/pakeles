//! The normative IR: generated protobuf types plus serialization helpers.
//! This module depends on no other module in the crate.

// Vendored prost/pbjson output (src/gen/, committed like python/'s
// _pb modules): consumers never need protoc. Regenerate after a
// proto/ change with `cargo run --bin pakeles-pbgen`; guarded by
// pakeles-pbgen's committed_pb_current test.
#[allow(clippy::all)]
pub mod pb {
    include!("../gen/pakeles.ir.v1alpha1.rs");
    include!("../gen/pakeles.ir.v1alpha1.serde.rs");
}

pub mod validate;

// 0.2.0: bit-uniform lengths (`bit_len` widths, region push lengths,
// `remaining()` all in BITS). Pre-1.0: `validate()` requires an exact
// match — a 0.1.0 byte-denominated IR must fail loudly, never be
// silently re-read with its lengths ×8 off.
pub const IR_VERSION: &str = "0.2.0";

use anyhow::Result;
use prost::Message;
use std::ops::Deref;

/// An IR whose complete set of semantic invariants has been checked.
///
/// Decoding protobuf or JSON produces [`pb::Ir`], which is intentionally
/// treated as untrusted. Interpreters and code generators accept this type
/// instead, making it impossible to accidentally bypass validation at their
/// public API boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedIr(pb::Ir);

impl ValidatedIr {
    pub fn new(ir: pb::Ir) -> std::result::Result<Self, ValidationErrors> {
        Self::new_with_limits(ir, &validate::ValidationLimits::default())
    }

    pub fn new_with_limits(
        ir: pb::Ir,
        limits: &validate::ValidationLimits,
    ) -> std::result::Result<Self, ValidationErrors> {
        validate::validate_with_limits(&ir, limits).map_err(ValidationErrors)?;
        Ok(Self(ir))
    }

    pub fn as_pb(&self) -> &pb::Ir {
        &self.0
    }

    pub fn into_inner(self) -> pb::Ir {
        self.0
    }
}

impl Deref for ValidatedIr {
    type Target = pb::Ir;

    fn deref(&self) -> &Self::Target {
        self.as_pb()
    }
}

impl AsRef<pb::Ir> for ValidatedIr {
    fn as_ref(&self) -> &pb::Ir {
        self.as_pb()
    }
}

impl PartialEq<pb::Ir> for ValidatedIr {
    fn eq(&self, other: &pb::Ir) -> bool {
        self.as_pb() == other
    }
}

impl PartialEq<ValidatedIr> for pb::Ir {
    fn eq(&self, other: &ValidatedIr) -> bool {
        self == other.as_pb()
    }
}

impl TryFrom<pb::Ir> for ValidatedIr {
    type Error = ValidationErrors;

    fn try_from(value: pb::Ir) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<String>);

impl std::fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid IR:\n  {}", self.0.join("\n  "))
    }
}

impl std::error::Error for ValidationErrors {}

pub fn to_bytes(ir: &pb::Ir) -> Vec<u8> {
    ir.encode_to_vec()
}

pub fn from_bytes(b: &[u8]) -> Result<pb::Ir> {
    Ok(pb::Ir::decode(b)?)
}

pub fn to_json(ir: &pb::Ir) -> Result<String> {
    Ok(serde_json::to_string_pretty(ir)?)
}

/// Read, parse, and validate an IR file (protojson) — the standard way
/// any consumer loads an IR from disk.
pub fn load(path: &std::path::Path) -> anyhow::Result<ValidatedIr> {
    use anyhow::Context as _;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading IR from {}", path.display()))?;
    let ir = from_json(&text)?;
    Ok(ValidatedIr::new(ir)?)
}

pub fn from_json(s: &str) -> Result<pb::Ir> {
    Ok(serde_json::from_str(s)?)
}

/// Semantic canonicalization (`fmt-ir`): orderings the IR's meaning
/// does not depend on are normalized, so equal parsers serialize to
/// equal bytes. Today that is one rule: `value_labels` sort by value
/// (presentation metadata; no execution path may branch on it).
/// Select arms are deliberately NOT reordered — authored arm order is
/// reserved as priority order for future masked/range arms.
pub fn canonicalize(ir: &mut pb::Ir) {
    let Some(parser) = ir.parser.as_mut() else {
        return;
    };
    let displays = parser
        .header_types
        .iter_mut()
        .flat_map(|ht| &mut ht.fields)
        .filter_map(|f| f.display.as_mut())
        .chain(
            parser
                .metadata
                .iter_mut()
                .filter_map(|m| m.display.as_mut()),
        );
    for d in displays {
        d.value_labels.sort_by_key(|vl| vl.value);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::pb;

    pub fn tiny() -> pb::Ir {
        pb::Ir {
            ir_version: super::IR_VERSION.into(),
            parser: Some(pb::Parser {
                name: "tiny".into(),
                max_depth: 1,
                start_state: "s".into(),
                states: vec![pb::State {
                    name: "s".into(),
                    transition: Some(pb::Transition {
                        kind: Some(pb::transition::Kind::Direct(pb::Target {
                            kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                        })),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binary_and_json() {
        let ir = test_support::tiny();
        assert_eq!(from_bytes(&to_bytes(&ir)).unwrap(), ir);
        assert_eq!(from_json(&to_json(&ir).unwrap()).unwrap(), ir);
    }

    #[test]
    fn canonicalize_sorts_value_labels_everywhere() {
        let labels = |vals: &[u64]| {
            Some(pb::Display {
                value_labels: vals
                    .iter()
                    .map(|&value| pb::ValueLabel {
                        value,
                        label: format!("l{value}"),
                    })
                    .collect(),
                ..Default::default()
            })
        };
        let mut ir = test_support::tiny();
        let parser = ir.parser.as_mut().unwrap();
        parser.header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                display: labels(&[0x86DD, 0x0800, 0x6558]),
                ..Default::default()
            }],
            ..Default::default()
        });
        parser.metadata.push(pb::MetadataField {
            name: "m".into(),
            display: labels(&[17, 6]),
            ..Default::default()
        });
        canonicalize(&mut ir);
        let parser = ir.parser.as_ref().unwrap();
        let values = |d: &Option<pb::Display>| -> Vec<u64> {
            d.as_ref()
                .unwrap()
                .value_labels
                .iter()
                .map(|vl| vl.value)
                .collect()
        };
        assert_eq!(
            values(&parser.header_types[0].fields[0].display),
            vec![0x0800, 0x6558, 0x86DD]
        );
        assert_eq!(values(&parser.metadata[0].display), vec![6, 17]);
    }
}

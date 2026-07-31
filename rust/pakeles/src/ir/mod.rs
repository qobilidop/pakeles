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

pub const IR_VERSION: &str = "0.1.0";

use anyhow::Result;
use prost::Message;

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
pub fn load(path: &std::path::Path) -> anyhow::Result<pb::Ir> {
    use anyhow::Context as _;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading IR from {}", path.display()))?;
    let ir = from_json(&text)?;
    validate::validate(&ir).map_err(|e| anyhow::anyhow!("invalid IR:\n  {}", e.join("\n  ")))?;
    Ok(ir)
}

pub fn from_json(s: &str) -> Result<pb::Ir> {
    Ok(serde_json::from_str(s)?)
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
}

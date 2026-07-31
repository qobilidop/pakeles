//! The built-in synthetic gallery examples, loaded from their
//! committed IR.
//!
//! The eDSL (`python/src/pakeles/examples/*.py`) is the single source of
//! truth; `scripts/gen-examples.sh` emits the canonical `ir.json` per
//! example. Here we embed each committed file at compile time — this
//! doubles as the CLI's default IR, so it must work outside the repo
//! root, which `include_str!` guarantees (a compile-time *embedding*
//! guarantee: the file must exist to build). The parse itself happens
//! at load time — checked by the `embedded_ir_parses_and_validates`
//! tests below.
//!
//! Only the synthetic gallery lives in the core crate: each real-world
//! example (`examples/real_world/<X>/`) is its own workspace member
//! carrying its own IR loader, projection, and gates.

use crate::ir::pb;

/// Gallery examples built to isolate one IR capability (no incumbent
/// to agree with) — `examples/synthetic/`.
pub const SYNTHETIC: [&str; 3] = ["eth_ipvx_l4", "counted_items", "tlv_items"];

/// The gallery example, parsed from the embedded committed IR.
pub fn eth_ipvx_l4() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/synthetic/eth_ipvx_l4/eth_ipvx_l4.ir.json"
    ))
    .expect("committed example IR must parse")
}

/// The metadata-v1 toy example, parsed from the embedded committed IR.
pub fn counted_items() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/synthetic/counted_items/counted_items.ir.json"
    ))
    .expect("committed example IR must parse")
}

/// The sized-region toy example (length-bounded TLV items), parsed
/// from the embedded committed IR.
pub fn tlv_items() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/synthetic/tlv_items/tlv_items.ir.json"
    ))
    .expect("committed example IR must parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ir_parses_and_validates() {
        for ir in [eth_ipvx_l4(), counted_items(), tlv_items()] {
            crate::ir::validate::validate(&ir).unwrap();
        }
    }

    #[test]
    fn committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard.
        for name in SYNTHETIC {
            let committed =
                std::fs::read_to_string(format!("examples/synthetic/{name}/{name}.ir.json"))
                    .unwrap();
            let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
            assert_eq!(
                round, committed,
                "committed {name}.ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
            );
        }
    }

    #[test]
    fn committed_py_example_current() {
        for name in SYNTHETIC {
            let canonical =
                std::fs::read_to_string(format!("python/src/pakeles/examples/{name}.py")).unwrap();
            let mirrored =
                std::fs::read_to_string(format!("examples/synthetic/{name}/{name}.py")).unwrap();
            assert_eq!(
                canonical, mirrored,
                "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
            );
        }
    }
}

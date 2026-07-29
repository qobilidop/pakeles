//! The built-in gallery examples (`eth_ipvx_l4`, `linux_flow_dissector`),
//! loaded from their committed IR.
//!
//! The eDSL (`py/src/pakeles/examples/*.py`) is the single source of
//! truth; `scripts/gen-examples.sh` emits the canonical `ir.json` per
//! example. Here we embed each committed file at compile time — this
//! doubles as the CLI's default IR, so it must work outside the repo
//! root, which `include_str!` guarantees (a compile-time *embedding*
//! guarantee: the file must exist to build). The parse itself happens
//! at load time — checked by the `embedded_ir_parses_and_validates`
//! tests below.

use crate::ir::pb;

/// The gallery example, parsed from the embedded committed IR.
pub fn eth_ipvx_l4() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/eth_ipvx_l4/eth_ipvx_l4.ir.json"))
        .expect("committed example IR must parse")
}

/// The linux_flow_dissector example, parsed from its committed IR.
pub fn linux_flow_dissector() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/linux_flow_dissector/linux_flow_dissector.ir.json"
    ))
    .expect("committed linux_flow_dissector IR must parse")
}

/// The dpdk_ptype example (DPDK rte_net_get_ptype agreement), parsed
/// from its committed IR.
pub fn dpdk_ptype() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/dpdk_ptype/dpdk_ptype.ir.json"))
        .expect("committed dpdk_ptype IR must parse")
}

/// The katran_flow example (Katran XDP parse-path agreement), parsed
/// from its committed IR.
pub fn katran_flow() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/katran_flow/katran_flow.ir.json"))
        .expect("committed katran_flow IR must parse")
}

/// The sai_parser example (SONiC PINS parser agreement), parsed from
/// its committed IR.
pub fn sai_parser() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/sai_parser/sai_parser.ir.json"))
        .expect("committed sai_parser IR must parse")
}

/// The metadata-v1 toy example, parsed from the embedded committed IR.
pub fn counted_items() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/counted_items/counted_items.ir.json"
    ))
    .expect("committed example IR must parse")
}

/// The sized-region toy example (length-bounded TLV items), parsed
/// from the embedded committed IR.
pub fn tlv_items() -> pb::Ir {
    crate::ir::from_json(include_str!("../examples/tlv_items/tlv_items.ir.json"))
        .expect("committed example IR must parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&eth_ipvx_l4()).unwrap();
    }

    #[test]
    fn committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard (replaces the old builder-vs-committed check).
        let committed =
            std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/eth_ipvx_l4.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/eth_ipvx_l4/eth_ipvx_l4.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn linux_flow_dissector_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&linux_flow_dissector()).unwrap();
    }

    #[test]
    fn linux_flow_dissector_committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard (replaces the old builder-vs-committed check).
        let committed =
            std::fs::read_to_string("examples/linux_flow_dissector/linux_flow_dissector.ir.json")
                .unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn linux_flow_dissector_committed_py_example_current() {
        let canonical =
            std::fs::read_to_string("py/src/pakeles/examples/linux_flow_dissector.py").unwrap();
        let mirrored =
            std::fs::read_to_string("examples/linux_flow_dissector/linux_flow_dissector.py")
                .unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn dpdk_ptype_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&dpdk_ptype()).unwrap();
    }

    #[test]
    fn dpdk_ptype_committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard (replaces the old builder-vs-committed check).
        let committed = std::fs::read_to_string("examples/dpdk_ptype/dpdk_ptype.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn dpdk_ptype_committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/dpdk_ptype.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/dpdk_ptype/dpdk_ptype.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn katran_flow_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&katran_flow()).unwrap();
    }

    #[test]
    fn katran_flow_committed_ir_json_is_canonical() {
        let committed =
            std::fs::read_to_string("examples/katran_flow/katran_flow.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn katran_flow_committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/katran_flow.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/katran_flow/katran_flow.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn sai_parser_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&sai_parser()).unwrap();
    }

    #[test]
    fn sai_parser_committed_ir_json_is_canonical() {
        let committed = std::fs::read_to_string("examples/sai_parser/sai_parser.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn sai_parser_committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/sai_parser.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/sai_parser/sai_parser.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn counted_items_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&counted_items()).unwrap();
    }

    #[test]
    fn counted_items_committed_ir_json_is_canonical() {
        // The committed file must already be exactly what the Rust
        // canonical serializer emits — the anti-drift "canonical form"
        // guard (replaces the old builder-vs-committed check).
        let committed =
            std::fs::read_to_string("examples/counted_items/counted_items.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn counted_items_committed_py_example_current() {
        let canonical =
            std::fs::read_to_string("py/src/pakeles/examples/counted_items.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/counted_items/counted_items.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn tlv_items_embedded_ir_parses_and_validates() {
        crate::ir::validate::validate(&tlv_items()).unwrap();
    }

    #[test]
    fn tlv_items_committed_ir_json_is_canonical() {
        let committed = std::fs::read_to_string("examples/tlv_items/tlv_items.ir.json").unwrap();
        let round = crate::ir::to_json(&crate::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn tlv_items_committed_py_example_current() {
        let canonical = std::fs::read_to_string("py/src/pakeles/examples/tlv_items.py").unwrap();
        let mirrored = std::fs::read_to_string("examples/tlv_items/tlv_items.py").unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }
}

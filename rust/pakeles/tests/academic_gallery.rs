//! Conformance + equality guards for the academic gallery
//! (examples/academic/ — descriptions reproduced from published
//! evaluations; see its README). Same battery as the synthetic
//! gallery, but the descriptions are not embedded in the crate: each
//! committed ir.json is loaded from disk. Keep the NAMES list in step
//! with pakeles-dev's ACADEMIC table, scripts/gen-examples.sh, and
//! python/tests/conftest.py.

use std::path::{Path, PathBuf};

const NAMES: [&str; 8] = [
    "gibb_simple",
    "gibb_enterprise",
    "gibb_datacenter",
    "gibb_edge",
    "gibb_service_provider",
    "gibb_big_union",
    "kangaroo_parse_tree",
    "p4lang_switch_parser",
];

fn dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/academic")
        .join(name)
}

fn ir(name: &str) -> pakeles::ir::pb::Ir {
    pakeles::ir::load(&dir(name).join(format!("{name}.ir.json")))
        .unwrap_or_else(|e| panic!("loading committed {name}.ir.json: {e}"))
}

fn suite(name: &str) -> Option<pakeles::testvec::pb::TestSuite> {
    pakeles_testkit::committed_suite(&dir(name))
}

/// Every committed description validates and is in canonical form
/// (byte-identical to what the canonical serializer emits).
#[test]
fn committed_ir_json_valid_and_canonical() {
    for name in NAMES {
        let path = dir(name).join(format!("{name}.ir.json"));
        let committed =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let parsed = pakeles::ir::from_json(&committed).unwrap();
        pakeles::ir::validate::validate(&parsed).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let round = pakeles::ir::to_json(&parsed).unwrap();
        assert_eq!(
            round, committed,
            "{name}.ir.json is not canonical; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }
}

// --- committed gen/ artifacts ---

#[test]
fn committed_gen_artifacts_current_all() {
    for name in NAMES {
        pakeles_testkit::committed_artifacts_current(&ir(name), &dir(name));
    }
}

// --- C backend ---

#[test]
fn c_backend_conformance_all() {
    for name in NAMES {
        pakeles_testkit::c_backend_conformance(&ir(name), suite(name).as_ref());
    }
}

// --- eBPF backend ---

#[test]
fn bpf_backend_conformance_all() {
    for name in NAMES {
        pakeles_testkit::bpf_backend_conformance(&ir(name), suite(name).as_ref());
    }
}

// --- Wireshark Lua backend (inside real tshark) ---

#[test]
fn lua_backend_conformance_all() {
    for name in NAMES {
        let Some(suite) = suite(name) else {
            continue;
        };
        pakeles_testkit::lua_backend_conformance(&ir(name), &suite, 3);
    }
}

// --- BMv2 simple_switch (P4 backend) — bounded to two members to
// --- keep the gate's BMv2 cost flat; gibb_big_union additionally
// --- exercises the 32-bit verdict-bitmap tier at generation time
// --- via committed_gen_artifacts_current above.

#[test]
fn bmv2_backend_conformance_gibb_simple() {
    let Some(suite) = suite("gibb_simple") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("gibb_simple"), &suite, 4);
}

#[test]
fn bmv2_backend_conformance_gibb_enterprise() {
    let Some(suite) = suite("gibb_enterprise") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("gibb_enterprise"), &suite, 4);
}

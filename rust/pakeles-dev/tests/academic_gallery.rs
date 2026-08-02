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
        .join("../../benchmarks/academic")
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

// --- BMv2 simple_switch (P4 backend). Every academic member with a
// --- committed gen/parser.p4 now has one: the 2026-08-01 lesson was
// --- that "generates" is not "compiles" — the four `lookahead`
// --- members below emitted P4 that p4c-bm2-ss had ALWAYS rejected
// --- (a 4-bit nibble header) and nobody knew, because none of them
// --- had this test. The oracle batches a suite into one
// --- simple_switch run, so the added cost is seconds.

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

// The four `lookahead` members: their P4 became BMv2-compilable only
// when the pseudo-field stopped being a consumed 4-bit header
// (2026-08-01), so these tests could not have existed before.

#[test]
fn bmv2_backend_conformance_gibb_service_provider() {
    let Some(suite) = suite("gibb_service_provider") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("gibb_service_provider"), &suite, 15);
}

#[test]
fn bmv2_backend_conformance_gibb_edge() {
    let Some(suite) = suite("gibb_edge") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("gibb_edge"), &suite, 10);
}

#[test]
fn bmv2_backend_conformance_gibb_big_union() {
    let Some(suite) = suite("gibb_big_union") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("gibb_big_union"), &suite, 1_500);
}

#[test]
fn bmv2_backend_conformance_kangaroo_parse_tree() {
    let Some(suite) = suite("kangaroo_parse_tree") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("kangaroo_parse_tree"), &suite, 2_000);
}

/// The flagship: P4-vs-P4 over switch.p4's own parser, all 13,599
/// byte-aligned vectors in one `simple_switch` run (~14 s). Worth its
/// cost in the gate — this is the member that exercised BOTH P4-backend
/// defects found 2026-08-01 (a peeked header type BMv2 rejects for not
/// being a byte multiple, and a zero-mask catch-all arm BMv2 never
/// matches), neither of which any smaller member reaches.
#[test]
fn bmv2_backend_conformance_p4lang_switch_parser() {
    let Some(suite) = suite("p4lang_switch_parser") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&ir("p4lang_switch_parser"), &suite, 13_000);
}

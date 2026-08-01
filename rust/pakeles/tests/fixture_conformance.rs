//! Conformance guards for the core's OWN test parsers — the frozen
//! fixture files under repo-root `testdata/parsers/` (see the
//! 2026-07-31 layout decision record: these are independent of the
//! educational `examples/` tree and free to evolve for coverage).
//! Suites are generated in-test by symex (no committed vectors, no
//! committed `gen/` artifacts — fixtures are not a browsable gallery).

#![cfg(feature = "symex")]

use std::path::{Path, PathBuf};

const NAMES: [&str; 3] = ["eth_ipvx_l4", "counted_items", "tlv_items"];

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/parsers")
        .join(format!("{name}.ir.json"))
}

fn ir(name: &str) -> pakeles::ir::pb::Ir {
    pakeles::ir::load(&fixture_path(name)).unwrap_or_else(|e| panic!("loading fixture {name}: {e}"))
}

fn suite(name: &str) -> pakeles::testvec::pb::TestSuite {
    pakeles::symex::testgen::generate(&ir(name))
        .unwrap_or_else(|e| panic!("testgen for fixture {name}: {e}"))
}

#[test]
fn fixtures_validate() {
    for name in NAMES {
        pakeles::ir::validate::validate(&ir(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

#[test]
fn c_backend_conformance_fixtures() {
    for name in NAMES {
        pakeles_testkit::c_backend_conformance(&ir(name), Some(&suite(name)));
    }
}

#[test]
fn bpf_backend_conformance_fixtures() {
    for name in NAMES {
        pakeles_testkit::bpf_backend_conformance(&ir(name), Some(&suite(name)));
    }
}

#[test]
fn lua_backend_conformance_fixtures() {
    for name in NAMES {
        pakeles_testkit::lua_backend_conformance(&ir(name), &suite(name), 3);
    }
}

#[test]
fn bmv2_backend_conformance_eth_ipvx_l4() {
    pakeles_testkit::bmv2_backend_conformance(&ir("eth_ipvx_l4"), &suite("eth_ipvx_l4"), 6);
}

#[test]
fn bmv2_backend_conformance_counted_items() {
    // BMv2 compares the header-presence bitmap only (documented v1
    // boundary) — still exercises the metadata-driven select loop.
    pakeles_testkit::bmv2_backend_conformance(&ir("counted_items"), &suite("counted_items"), 2);
}

// Builder-constructed micro-fixtures keep their compile checks here
// (they live in the lib, not in testdata).
#[test]
fn c_backend_compiles_builder_fixtures() {
    pakeles_testkit::c_backend_conformance(&pakeles::builder::tlv_mini(), None);
    pakeles_testkit::c_backend_conformance(&pakeles::builder::meta_loop(), None);
}

#[test]
fn bpf_backend_compiles_builder_fixtures() {
    pakeles_testkit::bpf_backend_conformance(&pakeles::builder::tlv_mini(), None);
    pakeles_testkit::bpf_backend_conformance(&pakeles::builder::meta_loop(), None);
}

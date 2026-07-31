//! Conformance + equality guards for the synthetic gallery, via the
//! shared harnesses in pakeles-testkit. (Integration tests, not unit
//! tests: the harnesses must see the same `pakeles` crate instance
//! they were compiled against.) The real-world examples run the same
//! battery from their own crates.

use std::path::{Path, PathBuf};

fn dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/synthetic")
        .join(name)
}

fn suite(name: &str) -> Option<pakeles::testvec::pb::TestSuite> {
    pakeles_testkit::committed_suite(&dir(name))
}

// --- committed gen/ artifacts ---

#[test]
fn committed_gen_artifacts_current_eth_ipvx_l4() {
    pakeles_testkit::committed_artifacts_current(
        &pakeles::examples::eth_ipvx_l4(),
        &dir("eth_ipvx_l4"),
    );
}

#[test]
fn committed_gen_artifacts_current_counted_items() {
    pakeles_testkit::committed_artifacts_current(
        &pakeles::examples::counted_items(),
        &dir("counted_items"),
    );
}

#[test]
fn committed_gen_artifacts_current_tlv_items() {
    pakeles_testkit::committed_artifacts_current(
        &pakeles::examples::tlv_items(),
        &dir("tlv_items"),
    );
}

// --- C backend ---

#[test]
fn c_backend_conformance_eth_ipvx_l4() {
    pakeles_testkit::c_backend_conformance(
        &pakeles::examples::eth_ipvx_l4(),
        suite("eth_ipvx_l4").as_ref(),
    );
}

#[test]
fn c_backend_conformance_counted_items() {
    pakeles_testkit::c_backend_conformance(
        &pakeles::examples::counted_items(),
        suite("counted_items").as_ref(),
    );
}

#[test]
fn c_backend_conformance_tlv_items() {
    pakeles_testkit::c_backend_conformance(
        &pakeles::examples::tlv_items(),
        suite("tlv_items").as_ref(),
    );
}

#[test]
fn c_backend_compiles_tlv_mini() {
    pakeles_testkit::c_backend_conformance(&pakeles::builder::tlv_mini(), None);
}

#[test]
fn c_backend_compiles_meta_loop() {
    pakeles_testkit::c_backend_conformance(&pakeles::builder::meta_loop(), None);
}

// --- eBPF backend ---

#[test]
fn bpf_backend_conformance_eth_ipvx_l4() {
    pakeles_testkit::bpf_backend_conformance(
        &pakeles::examples::eth_ipvx_l4(),
        suite("eth_ipvx_l4").as_ref(),
    );
}

#[test]
fn bpf_backend_conformance_counted_items() {
    pakeles_testkit::bpf_backend_conformance(
        &pakeles::examples::counted_items(),
        suite("counted_items").as_ref(),
    );
}

#[test]
fn bpf_backend_conformance_tlv_items() {
    pakeles_testkit::bpf_backend_conformance(
        &pakeles::examples::tlv_items(),
        suite("tlv_items").as_ref(),
    );
}

#[test]
fn bpf_backend_compiles_tlv_mini() {
    pakeles_testkit::bpf_backend_conformance(&pakeles::builder::tlv_mini(), None);
}

#[test]
fn bpf_backend_compiles_meta_loop() {
    pakeles_testkit::bpf_backend_conformance(&pakeles::builder::meta_loop(), None);
}

// --- Wireshark Lua backend (inside real tshark) ---

#[test]
fn lua_backend_conformance_eth_ipvx_l4() {
    // One-witness-per-path shrank the accept-vector set; the floor
    // guards against a silently-empty suite, not an exact count.
    let Some(suite) = suite("eth_ipvx_l4") else {
        return;
    };
    pakeles_testkit::lua_backend_conformance(&pakeles::examples::eth_ipvx_l4(), &suite, 100);
}

#[test]
fn lua_backend_conformance_counted_items() {
    let Some(suite) = suite("counted_items") else {
        return;
    };
    pakeles_testkit::lua_backend_conformance(&pakeles::examples::counted_items(), &suite, 3);
}

#[test]
fn lua_backend_conformance_tlv_items() {
    let Some(suite) = suite("tlv_items") else {
        return;
    };
    pakeles_testkit::lua_backend_conformance(&pakeles::examples::tlv_items(), &suite, 3);
}

// --- BMv2 simple_switch (P4 backend; region-bearing tlv_items is
// --- P4-unsupported by design, so no bmv2 entry for it) ---

#[test]
fn bmv2_backend_conformance_eth_ipvx_l4() {
    let Some(suite) = suite("eth_ipvx_l4") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&pakeles::examples::eth_ipvx_l4(), &suite, 6);
}

#[test]
fn bmv2_backend_conformance_counted_items() {
    // BMv2 compares the header-presence bitmap only (documented v1
    // boundary) — this still exercises the metadata-driven select
    // loop's control flow, just not the metadata values themselves.
    let Some(suite) = suite("counted_items") else {
        return;
    };
    pakeles_testkit::bmv2_backend_conformance(&pakeles::examples::counted_items(), &suite, 2);
}

//! Gate battery for the educational tutorials (`examples/<name>`,
//! flat): committed IR canonical + valid, committed `gen/` artifacts
//! current, and backend conformance over the committed suites.
//! Tutorials are proven here — from the dev crate, per the 2026-07-31
//! layout decision record — without being load-bearing for the engine
//! (the core's own fixtures live in `testdata/parsers/`). Keep NAMES
//! in step with `pakeles_dev::TUTORIALS`.

use std::path::PathBuf;

fn dir(name: &str) -> PathBuf {
    pakeles_dev::repo_root().join("examples").join(name)
}

fn ir(name: &str) -> pakeles::ir::ValidatedIr {
    pakeles::ir::load(&dir(name).join(format!("{name}.ir.json")))
        .unwrap_or_else(|e| panic!("loading committed {name}.ir.json: {e}"))
}

fn suite(name: &str) -> Option<pakeles::testvec::pb::TestSuite> {
    pakeles_testkit::committed_suite(&dir(name))
}

#[test]
fn committed_ir_json_valid_and_canonical() {
    for name in pakeles_dev::TUTORIALS {
        let path = dir(name).join(format!("{name}.ir.json"));
        let committed =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let parsed = pakeles::ir::from_json(&committed).unwrap();
        pakeles::ir::validate::validate(&parsed).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(
            pakeles::ir::to_json(&parsed).unwrap(),
            committed,
            "{name}.ir.json is not canonical; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }
}

#[test]
fn committed_gen_artifacts_current_all() {
    for name in pakeles_dev::TUTORIALS {
        pakeles_testkit::committed_artifacts_current(&ir(name), &dir(name));
    }
}

#[test]
fn c_backend_conformance_all() {
    for name in pakeles_dev::TUTORIALS {
        pakeles_testkit::c_backend_conformance(&ir(name), suite(name).as_ref());
    }
}

#[test]
fn bpf_backend_conformance_all() {
    for name in pakeles_dev::TUTORIALS {
        pakeles_testkit::bpf_backend_conformance(&ir(name), suite(name).as_ref());
    }
}

#[test]
fn lua_backend_conformance_all() {
    for name in pakeles_dev::TUTORIALS {
        let Some(suite) = suite(name) else {
            continue;
        };
        pakeles_testkit::lua_backend_conformance(&ir(name), &suite, 3);
    }
}

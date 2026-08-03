//! Regenerates the committed generated-protobuf code in the core
//! crate from the normative schemas in `proto/`.
//!
//! The core crate vendors its prost/pbjson output (like `python/`
//! vendors its `_pb` modules) so that consumers of the published crate
//! never need protoc, and so the crate is location-independent for
//! packaging. The cost is this manual step after any `proto/` change:
//!
//! ```sh
//! ./dev.sh cargo run --bin pakeles-pbgen
//! ```
//!
//! The committed output is equality-guarded by this crate's
//! `committed_pb_current` test (skip-gated on protoc, like every
//! tool-dependent test).

use std::path::{Path, PathBuf};

/// The four files `generate` emits, relative to the output dir.
pub const GENERATED: [&str; 4] = [
    "pakeles.ir.v1alpha1.rs",
    "pakeles.ir.v1alpha1.serde.rs",
    "pakeles.testvec.v1alpha1.rs",
    "pakeles.testvec.v1alpha1.serde.rs",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Where the committed generated code lives, inside the core crate.
pub fn committed_dir() -> PathBuf {
    repo_root().join("rust/pakeles/src/gen")
}

/// Run prost + pbjson over `proto/` into `out_dir`. Mirrors what the
/// core crate's build.rs did before the output was vendored.
pub fn generate(out_dir: &Path) -> anyhow::Result<()> {
    let root = repo_root();
    let protos = [
        root.join("proto/pakeles/ir/v1alpha1/ir.proto"),
        root.join("proto/pakeles/testvec/v1alpha1/testvec.proto"),
    ];
    std::fs::create_dir_all(out_dir)?;
    let descriptor = out_dir.join("descriptor.bin");
    prost_build::Config::new()
        .out_dir(out_dir)
        .file_descriptor_set_path(&descriptor)
        .boxed(".pakeles.ir.v1alpha1.BinOp.lhs")
        .boxed(".pakeles.ir.v1alpha1.BinOp.rhs")
        // BTreeMap for every proto map: HashMap serializes in iteration
        // order, which would make `fmt-ir` output nondeterministic the
        // moment an annotations map holds a second entry.
        .btree_map(["."])
        .compile_protos(&protos, &[root.join("proto")])?;
    pbjson_build::Builder::new()
        .out_dir(out_dir)
        .register_descriptors(&std::fs::read(&descriptor)?)?
        .btree_map(["."])
        .build(&[".pakeles.ir.v1alpha1", ".pakeles.testvec.v1alpha1"])?;
    std::fs::remove_file(descriptor)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let dir = committed_dir();
    generate(&dir)?;
    println!("regenerated {} files in {}", GENERATED.len(), dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed generated code must match fresh generation from
    /// `proto/` — the anti-drift guard for the vendored output.
    /// Skips where protoc is absent (it runs in the dev container).
    #[test]
    fn committed_pb_current() {
        if !pakeles::process::is_available("protoc", &["--version"]) {
            eprintln!("skipping: protoc not available");
            return;
        }
        let tmp = tempfile::Builder::new()
            .prefix("pakeles_pbgen_")
            .tempdir()
            .unwrap();
        generate(tmp.path()).unwrap();
        for f in GENERATED {
            let fresh = std::fs::read_to_string(tmp.path().join(f)).unwrap();
            let committed = std::fs::read_to_string(committed_dir().join(f)).unwrap();
            assert_eq!(
                fresh, committed,
                "{f} drifted from proto/; regenerate: ./dev.sh cargo run --bin pakeles-pbgen"
            );
        }
    }
}

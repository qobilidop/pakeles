pub mod builder;
pub mod codegen;
pub mod docgen;
pub mod examples;
pub mod fixtures;
pub mod interp;
pub mod ir;
pub mod oracle;
pub mod pcapio;
#[cfg(feature = "symex")]
pub mod symex;
pub mod testvec;
pub mod viz;

/// Repo-root-relative path for tests and fixture tooling: unit tests
/// run with CWD = this crate's directory (rust/pakeles), two levels
/// below the repo root where the language-neutral trees (testdata/,
/// examples/, python/) live.
#[cfg(test)]
pub(crate) fn test_repo_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

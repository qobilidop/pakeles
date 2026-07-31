//! The example's diff command: run from this directory, `cargo run`
//! diffs our flow-dissector parse (flow keys)
//! against the committed kernel-captured golden — the human-facing form of
//! the `committed_goldens_agree` gate test.

use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Diff our flow-dissector parse (flow keys) against the committed kernel-captured golden"
)]
struct Args {
    /// IR file (protojson). Defaults to the committed description.
    #[arg(long)]
    ir: Option<std::path::PathBuf>,
    /// Golden file. Defaults to the committed golden in conformance/.
    #[arg(long)]
    goldens: Option<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = pakeles_example_linux_flow_dissector::cli_diff(
        args.ir.as_deref(),
        args.goldens.as_deref(),
    )?;
    print!("{report}");
    std::process::exit(if report.mismatches.is_empty() { 0 } else { 1 });
}

//! The example's diff command: run from this directory, `cargo run`
//! diffs our dpdk_ptype parse (ptype mask + hdr_lens)
//! against the committed DPDK-minted golden — the human-facing form of
//! the `committed_goldens_agree` gate test.

use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Diff our dpdk_ptype parse (ptype mask + hdr_lens) against the committed DPDK-minted golden"
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
    let report = pakeles_example_dpdk_ptype::cli_diff(args.ir.as_deref(), args.goldens.as_deref())?;
    print!("{report}");
    std::process::exit(if report.mismatches.is_empty() { 0 } else { 1 });
}

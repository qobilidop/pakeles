//! The `pakeles` CLI: thin dispatch onto library functions.

use anyhow::{Context, Result};
use clap::{Parser as ClapParser, Subcommand};
use pakeles::interp::{FieldValue, Outcome};
use pakeles::ir::pb;
use std::path::{Path, PathBuf};

#[derive(ClapParser)]
#[command(
    name = "pakeles",
    version,
    about = "Pakeles wire-format parser toolchain"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse every packet in a pcap; one JSON line per packet.
    Run {
        #[arg(long)]
        pcap: PathBuf,
        /// IR file (protojson).
        #[arg(long)]
        ir: PathBuf,
    },
    /// Emit the parse graph as Graphviz dot.
    Viz {
        #[arg(long)]
        ir: PathBuf,
    },
    /// Diff our parse against a toolchain-generic oracle (tshark,
    /// BMv2); exit 1 on mismatch. Incumbent diffs live with their
    /// examples: `cargo run -p pakeles-example-<x>`.
    Diff {
        #[command(subcommand)]
        oracle: Oracle,
    },
    /// Generate the path-complete conformance test-vector suite.
    #[cfg(feature = "symex")]
    Testgen {
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
        /// Also export the byte-aligned vectors as a pcap.
        #[arg(long)]
        pcap_out: Option<PathBuf>,
    },
    /// Report unreachable states and unsatisfiable select arms.
    #[cfg(feature = "symex")]
    Lint {
        #[arg(long)]
        ir: PathBuf,
    },
    /// Report which parse paths a pcap corpus exercises.
    #[cfg(feature = "symex")]
    Cov {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ir: PathBuf,
    },
    /// Generate markdown documentation from the IR + annotations.
    Doc {
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Generate a backend artifact from the IR.
    Gen {
        #[command(subcommand)]
        target: GenTarget,
    },
    /// Canonicalize an IR file: parse + re-emit in the canonical form
    /// (what this CLI itself writes). Other authoring surfaces (the
    /// Python eDSL) pipe through this before equality comparisons.
    FmtIr {
        /// IR file (protojson) to canonicalize.
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout. Defaults to stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum GenTarget {
    /// Wireshark Lua dissector (direct translation, Lua 5.2).
    Lua {
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Portable C99 parser (<name>.h + <name>.c).
    C {
        #[arg(long)]
        ir: PathBuf,
        /// Directory to write parser.h and parser.c into.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
    },
    /// Self-contained eBPF C variant.
    Bpf {
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// P4-16 program for the v1model architecture (BMv2-runnable).
    P4 {
        #[arg(long)]
        ir: PathBuf,
        /// Output path; `-` for stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum Oracle {
    /// Compare annotated numeric fields against `tshark -T json`.
    Tshark {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        ir: PathBuf,
    },
    /// Verdict-compare the byte-aligned vectors against BMv2 simple_switch.
    Bmv2 {
        #[arg(long)]
        ir: PathBuf,
        /// Vector suite (testvec JSON). Defaults to the gallery suite.
        #[arg(
            long,
            default_value = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../examples/eth_ipvx_l4/conformance/vectors.json"
            )
        )]
        vectors: PathBuf,
    },
}

fn load_ir(path: &Path) -> Result<pb::Ir> {
    pakeles::ir::load(path)
}

fn result_json(idx: usize, res: &pakeles::interp::ParseResult) -> serde_json::Value {
    let headers: Vec<serde_json::Value> = res
        .headers
        .iter()
        .map(|h| {
            let fields: serde_json::Map<String, serde_json::Value> = h
                .fields
                .iter()
                .map(|f| {
                    let v = match &f.value {
                        FieldValue::Uint(u) => serde_json::json!(u),
                        FieldValue::Bytes(b) => serde_json::json!(b
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>()),
                    };
                    (f.name.clone(), v)
                })
                .collect();
            serde_json::json!({ "instance": h.instance, "fields": fields })
        })
        .collect();
    let outcome = match &res.outcome {
        Outcome::Accept => serde_json::json!("accept"),
        Outcome::Reject { reason } => serde_json::json!({ "reject": reason }),
    };
    let error = res.error.as_ref().map(|e| {
        serde_json::json!({
            "state": e.state,
            "instance": e.instance,
            "field": e.field,
            "bit_offset": e.bit_offset,
            "reason": e.reason,
            "severity": match e.severity {
                pakeles::interp::Severity::Error => "error",
                pakeles::interp::Severity::Info => "info",
            },
        })
    });
    serde_json::json!({
        "packet": idx,
        "outcome": outcome,
        "headers": headers,
        "error": error,
        "payload_bit_off": res.consumed_bits,
    })
}

/// Entry point returning a process exit code (testable without a process).
pub fn main_with(args: &[&str]) -> Result<i32> {
    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Command::Run { pcap, ir } => {
            let ir = load_ir(&ir)?;
            for (idx, packet) in pakeles::pcapio::read_packets(&pcap)?.iter().enumerate() {
                let res = pakeles::interp::run(&ir, packet)?;
                println!("{}", result_json(idx, &res));
            }
            Ok(0)
        }
        Command::Viz { ir } => {
            print!("{}", pakeles::viz::to_dot(&load_ir(&ir)?));
            Ok(0)
        }
        Command::Diff {
            oracle: Oracle::Bmv2 { ir, vectors },
        } => {
            let ir = load_ir(&ir)?;
            let suite = pakeles::testvec::suite_from_json(&std::fs::read_to_string(&vectors)?)?;
            let report = pakeles::oracle::bmv2::diff_suite(&ir, &suite)?;
            println!(
                "{} vectors compared ({} bit-granular skipped, {} depth-bound skipped), {} mismatches",
                report.compared,
                report.skipped_bit_granular,
                report.skipped_depth_bound,
                report.mismatches.len()
            );
            for m in &report.mismatches {
                println!("  {m}");
            }
            Ok(if report.mismatches.is_empty() { 0 } else { 1 })
        }
        Command::Diff {
            oracle: Oracle::Tshark { pcap, ir },
        } => {
            let report = pakeles::oracle::diff_pcap(&load_ir(&ir)?, &pcap)?;
            println!(
                "{} packets, {} fields compared, {} mismatches",
                report.packets,
                report.compared,
                report.mismatches.len()
            );
            for m in &report.mismatches {
                println!(
                    "  packet {} {}: ours={:#x} tshark={} ({:?})",
                    m.packet, m.tshark_key, m.ours, m.raw, m.theirs
                );
            }
            Ok(if report.mismatches.is_empty() { 0 } else { 1 })
        }
        #[cfg(feature = "symex")]
        Command::Lint { ir } => {
            let findings = pakeles::symex::lint::lint(&load_ir(&ir)?)?;
            for f in &findings {
                println!("{}: {}", f.location, f.message);
            }
            if findings.is_empty() {
                println!("clean");
            }
            Ok(if findings.is_empty() { 0 } else { 1 })
        }
        #[cfg(feature = "symex")]
        Command::Cov { pcap, ir } => {
            let cov = pakeles::symex::cov::coverage(&load_ir(&ir)?, &pcap)?;
            println!(
                "{} packets exercised {}/{} paths",
                cov.packets,
                cov.hits.len(),
                cov.total
            );
            for (id, n) in &cov.hits {
                println!("  {n:>6}  {id}");
            }
            println!("{} paths unexercised", cov.unexercised.len());
            Ok(0)
        }
        #[cfg(feature = "symex")]
        Command::Testgen { ir, out, pcap_out } => {
            let suite = pakeles::symex::testgen::generate(&load_ir(&ir)?)?;
            let json = pakeles::testvec::suite_to_json(&suite)?;
            if out.as_os_str() == "-" {
                println!("{json}");
            } else {
                std::fs::write(&out, json)?;
                eprintln!("wrote {} vectors to {}", suite.vectors.len(), out.display());
            }
            if let Some(pcap) = pcap_out {
                let (packets, indices) = pakeles::testvec::suite_to_packets(&suite);
                pakeles::pcapio::write_pcap(&pcap, &packets)?;
                eprintln!(
                    "wrote {} byte-aligned vectors to {} ({} bit-granular vectors skipped)",
                    packets.len(),
                    pcap.display(),
                    suite.vectors.len() - indices.len()
                );
            }
            Ok(0)
        }
        Command::Doc { ir, out } => {
            let md = pakeles::docgen::generate_markdown(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{md}");
            } else {
                std::fs::write(&out, md)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::Lua { ir, out },
        } => {
            let lua = pakeles::codegen::lua::generate_lua(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{lua}");
            } else {
                std::fs::write(&out, lua)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::C { ir, out_dir },
        } => {
            let arts = pakeles::codegen::c::generate_c(&load_ir(&ir)?)?;
            std::fs::create_dir_all(&out_dir)?;
            std::fs::write(out_dir.join("parser.h"), arts.header)?;
            std::fs::write(out_dir.join("parser.c"), arts.source)?;
            eprintln!("wrote parser.h + parser.c to {}", out_dir.display());
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::Bpf { ir, out },
        } => {
            let c = pakeles::codegen::c::generate_bpf(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{c}");
            } else {
                std::fs::write(&out, c)?;
            }
            Ok(0)
        }
        Command::Gen {
            target: GenTarget::P4 { ir, out },
        } => {
            let p4 = pakeles::codegen::p4::generate_p4(&load_ir(&ir)?)?;
            if out.as_os_str() == "-" {
                print!("{p4}");
            } else {
                std::fs::write(&out, p4)?;
            }
            Ok(0)
        }
        Command::FmtIr { ir, out } => {
            let text = std::fs::read_to_string(&ir)
                .with_context(|| format!("reading IR from {}", ir.display()))?;
            let mut parsed = pakeles::ir::from_json(&text)?;
            pakeles::ir::canonicalize(&mut parsed);
            let canonical = pakeles::ir::to_json(&parsed)?;
            if out.as_os_str() == "-" {
                println!("{canonical}");
            } else {
                std::fs::write(&out, canonical)?;
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::main_with;

    /// Repo-root-relative path (tests run with CWD = pakeles-cli/).
    fn from_root(p: &str) -> String {
        format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn run_on_fixture_ok() {
        let code = main_with(&[
            "pakeles",
            "run",
            "--ir",
            &from_root("testdata/parsers/eth_ipvx_l4.ir.json"),
            "--pcap",
            &from_root("testdata/basic.pcap"),
        ])
        .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_tshark_on_fixture_green() {
        if std::process::Command::new("tshark")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: tshark not available");
            return;
        }
        let code = main_with(&[
            "pakeles",
            "diff",
            "tshark",
            "--ir",
            &from_root("testdata/parsers/eth_ipvx_l4.ir.json"),
            "--pcap",
            &from_root("testdata/basic.pcap"),
        ])
        .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn viz_ok() {
        let ir = from_root("testdata/parsers/eth_ipvx_l4.ir.json");
        assert_eq!(main_with(&["pakeles", "viz", "--ir", &ir]).unwrap(), 0);
    }

    #[test]
    fn fmt_ir_canonicalizes_mangled_json() {
        let ir = pakeles::ir::load(std::path::Path::new(&from_root(
            "testdata/parsers/eth_ipvx_l4.ir.json",
        )))
        .unwrap();
        let canonical = pakeles::ir::to_json(&ir).unwrap();
        // Same document, hostile formatting: compact everything.
        let mangled =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&canonical).unwrap())
                .unwrap();
        let dir = std::env::temp_dir().join("pakeles_fmt_ir");
        std::fs::create_dir_all(&dir).unwrap();
        let inp = dir.join("mangled.json");
        let outp = dir.join("out.json");
        std::fs::write(&inp, mangled).unwrap();
        let code = main_with(&[
            "pakeles",
            "fmt-ir",
            "--ir",
            inp.to_str().unwrap(),
            "--out",
            outp.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(std::fs::read_to_string(&outp).unwrap(), canonical);
    }
}

//! Phase-timed symex benchmark: enumeration vs witness solving, with the
//! feasibility-check telemetry from `EnumStats` and an optional path
//! inventory dump (kind + id per line) — the identity reference every
//! perf lever is verified against. Plan:
//! docs/plans/2026-07-28-symex-enum-perf.md.
//!
//! Usage: symex_bench <example> [--enum-only] [--inventory PATH]

use pakeles::symex::engine::{Enumeration, PathKind};
use pakeles::symex::testgen;
use std::time::Instant;

fn ir_for(name: &str) -> anyhow::Result<pakeles::ir::pb::Ir> {
    Ok(match name {
        "eth_ipvx_l4" => pakeles::examples::eth_ipvx_l4(),
        "linux_flow_dissector" => pakeles::examples::linux_flow_dissector(),
        "counted_items" => pakeles::examples::counted_items(),
        "dpdk_ptype" => pakeles::examples::dpdk_ptype(),
        "encap_proxy" => pakeles::builder::encap_proxy(),
        _ => anyhow::bail!("unknown example `{name}` (gallery names or `encap_proxy`)"),
    })
}

fn kind_str(k: &PathKind) -> String {
    match k {
        PathKind::Accept => "Accept".into(),
        PathKind::Truncation => "Truncation".into(),
        PathKind::Reject { reason } => format!("Reject:{reason}"),
    }
}

fn report_enum(e: &Enumeration, wall: std::time::Duration) {
    let count = |f: fn(&PathKind) -> bool| e.paths.iter().filter(|p| f(&p.kind)).count();
    println!("ENUM wall: {:.3}s", wall.as_secs_f64());
    println!(
        "ENUM paths: {} (accept {}, reject {}, trunc {})",
        e.paths.len(),
        count(|k| matches!(k, PathKind::Accept)),
        count(|k| matches!(k, PathKind::Reject { .. })),
        count(|k| matches!(k, PathKind::Truncation)),
    );
    let s = &e.stats;
    println!(
        "CHECKS: {} total ({} sat / {} unsat), wall {:.3}s",
        s.checks,
        s.sat,
        s.unsat,
        s.check_wall.as_secs_f64()
    );
    println!(
        "CHECKS symbolic (ExtractAt): {} calls, wall {:.3}s ({:.1}% of check wall)",
        s.symbolic_checks,
        s.symbolic_wall.as_secs_f64(),
        100.0 * s.symbolic_wall.as_secs_f64() / s.check_wall.as_secs_f64().max(1e-9),
    );
    let labels = ["<1ms", "<10ms", "<100ms", "<1s", "<10s", ">=10s"];
    let hist: Vec<String> = labels
        .iter()
        .zip(&s.hist)
        .map(|(l, n)| format!("{l}:{n}"))
        .collect();
    println!("CHECKS histogram: {}", hist.join(" "));
    println!(
        "WITNESSES: {} solves, wall {:.3}s, {} UNSAT ladder rungs burned",
        s.witnesses,
        s.witness_wall.as_secs_f64(),
        s.witness_unsat_rungs,
    );
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut name = None;
    let mut enum_only = false;
    let mut inventory = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--enum-only" => enum_only = true,
            "--inventory" => {
                inventory = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--inventory needs a path"))?
                        .clone(),
                )
            }
            _ => {
                anyhow::ensure!(name.is_none(), "unexpected arg `{a}`");
                name = Some(a.clone());
            }
        }
    }
    let name = name.ok_or_else(|| {
        anyhow::anyhow!("usage: symex_bench <example> [--enum-only] [--inventory PATH]")
    })?;
    let ir = ir_for(&name)?;

    let t0 = Instant::now();
    let e = testgen::enumerate_paths(&ir)?;
    let enum_wall = t0.elapsed();
    report_enum(&e, enum_wall);

    // Inventory before any solving: identity reference survives even if
    // the solve phase fails or is interrupted.
    if let Some(path) = &inventory {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut lines: Vec<String> = e
            .paths
            .iter()
            .map(|p| format!("{}\t{}", kind_str(&p.kind), p.id))
            .collect();
        lines.push(String::new()); // trailing newline
        std::fs::write(path, lines.join("\n"))?;
        println!("INVENTORY: {} paths -> {path}", e.paths.len());
    }

    if !enum_only {
        let t1 = Instant::now();
        let vectors = testgen::solve_all(&ir, &e.paths)?;
        let solve_wall = t1.elapsed();
        println!(
            "SOLVE wall: {:.3}s, {} vectors",
            solve_wall.as_secs_f64(),
            vectors.len()
        );
        println!("TOTAL wall: {:.3}s", t0.elapsed().as_secs_f64());
    }
    Ok(())
}

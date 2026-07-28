//! Vector assembly over enumerated paths. Witnesses are solved at emit
//! time by the engine's incremental session (constructed packets, free
//! bits zero); expected outputs come from the reference interpreter, so
//! the suite is self-checking against normative semantics by
//! construction.

use super::engine::{enumerate, Enumeration, Path, PathKind};
use super::z3solver::Z3Solver;
use crate::interp::{run_bits, FieldValue, Outcome};
use crate::ir::pb as irpb;
use crate::testvec::{pb, Bits};
use anyhow::{bail, Context, Result};

pub fn generate(ir: &irpb::Ir) -> Result<pb::TestSuite> {
    let enumeration = enumerate_paths(ir)?;
    let parser = ir.parser.as_ref().expect("validated");
    let vectors = solve_all(ir, &enumeration.paths)?;
    Ok(pb::TestSuite {
        parser_name: parser.name.clone(),
        ir_version: ir.ir_version.clone(),
        vectors,
    })
}

/// Enumeration phase only — the bench / phase-timing entry point, and the
/// source of the path inventory the perf plan uses as its identity
/// reference (see docs/superpowers/plans/2026-07-28-symex-enum-perf.md).
pub fn enumerate_paths(ir: &irpb::Ir) -> Result<Enumeration> {
    let mut solver = Z3Solver::new();
    enumerate(ir, &mut solver)
}

/// Assemble vectors from the witnesses the engine solved at emit time
/// (no z3 here — just the interp round-trip per path). Public alongside
/// `enumerate_paths` so the bench can time phases apart.
pub fn solve_all(ir: &irpb::Ir, paths: &[Path]) -> Result<Vec<pb::TestVector>> {
    paths
        .iter()
        .map(|path| vector_for(ir, path).with_context(|| path.id.clone()))
        .collect()
}

fn vector_for(ir: &irpb::Ir, path: &Path) -> Result<pb::TestVector> {
    let Some((bytes, bit_len)) = path.witness.clone() else {
        bail!("engine bug: enumerated path is UNSAT");
    };
    let bits = Bits { bytes, bit_len };
    let result = run_bits(ir, &bits)?;

    // The interpreter must agree with the path's own expectation —
    // any mismatch is a soundness bug in engine or interpreter.
    let (category, expected) = match (&path.kind, &result.outcome) {
        (PathKind::Accept, Outcome::Accept) => (
            pb::Category::Accept,
            pb::expected::Outcome::Accept(pb::Accepted {
                headers: result
                    .headers
                    .iter()
                    .map(|h| pb::ExpectedHeader {
                        instance: h.instance.clone(),
                        fields: h
                            .fields
                            .iter()
                            .map(|f| pb::ExpectedField {
                                name: f.name.clone(),
                                value: Some(match &f.value {
                                    FieldValue::Uint(u) => pb::expected_field::Value::Uint(*u),
                                    FieldValue::Bytes(b) => pb::expected_field::Value::BytesHex(
                                        crate::testvec::hex_encode(b),
                                    ),
                                }),
                            })
                            .collect(),
                    })
                    .collect(),
                metadata: result
                    .metadata
                    .iter()
                    .map(|(n, v)| pb::ExpectedMeta {
                        name: n.clone(),
                        value: *v,
                    })
                    .collect(),
            }),
        ),
        (PathKind::Reject { reason }, Outcome::Reject { reason: got }) if reason == got => (
            pb::Category::Reject,
            pb::expected::Outcome::Reject(pb::Rejected {
                reason: got.clone(),
            }),
        ),
        (PathKind::Truncation, Outcome::Reject { reason: got }) if got == "out of bounds" => (
            pb::Category::Truncation,
            pb::expected::Outcome::Reject(pb::Rejected {
                reason: got.clone(),
            }),
        ),
        (kind, outcome) => {
            bail!("soundness bug: path predicts {kind:?}, interpreter says {outcome:?}")
        }
    };

    Ok(pb::TestVector {
        id: path.id.clone(),
        category: category as i32,
        packet: Some(bits.to_pb()),
        expected: Some(pb::Expected {
            outcome: Some(expected),
        }),
    })
}

/// Replay a suite through the reference interpreter; returns mismatch
/// descriptions (empty = green). This — not solver re-runs — is the
/// CI-stable check for committed suites.
pub fn replay(ir: &irpb::Ir, suite: &pb::TestSuite) -> Result<Vec<String>> {
    let mut mismatches = Vec::new();
    for v in &suite.vectors {
        let Some(packet) = &v.packet else {
            mismatches.push(format!("{}: no packet", v.id));
            continue;
        };
        let (bits, warnings) = Bits::from_pb(packet);
        for w in warnings {
            mismatches.push(format!("{}: non-canonical packet: {w}", v.id));
        }
        let result = run_bits(ir, &bits)?;
        let expected = v.expected.as_ref().and_then(|e| e.outcome.as_ref());
        match (expected, &result.outcome) {
            (Some(pb::expected::Outcome::Reject(r)), Outcome::Reject { reason })
                if &r.reason == reason => {}
            (Some(pb::expected::Outcome::Accept(a)), Outcome::Accept) => {
                let got: Vec<pb::ExpectedHeader> = result
                    .headers
                    .iter()
                    .map(|h| pb::ExpectedHeader {
                        instance: h.instance.clone(),
                        fields: h
                            .fields
                            .iter()
                            .map(|f| pb::ExpectedField {
                                name: f.name.clone(),
                                value: Some(match &f.value {
                                    FieldValue::Uint(u) => pb::expected_field::Value::Uint(*u),
                                    FieldValue::Bytes(b) => pb::expected_field::Value::BytesHex(
                                        crate::testvec::hex_encode(b),
                                    ),
                                }),
                            })
                            .collect(),
                    })
                    .collect();
                if got != a.headers {
                    mismatches.push(format!("{}: field mismatch", v.id));
                }
                let got_meta: Vec<pb::ExpectedMeta> = result
                    .metadata
                    .iter()
                    .map(|(n, v)| pb::ExpectedMeta {
                        name: n.clone(),
                        value: *v,
                    })
                    .collect();
                if got_meta != a.metadata {
                    mismatches.push(format!("{}: metadata mismatch", v.id));
                }
            }
            (e, o) => mismatches.push(format!("{}: expected {e:?}, interpreter {o:?}", v.id)),
        }
    }
    Ok(mismatches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::examples::eth_ipvx_l4;

    #[test]
    fn example_suite_shape_and_replay() {
        let ir = eth_ipvx_l4();
        let suite = generate(&ir).unwrap();
        let by_cat = |c: pb::Category| {
            suite
                .vectors
                .iter()
                .filter(|v| v.category == c as i32)
                .count()
        };
        // Symbolic layout = one witness per control-flow path. Accepts:
        // ipv4->{tcp,udp} + ipv6->{tcp,udp} = 4 (ihl length no longer forks).
        // Rejects: 1 ipv4-options oob (ihl<5 wraps) + ipv4-default +
        // ipv6-default + eth-default = 4.
        assert_eq!(by_cat(pb::Category::Accept), 4);
        assert_eq!(by_cat(pb::Category::Reject), 4);
        assert!(by_cat(pb::Category::Truncation) > 0);
        // IDs unique and sorted.
        let ids: Vec<&str> = suite.vectors.iter().map(|v| v.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
        // Self-check: replay green.
        assert!(replay(&ir, &suite).unwrap().is_empty());
    }

    #[test]
    fn vectors_carry_and_replay_metadata() {
        let ir = crate::builder::meta_loop(); // shared test IR from Task 2
        let suite = generate(&ir).unwrap();
        let accepts: Vec<_> = suite
            .vectors
            .iter()
            .filter(|v| {
                matches!(
                    v.expected.as_ref().and_then(|e| e.outcome.as_ref()),
                    Some(pb::expected::Outcome::Accept(_))
                )
            })
            .collect();
        assert!(!accepts.is_empty());
        for v in &accepts {
            let Some(pb::expected::Outcome::Accept(a)) =
                v.expected.as_ref().and_then(|e| e.outcome.as_ref())
            else {
                unreachable!()
            };
            assert_eq!(
                a.metadata
                    .iter()
                    .map(|em| em.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["flag", "acc"], // declared order
            );
            assert_eq!(a.metadata[0].value, 1, "flag constant-written on s0");
            assert_eq!(a.metadata[1].value, 0, "loop exits only at acc==0");
        }
        assert!(replay(&ir, &suite).unwrap().is_empty());
    }

    #[test]
    fn committed_vectors_replay_green() {
        for name in ["eth_ipvx_l4", "counted_items"] {
            let ir = match name {
                "eth_ipvx_l4" => eth_ipvx_l4(),
                "counted_items" => crate::examples::counted_items(),
                _ => unreachable!(),
            };
            let Some(suite) = crate::testvec::committed_suite_or_skip(name) else {
                continue;
            };
            let mismatches = replay(&ir, &suite).unwrap();
            assert!(mismatches.is_empty(), "[{name}] {mismatches:#?}");
        }
    }
}

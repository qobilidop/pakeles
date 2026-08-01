//! Reference interpreter, reject mode. Normative semantics: what this
//! module does *is* what an IR description means.

mod bits;
mod eval;

use anyhow::Context;
use std::collections::HashMap;

use crate::ir::pb;
use bits::read_bits;
use eval::{eval_entry, eval_expr, Env};

/// Expression evaluation for sibling modules (pathid) — same semantics
/// the interpreter itself uses.
#[cfg(feature = "symex")]
pub(crate) fn eval_expr_pub(
    e: &pb::Expr,
    env: &std::collections::HashMap<(String, String), u64>,
) -> anyhow::Result<u64> {
    // bit_len can't reference metadata or remaining() (validator-
    // enforced), so the store is always empty and no region context
    // is needed here.
    eval_expr(e, env, &std::collections::HashMap::new(), None)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Accept,
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Uint(u64),
    /// Opaque bit run in canonical form: `ceil(bit_len/8)` bytes,
    /// MSB-first, trailing pad bits zero. The owning `ParsedField`'s
    /// `bit_len` is the authoritative length.
    Bits(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedField {
    pub name: String,
    pub bit_offset: usize,
    pub bit_len: usize,
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHeader {
    pub instance: String,
    pub header_type: String,
    pub start_bit: usize,
    pub fields: Vec<ParsedField>,
}

/// One transition decision, recorded per state entered.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceStep {
    pub state: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Arm(usize),
    Default,
    Direct,
    /// Parse ended inside this state (oob/depth) before any decision.
    None,
}

/// Diagnose-mode severity of a reject (from `Reject.annotations["severity"]`;
/// built-in rejects are always `Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Info,
}

/// Structured forensics for a reject: where the parse stopped and why.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub state: String,
    pub instance: Option<String>,
    pub field: Option<String>,
    pub bit_offset: usize,
    pub reason: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub outcome: Outcome,
    pub headers: Vec<ParsedHeader>,
    pub trace: Vec<TraceStep>,
    /// Present iff outcome is Reject.
    pub error: Option<ParseError>,
    /// Bits consumed when parsing stopped; payload/remainder is
    /// `consumed_bits..input.bit_len`.
    pub consumed_bits: usize,
    /// Final metadata values in declared order; empty when the parser
    /// declares none.
    pub metadata: Vec<(String, u64)>,
}

/// Run the parser over one byte-aligned packet. `Err` means the IR
/// itself is malformed; anything about the *packet* is a `Reject`.
pub fn run(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<ParseResult> {
    run_bits(ir, &crate::testvec::Bits::from_bytes(packet))
}

/// Bit-granular entry point (test vectors may end mid-byte).
pub fn run_bits(ir: &pb::Ir, input: &crate::testvec::Bits) -> anyhow::Result<ParseResult> {
    let packet = input.bytes.as_slice();
    let avail_bits = input.bit_len;
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let states: std::collections::HashMap<&str, &pb::State> =
        parser.states.iter().map(|s| (s.name.as_str(), s)).collect();
    let header_types: std::collections::HashMap<&str, &pb::HeaderType> = parser
        .header_types
        .iter()
        .map(|h| (h.name.as_str(), h))
        .collect();

    let mut headers = Vec::new();
    let mut trace: Vec<TraceStep> = Vec::new();
    let mut env = Env::new();
    let mut cursor_bits = 0usize;
    let mut depth = 0u32;
    let mut current = parser.start_state.as_str();
    // Sized-region stack: end bit offsets, innermost last. Reads are
    // bounded by min(top, avail_bits); see the sized-region design doc.
    let mut regions: Vec<usize> = Vec::new();

    let mut meta: HashMap<String, u64> = parser
        .metadata
        .iter()
        .map(|m| (m.name.clone(), m.init))
        .collect();
    let meta_bits: HashMap<&str, u32> = parser
        .metadata
        .iter()
        .map(|m| (m.name.as_str(), m.bits))
        .collect();

    struct RejectCtx {
        severity: Severity,
        instance: Option<String>,
        field: Option<String>,
    }

    let reject = |reason: &str,
                  ctx: RejectCtx,
                  state: &str,
                  bit_offset: usize,
                  headers: Vec<ParsedHeader>,
                  trace: Vec<TraceStep>,
                  metadata: Vec<(String, u64)>| {
        Ok(ParseResult {
            outcome: Outcome::Reject {
                reason: reason.into(),
            },
            headers,
            trace,
            error: Some(ParseError {
                state: state.to_string(),
                instance: ctx.instance,
                field: ctx.field,
                bit_offset,
                reason: reason.into(),
                severity: ctx.severity,
            }),
            consumed_bits: bit_offset,
            metadata,
        })
    };
    let plain = |severity: Severity| RejectCtx {
        severity,
        instance: None,
        field: None,
    };

    loop {
        depth += 1;
        trace.push(TraceStep {
            state: current.to_string(),
            decision: Decision::None,
        });
        if depth > parser.max_depth {
            return reject(
                "max depth exceeded",
                plain(Severity::Error),
                current,
                cursor_bits,
                headers,
                trace,
                final_meta(parser, &meta),
            );
        }
        let state = states
            .get(current)
            .ok_or_else(|| anyhow::anyhow!("unknown state `{current}`"))?;

        for ex in &state.extracts {
            let ht = header_types
                .get(ex.header_type.as_str())
                .ok_or_else(|| anyhow::anyhow!("unknown header type `{}`", ex.header_type))?;
            let instance = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            let mut parsed = ParsedHeader {
                instance: instance.clone(),
                header_type: ht.name.clone(),
                start_bit: cursor_bits,
                fields: Vec::new(),
            };
            for field in &ht.fields {
                let width = field
                    .width
                    .as_ref()
                    .and_then(|w| w.width.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("field `{}` has no width", field.name))?;
                // Reads are bounded by the innermost region end AND the
                // buffer. The reason rule is avail-free (design doc,
                // build-time refinements): crossing the region end (a
                // wrapped length crosses everything) is structural
                // ("out of region bounds"); any other failing read is
                // the truncation-class "out of bounds".
                let bound_bits = regions.last().map_or(avail_bits, |e| (*e).min(avail_bits));
                let oob_reason = |end_bits: Option<usize>| {
                    let crosses_region = regions
                        .last()
                        .is_some_and(|top| end_bits.is_none_or(|e| e > *top));
                    if crosses_region {
                        "out of region bounds"
                    } else {
                        "out of bounds"
                    }
                };
                match width {
                    pb::field_width::Width::Bits(n) => {
                        let n = *n as usize;
                        let Some(value) = read_bits(packet, bound_bits, cursor_bits, n) else {
                            let ctx = RejectCtx {
                                severity: Severity::Error,
                                instance: Some(instance.clone()),
                                field: Some(field.name.clone()),
                            };
                            headers.push(parsed);
                            return reject(
                                oob_reason(cursor_bits.checked_add(n)),
                                ctx,
                                current,
                                cursor_bits,
                                headers,
                                trace,
                                final_meta(parser, &meta),
                            );
                        };
                        env.insert((instance.clone(), field.name.clone()), value);
                        parsed.fields.push(ParsedField {
                            name: field.name.clone(),
                            bit_offset: cursor_bits,
                            bit_len: n,
                            value: FieldValue::Uint(value),
                        });
                        cursor_bits += n;
                    }
                    pb::field_width::Width::BitLen(expr) => {
                        // The length may be a wrapped u64 (e.g. ihl<5);
                        // checked math makes that an oob, not a panic.
                        let len_bits = eval_expr(expr, &env, &meta, None)?;
                        let end_bits = usize::try_from(len_bits)
                            .ok()
                            .and_then(|l| l.checked_add(cursor_bits));
                        if end_bits.is_none_or(|e| e > bound_bits) {
                            let ctx = RejectCtx {
                                severity: Severity::Error,
                                instance: Some(instance.clone()),
                                field: Some(field.name.clone()),
                            };
                            headers.push(parsed);
                            return reject(
                                oob_reason(end_bits),
                                ctx,
                                current,
                                cursor_bits,
                                headers,
                                trace,
                                final_meta(parser, &meta),
                            );
                        }
                        let len_bits = len_bits as usize;
                        parsed.fields.push(ParsedField {
                            name: field.name.clone(),
                            bit_offset: cursor_bits,
                            bit_len: len_bits,
                            value: FieldValue::Bits(bits::read_run(packet, cursor_bits, len_bits)),
                        });
                        cursor_bits += len_bits;
                    }
                }
            }
            headers.push(parsed);
        }

        // remaining() at this state's use points (assigns, region
        // pushes, select keys): STRUCTURAL bits to the innermost
        // region end — no buffer clamp (design doc, build-time
        // refinements). `None` (-> eval error) only when no region is
        // open (validator-enforced). `c <= top` is invariant (reads
        // never cross the region end), so the subtraction is exact.
        let remaining_here = |regions: &[usize], cursor_bits: usize| -> Option<u64> {
            let top = *regions.last()?;
            Some(top.saturating_sub(cursor_bits) as u64)
        };

        for a in &state.assigns {
            let v = eval_expr(
                a.value.as_ref().context("assign without value")?,
                &env,
                &meta,
                remaining_here(&regions, cursor_bits),
            )?;
            let bits = meta_bits
                .get(a.metadata.as_str())
                .copied()
                .ok_or_else(|| anyhow::anyhow!("unresolved assign target `{}`", a.metadata))?;
            let masked = if bits >= 64 {
                v
            } else {
                v & ((1u64 << bits) - 1)
            };
            meta.insert(a.metadata.clone(), masked);
        }

        for op in &state.region_ops {
            match op.kind.as_ref() {
                Some(pb::region_op::Kind::Push(e)) => {
                    let len = eval_expr(e, &env, &meta, remaining_here(&regions, cursor_bits))?;
                    // Structural check ONLY against the enclosing region
                    // (a region reaching past the buffer is a truncation
                    // found by reads, not a lie). Wrapped math is a lie.
                    let end = usize::try_from(len)
                        .ok()
                        .and_then(|l| l.checked_add(cursor_bits));
                    let structural_lie = match (end, regions.last()) {
                        (None, _) => true,
                        (Some(e), Some(top)) => e > *top,
                        (Some(_), None) => false,
                    };
                    if structural_lie {
                        return reject(
                            "region out of bounds",
                            plain(Severity::Error),
                            current,
                            cursor_bits,
                            headers,
                            trace,
                            final_meta(parser, &meta),
                        );
                    }
                    regions.push(end.expect("checked above"));
                }
                Some(pb::region_op::Kind::Pop(_)) => {
                    let end = regions
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("region pop with no open region"))?;
                    if cursor_bits < end {
                        // Exact-mode pop. A region end beyond the
                        // buffer is reachable here when the outer
                        // length lies past the buffer while all inner
                        // content is consistent (e.g. a TLS record
                        // length declaring more than was sent) — the
                        // incumbent semantic is "need more bytes", the
                        // truncation class. A region end within the
                        // buffer is real trailing content: structural.
                        let reason = if end > avail_bits {
                            "out of bounds"
                        } else {
                            "region not exhausted"
                        };
                        return reject(
                            reason,
                            plain(Severity::Error),
                            current,
                            cursor_bits,
                            headers,
                            trace,
                            final_meta(parser, &meta),
                        );
                    }
                }
                None => anyhow::bail!("empty region op"),
            }
        }

        let target = match state.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => anyhow::bail!("state `{current}` has no transition"),
            Some(pb::transition::Kind::Direct(t)) => {
                trace.last_mut().expect("state entered").decision = Decision::Direct;
                t
            }
            Some(pb::transition::Kind::Select(sel)) => {
                let mut keys = Vec::with_capacity(sel.keys.len());
                for k in &sel.keys {
                    keys.push(eval_expr(
                        k,
                        &env,
                        &meta,
                        remaining_here(&regions, cursor_bits),
                    )?);
                }
                let hit = sel.arms.iter().position(|arm| {
                    arm.entries.len() == keys.len()
                        && arm
                            .entries
                            .iter()
                            .zip(&keys)
                            .all(|(e, k)| eval_entry(e, *k))
                });
                match hit {
                    Some(i) => {
                        trace.last_mut().expect("state entered").decision = Decision::Arm(i);
                        sel.arms[i]
                            .next
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("select arm has no target"))?
                    }
                    None => {
                        trace.last_mut().expect("state entered").decision = Decision::Default;
                        match sel.default_target.as_ref() {
                            Some(t) => t,
                            None => {
                                return reject(
                                    "no matching select arm",
                                    plain(Severity::Error),
                                    current,
                                    cursor_bits,
                                    headers,
                                    trace,
                                    final_meta(parser, &meta),
                                )
                            }
                        }
                    }
                }
            }
        };

        match target.kind.as_ref() {
            Some(pb::target::Kind::State(name)) => current = name,
            Some(pb::target::Kind::Accept(_)) => {
                return Ok(ParseResult {
                    outcome: Outcome::Accept,
                    headers,
                    trace,
                    error: None,
                    consumed_bits: cursor_bits,
                    metadata: final_meta(parser, &meta),
                })
            }
            Some(pb::target::Kind::Reject(r)) => {
                let severity = match r.annotations.get("severity").map(String::as_str) {
                    Some("info") => Severity::Info,
                    _ => Severity::Error,
                };
                return reject(
                    &r.reason,
                    plain(severity),
                    current,
                    cursor_bits,
                    headers,
                    trace,
                    final_meta(parser, &meta),
                );
            }
            None => anyhow::bail!("empty target"),
        }
    }
}

/// Declared-order snapshot of a parser's metadata store, for `ParseResult`.
fn final_meta(parser: &pb::Parser, meta: &HashMap<String, u64>) -> Vec<(String, u64)> {
    parser
        .metadata
        .iter()
        .map(|m| (m.name.clone(), meta[m.name.as_str()]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::meta_loop; // shared test IR from Task 2
    use crate::builder::{
        arm, c, f, reject_info, to, v, HeaderTypeBuilder, ParserBuilder, StateBuilder,
    };
    use crate::fixtures::eth_ipvx_l4;
    use crate::fixtures::*;

    /// Minimal two-header IR for exercising engine mechanics without the
    /// gallery example: header `a` (16-bit tag) selects into header `b`
    /// (two 16-bit fields); tag 1 -> parse b -> accept, else reject(info).
    fn mini() -> pb::Ir {
        ParserBuilder::new("mini", 3)
            .header(HeaderTypeBuilder::new("a").bits("tag", 16))
            .header(HeaderTypeBuilder::new("b").bits("x", 16).bits("y", 16))
            .state(StateBuilder::new("s0").extract("a").select(
                vec![f("a", "tag")],
                vec![arm(vec![v(1)], to("s1"))],
                reject_info("unknown tag"),
            ))
            .state(StateBuilder::new("s1").extract("b").accept())
            .start("s0")
            .build()
            .unwrap()
    }

    #[test]
    fn metadata_accumulator_loop() {
        // n=2 -> two i-items then accept; flag set; acc counted down to 0.
        let res = run(&meta_loop(), &[2, 0xAA, 0xBB]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert_eq!(
            res.metadata,
            vec![("flag".to_string(), 1), ("acc".to_string(), 0)]
        );
        assert_eq!(res.headers.len(), 3); // h, i, i
    }

    #[test]
    fn metadata_init_and_zero_items() {
        // n=0 -> immediate accept; flag still written, acc = 0 via assignment.
        let res = run(&meta_loop(), &[0]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert_eq!(res.metadata[0], ("flag".to_string(), 1));
    }

    #[test]
    fn metadata_truncates_on_write() {
        // flag is 1 bit: writing 2 must store 0 (mod 2^1).
        let ir = ParserBuilder::new("trunc", 2)
            .meta("flag", 1, 0)
            .header(HeaderTypeBuilder::new("h").bits("x", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .assign("flag", c(2))
                    .accept(),
            )
            .start("s0")
            .build()
            .unwrap();
        let res = run(&ir, &[0]).unwrap();
        assert_eq!(res.metadata, vec![("flag".to_string(), 0)]);
    }

    #[test]
    fn metadata_loop_still_bounded_by_max_depth() {
        // n=200 can never finish within max_depth=6: depth reject, not a hang.
        let res = run(&meta_loop(), &[200, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(
            matches!(res.outcome, Outcome::Reject { ref reason } if reason == "max depth exceeded")
        );
    }

    #[test]
    fn example_smoke_accepts_and_rejects() {
        // One belt-and-suspenders check that the embedded example is
        // wired up; exhaustive behavior lives in the vector suite.
        let ir = eth_ipvx_l4();
        assert_eq!(run(&ir, &tcp_packet()).unwrap().outcome, Outcome::Accept);
        assert_eq!(
            run(&ir, &ipv6_tcp_packet()).unwrap().outcome,
            Outcome::Accept
        );
        assert_eq!(
            run(&ir, &icmp_packet()).unwrap().outcome,
            Outcome::Reject {
                reason: "unsupported ip protocol".into()
            }
        );
    }

    #[test]
    fn rejects_truncated_with_oob_forensics() {
        // 2 bytes: `a` extracts, `b` runs off the end mid-first-field.
        let res = run(&mini(), &[0x00, 0x01]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
        let err = res.error.unwrap();
        assert_eq!(err.state, "s1");
        assert_eq!(err.instance.as_deref(), Some("b"));
        assert_eq!(err.field.as_deref(), Some("x"));
        assert_eq!(err.bit_offset, 16);
        assert_eq!(err.severity, Severity::Error);
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn payload_boundary_reject_is_info() {
        // tag 2 misses the only arm -> default reject(info).
        let res = run(&mini(), &[0x00, 0x02]).unwrap();
        let err = res.error.unwrap();
        assert_eq!(err.severity, Severity::Info);
        assert_eq!(err.reason, "unknown tag");
        assert_eq!(res.consumed_bits, 16);
    }

    #[test]
    fn accept_has_no_error_and_full_consumption() {
        let res = run(&mini(), &[0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert!(res.error.is_none());
        assert_eq!(res.consumed_bits, 48);
    }

    #[test]
    fn interp_over_fixture_pcap() {
        let ir = eth_ipvx_l4();
        let packets =
            crate::pcapio::read_packets(&crate::test_repo_path("testdata/basic.pcap")).unwrap();
        let accepts: Vec<bool> = packets
            .iter()
            .map(|p| run(&ir, p).unwrap().outcome == Outcome::Accept)
            .collect();
        assert_eq!(accepts, vec![true, true, true, false]);
    }

    use crate::builder::tlv_mini;

    #[test]
    fn region_tlv_loop_accepts_exact_fill() {
        // total=4: two items (t,l=0)(t,l=0) fill the region exactly.
        let res = run(&tlv_mini(), &[4, 1, 0, 2, 0]).unwrap();
        assert_eq!(res.outcome, Outcome::Accept);
        assert_eq!(res.headers.len(), 3); // h + two items
        assert_eq!(res.consumed_bits, 40);
    }

    #[test]
    fn region_read_crossing_end_is_region_oob() {
        // total=3: item(t,l=0) leaves 1 byte; next item's `l` read
        // crosses the region end while the buffer continues.
        let res = run(&tlv_mini(), &[3, 1, 0, 5, 9, 9]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of region bounds".into()
            }
        );
        let err = res.error.unwrap();
        assert_eq!(err.field.as_deref(), Some("l"));
    }

    #[test]
    fn region_var_bytes_overrun_is_region_oob() {
        // total=3: item claims l=200, far past the region end but the
        // length itself is a structural lie -> region class.
        let res = run(&tlv_mini(), &[3, 1, 200, 9, 9, 9, 9]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of region bounds".into()
            }
        );
    }

    #[test]
    fn region_past_buffer_is_truncation_class() {
        // total=5 but the buffer ends after one item: structural
        // remaining()=3 keeps the loop going and the next read dies at
        // the BUFFER end (within the region), so this is the
        // truncation-class "out of bounds" (rustls: incomplete).
        let res = run(&tlv_mini(), &[5, 1, 0]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
        assert_eq!(res.error.unwrap().field.as_deref(), Some("t"));
    }

    #[test]
    fn pop_with_region_past_buffer_is_truncation_class() {
        // The region end lies beyond the buffer while everything read
        // so far was consistent: incumbent semantics say "need more
        // bytes" (e.g. rustls incomplete), so the exact-pop shortfall
        // is the truncation class here, not structural.
        let ir = ParserBuilder::new("lie_pop", 3)
            .header(HeaderTypeBuilder::new("h").bits("total", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .push_region(f("h", "total"))
                    .goto_(to("d")),
            )
            .state(StateBuilder::new("d").pop_region().accept())
            .start("s0")
            .build()
            .unwrap();
        let res = run(&ir, &[9, 0xAA]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "out of bounds".into()
            }
        );
    }

    #[test]
    fn pop_before_exhaustion_is_region_not_exhausted() {
        let ir = ParserBuilder::new("early_pop", 3)
            .header(HeaderTypeBuilder::new("h").bits("total", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .push_region(f("h", "total"))
                    .goto_(to("d")),
            )
            .state(StateBuilder::new("d").pop_region().accept())
            .start("s0")
            .build()
            .unwrap();
        let res = run(&ir, &[2, 0xAA, 0xBB]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "region not exhausted".into()
            }
        );
    }

    #[test]
    fn nested_push_overrun_is_region_out_of_bounds() {
        // Inner region (g.x=200 bytes) cannot fit the outer (total=2).
        let ir = ParserBuilder::new("nested_lie", 4)
            .header(HeaderTypeBuilder::new("h").bits("total", 8))
            .header(HeaderTypeBuilder::new("g").bits("x", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .push_region(f("h", "total"))
                    .goto_(to("s1")),
            )
            .state(
                StateBuilder::new("s1")
                    .extract("g")
                    .push_region(f("g", "x"))
                    .accept(),
            )
            .start("s0")
            .build()
            .unwrap();
        let res = run(&ir, &[2, 200, 9, 9]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "region out of bounds".into()
            }
        );
    }

    #[test]
    fn depth_bound_respected() {
        use crate::builder::{to, ParserBuilder, StateBuilder};
        let ir = ParserBuilder::new("loop", 3)
            .state(StateBuilder::new("s").goto_(to("s")))
            .start("s")
            .build()
            .unwrap();
        let res = run(&ir, &[]).unwrap();
        assert_eq!(
            res.outcome,
            Outcome::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }
}

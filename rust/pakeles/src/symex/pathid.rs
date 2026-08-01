//! Reconstruct the engine's path ID from a concrete interpreter run —
//! the bridge that lets `cov` map real packets onto enumerated paths.
//! Must mirror `engine.rs` segment construction exactly.

use crate::interp::{Decision, FieldValue, ParseResult};
use crate::ir::pb;

/// Engine's sanity ceiling, mirrored (see engine::SANITY_BITS).
const SANITY_BITS: u64 = 8 * 1024 * 1024;

pub fn path_id(ir: &pb::Ir, result: &ParseResult) -> anyhow::Result<String> {
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

    // Env of extracted fixed-width values, for evaluating length exprs.
    let mut env = std::collections::HashMap::new();
    for h in &result.headers {
        for f in &h.fields {
            if let FieldValue::Uint(u) = f.value {
                env.insert((h.instance.clone(), f.name.clone()), u);
            }
        }
    }

    let mut segments: Vec<String> = Vec::new();
    let mut headers = result.headers.iter();
    // Layout replay for region ops: cursor (advanced by parsed fields)
    // and the sized-region stack of end bit offsets, u128 to stay
    // wrap-free while classifying structural lies.
    let mut cursor_bits: u128 = 0;
    let mut regions: Vec<u128> = Vec::new();
    let region_reject = matches!(
        &result.outcome,
        crate::interp::Outcome::Reject { reason }
            if reason == "out of region bounds"
    );

    for (step_idx, step) in result.trace.iter().enumerate() {
        segments.push(step.state.clone());
        let last_step = step_idx == result.trace.len() - 1;
        // Depth-exceeded rejection: state entered, nothing else done.
        if last_step
            && step.decision == Decision::None
            && matches!(&result.outcome, crate::interp::Outcome::Reject{reason} if reason == "max depth exceeded")
        {
            break;
        }
        let state = states
            .get(step.state.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown state `{}`", step.state))?;
        for ex in &state.extracts {
            let ht = header_types
                .get(ex.header_type.as_str())
                .ok_or_else(|| anyhow::anyhow!("unknown header type `{}`", ex.header_type))?;
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            // E-Peek: a lookahead's fields advance a local cursor only.
            let entry_cursor = cursor_bits;
            let parsed = headers.next();
            for field in &ht.fields {
                let parsed_field =
                    parsed.and_then(|h| h.fields.iter().find(|f| f.name == field.name));
                match field.width.as_ref().and_then(|w| w.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(_)) => match parsed_field {
                        Some(pf) => cursor_bits = (pf.bit_offset + pf.bit_len) as u128,
                        None => {
                            // Reason-keyed: the interp already decided
                            // whether the region end or the buffer was
                            // crossed (avail-free rule).
                            if region_reject {
                                segments.push(format!("!roob@{inst}.{}", field.name));
                            } else {
                                segments.push(format!("!trunc@{inst}.{}", field.name));
                            }
                            return Ok(segments.join("/"));
                        }
                    },
                    Some(pb::field_width::Width::BitLen(expr)) => {
                        // A successful var-field read adds NO segment (the
                        // length is layout, not control flow). A failed read
                        // ends the path: `!roob` inside a region (reason-
                        // keyed), `!oob` if the length wraps/exceeds the
                        // sane max (matching engine's SANITY_BITS split),
                        // else `!trunc` (packet simply too short).
                        match parsed_field {
                            Some(pf) => cursor_bits = (pf.bit_offset + pf.bit_len) as u128,
                            None => {
                                if region_reject {
                                    segments.push(format!("!roob@{inst}.{}", field.name));
                                    return Ok(segments.join("/"));
                                }
                                let v = crate::interp::eval_expr_pub(expr, &env)?;
                                // Classify on the SAME quantity the engine
                                // splits on: `v > min(expr_max, SANITY_BITS)`.
                                // (Not `v + cursor` — that shifts the
                                // boundary by the cursor and diverges from the
                                // engine near ~1 MB lengths.)
                                let bound_bits: u64 = crate::codegen::p4::expr_max(expr, parser)?
                                    .min(SANITY_BITS as u128)
                                    as u64;
                                let oob_by_len = v > bound_bits;
                                if oob_by_len {
                                    segments.push(format!("!oob@{inst}.{}", field.name));
                                } else {
                                    segments.push(format!("!trunc@{inst}.{}", field.name));
                                }
                                return Ok(segments.join("/"));
                            }
                        }
                    }
                    None => anyhow::bail!("field `{}` has no width", field.name),
                }
            }
            if ex.lookahead {
                cursor_bits = entry_cursor;
            }
        }
        // Region ops (after extracts/assigns, before the decision):
        // replay pushes/pops against the layout to find the failing op
        // when the interp rejected here, otherwise to keep the stack
        // current for later remaining()/region checks.
        for (i, op) in state.region_ops.iter().enumerate() {
            match &op.kind {
                Some(pb::region_op::Kind::Push(e)) => {
                    let v = crate::interp::eval_expr_pub(e, &env)? as u128;
                    let bound_bits =
                        crate::codegen::p4::expr_max(e, parser)?.min(SANITY_BITS as u128);
                    let end = cursor_bits + v;
                    let lie = v > bound_bits || regions.last().is_some_and(|top| end > *top);
                    if lie {
                        segments.push(format!("!rpush@{}#{i}", step.state));
                        return Ok(segments.join("/"));
                    }
                    regions.push(end);
                }
                Some(pb::region_op::Kind::Pop(_)) => {
                    let end = regions
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("region pop with no open region"))?;
                    if cursor_bits < end {
                        segments.push(format!("!rtrail@{}#{i}", step.state));
                        return Ok(segments.join("/"));
                    }
                }
                None => {}
            }
        }
        match step.decision {
            Decision::Arm(i) => segments.push(format!("arm{i}")),
            Decision::Default => segments.push("default".into()),
            Decision::Direct | Decision::None => {}
        }
    }
    Ok(segments.join("/"))
}

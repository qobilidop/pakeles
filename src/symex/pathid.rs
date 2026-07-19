//! Reconstruct the engine's path ID from a concrete interpreter run —
//! the bridge that lets `cov` map real packets onto enumerated paths.
//! Must mirror `engine.rs` segment construction exactly.

use crate::interp::{Decision, FieldValue, ParseResult};
use crate::ir::pb;

/// Engine's sanity bound, mirrored (see engine::SANITY_BITS).
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
    let mut cursor_bits: u64 = 0;

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
            let inst = if ex.instance.is_empty() { &ex.header_type } else { &ex.instance };
            let parsed = headers.next();
            for field in &ht.fields {
                let parsed_field =
                    parsed.and_then(|h| h.fields.iter().find(|f| f.name == field.name));
                match field.width.as_ref().and_then(|w| w.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(n)) => match parsed_field {
                        Some(_) => cursor_bits += u64::from(*n),
                        None => {
                            segments.push(format!("!trunc@{inst}.{}", field.name));
                            return Ok(segments.join("/"));
                        }
                    },
                    Some(pb::field_width::Width::ByteLen(expr)) => {
                        // Length is derivable from already-extracted
                        // fields whether or not the read succeeded.
                        let v = crate::interp::eval_expr_pub(expr, &env)?;
                        segments.push(format!("{inst}.{}={v}B", field.name));
                        let oob_by_len = v
                            .checked_mul(8)
                            .and_then(|b| b.checked_add(cursor_bits))
                            .is_none_or(|end| end > SANITY_BITS);
                        match parsed_field {
                            Some(_) => cursor_bits += v * 8,
                            None => {
                                if !oob_by_len {
                                    segments.push(format!("!trunc@{inst}.{}", field.name));
                                }
                                return Ok(segments.join("/"));
                            }
                        }
                    }
                    None => anyhow::bail!("field `{}` has no width", field.name),
                }
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

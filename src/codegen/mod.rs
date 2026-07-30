//! Backend code generators: Wireshark Lua, portable C99, eBPF C, P4-16.

pub mod c;
pub mod lua;
pub mod p4;

use crate::ir::pb;
use std::collections::HashMap;

/// True when any state carries sized-region ops. Backends that do not
/// (yet) lower regions must refuse such IR loudly — silently ignoring
/// region ops would miscompile.
pub(crate) fn has_region_ops(parser: &pb::Parser) -> bool {
    parser.states.iter().any(|s| !s.region_ops.is_empty())
}

/// Static state-entry bit alignment (mod 8): fixpoint over the graph.
/// `Some(a)` = every entry arrives with cursor ≡ a (mod 8); `None` =
/// conflicting or unknown. Shared by the Lua backend (which needs
/// byte-aligned ranges for `ProtoField`s) and the C/eBPF backend
/// (which emits byte loads instead of bit loops when it can prove
/// alignment).
pub(crate) fn entry_alignments(parser: &pb::Parser) -> HashMap<String, Option<u32>> {
    let states: HashMap<&str, &pb::State> =
        parser.states.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut align: HashMap<String, Option<u32>> = HashMap::new();
    align.insert(parser.start_state.clone(), Some(0));
    let mut work = vec![parser.start_state.clone()];
    while let Some(name) = work.pop() {
        let Some(state) = states.get(name.as_str()) else {
            continue;
        };
        let entry = align[&name];
        // Alignment delta across the state: fixed widths only (var
        // fields add whole bytes — alignment-preserving).
        let mut delta = 0u32;
        for ex in &state.extracts {
            if let Some(ht) = parser
                .header_types
                .iter()
                .find(|h| h.name == ex.header_type)
            {
                for f in &ht.fields {
                    if let Some(pb::field_width::Width::Bits(n)) =
                        f.width.as_ref().and_then(|w| w.width.as_ref())
                    {
                        delta = (delta + n) % 8;
                    }
                }
            }
        }
        let exit = entry.map(|a| (a + delta) % 8);
        for succ in successor_states(state) {
            let merged = match align.get(&succ) {
                None => exit,
                Some(prev) if *prev == exit => continue,
                Some(_) => None,
            };
            align.insert(succ.clone(), merged);
            work.push(succ);
        }
    }
    align
}

pub(crate) fn successor_states(s: &pb::State) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |t: &pb::Target| {
        if let Some(pb::target::Kind::State(n)) = &t.kind {
            out.push(n.clone());
        }
    };
    match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
        Some(pb::transition::Kind::Direct(t)) => push(t),
        Some(pb::transition::Kind::Select(sel)) => {
            for arm in &sel.arms {
                if let Some(t) = &arm.next {
                    push(t);
                }
            }
            if let Some(t) = &sel.default_target {
                push(t);
            }
        }
        None => {}
    }
    out
}

/// Absolute alignment (mod 8) of a field's start, if statically known.
pub(crate) fn field_alignment(
    parser: &pb::Parser,
    entry_align: &HashMap<String, Option<u32>>,
    state: &pb::State,
    inst: &str,
    field_name: &str,
) -> Option<u32> {
    let entry = (*entry_align.get(&state.name)?)?;
    let mut off = entry;
    for ex in &state.extracts {
        let ht = parser
            .header_types
            .iter()
            .find(|h| h.name == ex.header_type)?;
        let this_inst = if ex.instance.is_empty() {
            ex.header_type.as_str()
        } else {
            ex.instance.as_str()
        };
        for f in &ht.fields {
            if this_inst == inst && f.name == field_name {
                return Some(off % 8);
            }
            if let Some(pb::field_width::Width::Bits(n)) =
                f.width.as_ref().and_then(|w| w.width.as_ref())
            {
                off = (off + n) % 8;
            }
            // var fields: whole bytes, alignment unchanged
        }
    }
    None
}

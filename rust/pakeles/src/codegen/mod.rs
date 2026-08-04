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

/// The normative semantics take a shift's right operand modulo 64
/// (`docs/reference/ir-semantics.md` §Expressions). No target language
/// does that on its own — C calls a shift past the width undefined, P4
/// and SMT bitvectors yield 0, Lua computes a float — so every backend
/// masks the amount to reproduce the spec.
///
/// The mask is skipped when the amount is a constant that is already in
/// range, which is every shift the gallery actually authors: `x << 3`
/// stays `x << 3` rather than becoming `x << (3 & 63)`.
pub(crate) fn shift_amount_needs_mask(e: &pb::Expr) -> bool {
    !matches!(e.kind.as_ref(), Some(pb::expr::Kind::Constant(v)) if *v < 64)
}

/// Derived per-program demands against backend envelopes — the
/// capability side of the refusal-marker culture, surfaced by
/// `pakeles lint` as information (never findings; a demand is a fact
/// about the program, not a defect). Each entry names the demand and
/// the backends that refuse it.
pub fn demand_report(parser: &pb::Parser) -> Vec<String> {
    let mut out = Vec::new();
    if has_region_ops(parser) {
        out.push("sized regions / remaining() — gen p4 refuses (no P4-16 lowering)".to_string());
    }
    // BMv2 refuses header types that are not a byte multiple. A
    // peek-only instance is padded (never extracted, so padding is
    // free); an extracted one cannot be, so its `gen p4` output is
    // valid P4-16 that `p4c-bm2-ss` will reject. Report it rather
    // than silently emitting an uncompilable program.
    let mut peeked_only: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut consumed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for s in &parser.states {
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                ex.header_type.as_str()
            } else {
                ex.instance.as_str()
            };
            if ex.lookahead {
                peeked_only.insert(inst);
            } else {
                consumed.insert(inst);
            }
        }
    }
    let mut odd: Vec<String> = Vec::new();
    for ht in &parser.header_types {
        let fixed: u32 = ht
            .fields
            .iter()
            .filter_map(|f| match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                Some(pb::field_width::Width::Bits(n)) => Some(*n),
                _ => None,
            })
            .sum();
        let all_fixed = ht.fields.iter().all(|f| {
            matches!(
                f.width.as_ref().and_then(|w| w.width.as_ref()),
                Some(pb::field_width::Width::Bits(_))
            )
        });
        if all_fixed && !fixed.is_multiple_of(8) && consumed.contains(ht.name.as_str()) {
            odd.push(format!("{} ({fixed} bits)", ht.name));
        }
    }
    if !odd.is_empty() {
        out.push(format!(
            "extracted header types that are not a byte multiple ({}) — valid P4-16, \
             but p4c-bm2-ss refuses them; a peeked type would be padded instead",
            odd.join(", ")
        ));
    }
    let misaligned = misaligned_var_runs(parser);
    if !misaligned.is_empty() {
        out.push(format!(
            "misaligned or bit-granular var runs ({}) — byte-surface backends refuse \
             (Lua tvb ranges, C harness hex printing); parse cores stay bit-exact",
            misaligned.join(", ")
        ));
    }
    out
}

/// Static value of an expression mod 8, when derivable. This is the
/// core of the (advisory) alignment analysis: since 8 divides 2^64,
/// residues mod 8 are preserved by the IR's wrapping +, -, and ×, and
/// bitwise ops only mix low bits with low bits — so the analysis is
/// sound even over expressions that wrap. The load-bearing case is
/// `expr * 8` (the frontends' byte-length sugar), which is ≡ 0
/// regardless of `expr`. `None` = not statically known.
pub(crate) fn expr_mod8(e: &pb::Expr) -> Option<u32> {
    match e.kind.as_ref()? {
        pb::expr::Kind::Constant(v) => Some((v % 8) as u32),
        pb::expr::Kind::Field(_) | pb::expr::Kind::Metadata(_) => None,
        // remaining() is bits to the region end: known only via the
        // region system, which this expression-local analysis cannot
        // see. (A region pushed as bytes keeps remaining() ≡ cursor
        // distance — still not expression-local.)
        pb::expr::Kind::Remaining(_) => None,
        pb::expr::Kind::Bin(b) => {
            let op = pb::BinOpKind::try_from(b.op).ok()?;
            let l = b.lhs.as_deref().and_then(expr_mod8);
            let r = b.rhs.as_deref().and_then(expr_mod8);
            match op {
                pb::BinOpKind::Add => Some((l? + r?) % 8),
                pb::BinOpKind::Sub => Some((l? + 8 - r?) % 8),
                pb::BinOpKind::Mul => match (l, r) {
                    // A provably ≡0 factor zeroes the product — the ×8
                    // sugar path, independent of the other factor.
                    (Some(0), _) | (_, Some(0)) => Some(0),
                    (Some(a), Some(b)) => Some((a * b) % 8),
                    _ => None,
                },
                // Shift counts are taken mod 64 and must be literal
                // constants to be known; a shift by >= 3 multiplies by
                // a multiple of 8.
                pb::BinOpKind::Shl => match b.rhs.as_deref().and_then(|r| r.kind.as_ref()) {
                    Some(pb::expr::Kind::Constant(k)) => {
                        let k = k % 64;
                        if k >= 3 {
                            Some(0)
                        } else {
                            Some((l? << k) % 8)
                        }
                    }
                    _ => None,
                },
                // Low bits of a right shift depend on higher input bits.
                pb::BinOpKind::Shr => None,
                // Bitwise: low 3 bits depend only on low 3 bits.
                pb::BinOpKind::And => Some(l? & r?),
                pb::BinOpKind::Or => Some(l? | r?),
                pb::BinOpKind::Unspecified => None,
            }
        }
    }
}

/// Constant value of an expression, when it folds statically (wrapping
/// u64 arithmetic, mirroring evaluation semantics). Lets backends type
/// fixed-length byte runs (`fixed_bytes(16, ..., IPV6)` folds to 128).
pub(crate) fn expr_const(e: &pb::Expr) -> Option<u64> {
    match e.kind.as_ref()? {
        pb::expr::Kind::Constant(v) => Some(*v),
        pb::expr::Kind::Bin(b) => {
            let l = expr_const(b.lhs.as_deref()?)?;
            let r = expr_const(b.rhs.as_deref()?)?;
            match pb::BinOpKind::try_from(b.op).ok()? {
                pb::BinOpKind::Add => Some(l.wrapping_add(r)),
                pb::BinOpKind::Sub => Some(l.wrapping_sub(r)),
                pb::BinOpKind::Mul => Some(l.wrapping_mul(r)),
                pb::BinOpKind::Shl => Some(l.wrapping_shl(r as u32)),
                pb::BinOpKind::Shr => Some(l.wrapping_shr(r as u32)),
                pb::BinOpKind::And => Some(l & r),
                pb::BinOpKind::Or => Some(l | r),
                pb::BinOpKind::Unspecified => None,
            }
        }
        _ => None,
    }
}

/// Static state-entry bit alignment (mod 8): fixpoint over the graph.
/// `Some(a)` = every entry arrives with cursor ≡ a (mod 8); `None` =
/// conflicting or unknown. Shared by the Lua backend (which needs
/// byte-aligned ranges for `ProtoField`s) and the C/eBPF backend
/// (which emits byte loads instead of bit loops when it can prove
/// alignment). Purely advisory: soundness of no backend depends on it
/// — an unknown alignment only costs the byte-load fast path or, for
/// backends whose *host surface* is byte-addressed (Lua tvb ranges,
/// the C harness's hex printing), a loud refusal.
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
        // Alignment delta across the state: fixed widths plus each var
        // field's statically-derived length residue (None poisons —
        // a data-dependent residue makes every later offset unknown).
        let mut delta = Some(0u32);
        for ex in &state.extracts {
            if ex.lookahead {
                continue; // E-Peek: the cursor is restored — no delta
            }
            if let Some(ht) = parser
                .header_types
                .iter()
                .find(|h| h.name == ex.header_type)
            {
                for f in &ht.fields {
                    match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                        Some(pb::field_width::Width::Bits(n)) => {
                            delta = delta.map(|d| (d + n) % 8);
                        }
                        Some(pb::field_width::Width::BitLen(e)) => {
                            delta = match (delta, expr_mod8(e)) {
                                (Some(d), Some(m)) => Some((d + m) % 8),
                                _ => None,
                            };
                        }
                        None => delta = None,
                    }
                }
            }
        }
        let exit = match (entry, delta) {
            (Some(a), Some(d)) => Some((a + d) % 8),
            _ => None,
        };
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

/// Var-run sites (state, instance, field) whose start alignment or
/// whole-byte length cannot be statically proven — the derived
/// "requires misaligned runs" capability. Byte-surface backends (Lua
/// tvb ranges, the C harness's byte-hex printing) refuse these; the
/// parse cores themselves are bit-exact at any alignment.
pub(crate) fn misaligned_var_runs(parser: &pb::Parser) -> Vec<String> {
    let entry_align = entry_alignments(parser);
    let mut out = Vec::new();
    for s in &parser.states {
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            let Some(ht) = parser
                .header_types
                .iter()
                .find(|h| h.name == ex.header_type)
            else {
                continue;
            };
            for f in &ht.fields {
                if let Some(pb::field_width::Width::BitLen(e)) =
                    f.width.as_ref().and_then(|w| w.width.as_ref())
                {
                    let aligned_start =
                        field_alignment(parser, &entry_align, s, inst, &f.name) == Some(0);
                    let whole_bytes = expr_mod8(e) == Some(0);
                    if !aligned_start || !whole_bytes {
                        out.push(format!("{}/{inst}.{}", s.name, f.name));
                    }
                }
            }
        }
    }
    out
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
        // A lookahead's fields sit at the current cursor but leave it
        // unmoved for the extracts that follow.
        let mut local = off;
        for f in &ht.fields {
            if this_inst == inst && f.name == field_name {
                return Some(local % 8);
            }
            match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                Some(pb::field_width::Width::Bits(n)) => local = (local + n) % 8,
                // Var fields advance by their length's static residue,
                // if any (×8-sugar lengths are ≡ 0).
                Some(pb::field_width::Width::BitLen(e)) => local = (local + expr_mod8(e)?) % 8,
                None => return None,
            }
        }
        if !ex.lookahead {
            off = local;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::*;

    #[test]
    fn mod8_sees_through_the_byte_sugar() {
        // expr * 8 is ≡ 0 whatever the expr — the load-bearing case.
        assert_eq!(expr_mod8(&mul(f("h", "len"), c(8))), Some(0));
        assert_eq!(expr_mod8(&mul(c(8), f("h", "len"))), Some(0));
        // Wrapping-safe residues: 8 | 2^64, so mod-8 survives wrap.
        assert_eq!(
            expr_mod8(&sub(c(3), c(5))),
            Some((3u64.wrapping_sub(5) % 8) as u32)
        );
        // Shift by >= 3 multiplies by a multiple of 8.
        assert_eq!(expr_mod8(&shl(f("h", "len"), c(3))), Some(0));
        assert_eq!(expr_mod8(&shl(f("h", "len"), c(2))), None);
        // Data-dependent lengths are unknown.
        assert_eq!(expr_mod8(&f("h", "len")), None);
        assert_eq!(expr_mod8(&add(f("h", "len"), c(2))), None);
    }

    #[test]
    fn const_lengths_fold() {
        assert_eq!(expr_const(&mul(c(16), c(8))), Some(128));
        assert_eq!(expr_const(&f("h", "len")), None);
    }

    fn var_run_ir(bit_len: crate::ir::pb::Expr) -> crate::ir::ValidatedIr {
        ParserBuilder::new("vr", 2)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 8)
                    .var_bits("body", bit_len),
            )
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap()
    }

    #[test]
    fn byte_sugar_runs_are_provably_aligned() {
        let ir = var_run_ir(mul(f("h", "n"), c(8)));
        let parser = ir.parser.as_ref().unwrap();
        assert!(misaligned_var_runs(parser).is_empty());
        assert!(demand_report(parser).is_empty());
    }

    #[test]
    fn bit_granular_runs_are_a_derived_demand() {
        let ir = var_run_ir(f("h", "n"));
        let parser = ir.parser.as_ref().unwrap();
        assert_eq!(misaligned_var_runs(parser), vec!["s/h.body".to_string()]);
        let demands = demand_report(parser);
        assert_eq!(demands.len(), 1);
        assert!(demands[0].contains("bit-granular var runs"), "{demands:?}");
    }

    #[test]
    fn unknown_run_residue_poisons_later_alignment() {
        // After a data-dependent bit run, successor entry alignment is
        // unknown (None), so the byte-load fast path degrades — never
        // misfires.
        let ir = ParserBuilder::new("poison", 3)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 8)
                    .var_bits("body", f("h", "n")),
            )
            .header(HeaderTypeBuilder::new("g").bits("x", 8))
            .state(StateBuilder::new("s").extract("h").goto_(to("t")))
            .state(StateBuilder::new("t").extract("g").accept())
            .start("s")
            .build()
            .unwrap();
        let parser = ir.parser.as_ref().unwrap();
        let align = entry_alignments(parser);
        assert_eq!(align["s"], Some(0));
        assert_eq!(align["t"], None);
    }
}

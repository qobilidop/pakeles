//! Path enumeration with symbolic layout.
//!
//! Control-flow *path* is decoupled from concrete *layout*: variable-length
//! fields do NOT fork per length value. Field offsets and the per-path total
//! length are symbolic `Term`s over one packet bitvector; a var-length field
//! forks control flow only into {continue, body-truncation, out-of-bounds}.
//! `testgen` solves one minimal witness per path. A concrete `cursor_max`
//! width budget (via interval arithmetic) keeps each per-path solve tight.

use super::solver::{Constraint, Solver, Term};
use crate::codegen::p4::expr_max;
use crate::ir::pb;
use std::collections::{HashMap, HashSet};

/// Ceiling on a materializable var-length body: the per-field bound is
/// `min(interval-max, SANITY_BYTES)`. A length above it (a wrapping expr like
/// ihl<5 -> ~2^64 bytes, or a genuinely huge field) is a semantic reject
/// ("out of bounds"), not a layout to build; it also caps the width budget so
/// the packet BV stays finite. Mirrored by `pathid` (same `min(expr_max,
/// SANITY_BYTES)` classifier) so engine and path-id agree per witness.
const SANITY_BITS: usize = 8 * 1024 * 1024;
const SANITY_BYTES: u64 = (SANITY_BITS / 8) as u64;

/// Max times a cyclic state may be entered per path during testgen. A
/// self-loop (e.g. IPv6 option chains) otherwise forks exponentially in
/// loop depth (~arms^depth), so we cap unrolling to a small constant.
/// At 2, this generates 0/1/2 option-header vectors — exercising loop
/// entry, the self-loop taken twice (stack depth 2), and
/// opt→opt→{frag,tcp,udp} — which is sufficient backend coverage, while
/// roughly halving the loop's path contribution vs 3 (which produced
/// ~7346 vectors for the looped example). Deeper chains are a documented
/// divergence covered by the kernel-agreement corpus. This is a coverage
/// bound, NOT parser behavior — over-cap unrollings emit no vector (not a
/// reject). Coexists with the global `max_depth` reject.
const TESTGEN_LOOP_UNROLL: u32 = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum PathKind {
    Accept,
    Reject { reason: String },
    Truncation,
}

#[derive(Debug, Clone)]
pub struct Path {
    pub id: String,
    pub kind: PathKind,
    /// Symbolic total packet length for this path (bits). Solved (and
    /// minimized) into a concrete length by `testgen`.
    pub(crate) bit_len: Term,
    /// Concrete upper bound on `bit_len` (bits) — the packet-BV width the
    /// witness solve runs over. Sound because every var-length is bounded
    /// by its expression's interval max.
    pub(crate) width: usize,
    pub(crate) constraints: Vec<Constraint>,
}

// Term arithmetic helpers for building symbolic offsets / lengths.
// (`t_` prefixed to avoid clashing with the `builder::{add,sub,mul}` Expr
// constructors glob-imported in the test module.)
fn t_cst(v: u64) -> Term {
    Term::Const(v)
}
fn t_add(a: Term, b: Term) -> Term {
    Term::Bin(pb::BinOpKind::Add, Box::new(a), Box::new(b))
}
fn t_sub(a: Term, b: Term) -> Term {
    Term::Bin(pb::BinOpKind::Sub, Box::new(a), Box::new(b))
}
fn t_mul(a: Term, b: Term) -> Term {
    Term::Bin(pb::BinOpKind::Mul, Box::new(a), Box::new(b))
}

/// Feasibility byproducts consumed by lint.
#[derive(Debug, Default)]
pub struct FeasibilityLog {
    pub reached_states: HashSet<String>,
    /// (state, arm index) attempted at a reached select.
    pub attempted_arms: HashSet<(String, usize)>,
    /// (state, arm index) feasible in at least one context.
    pub feasible_arms: HashSet<(String, usize)>,
}

pub struct Enumeration {
    pub paths: Vec<Path>,
    pub log: FeasibilityLog,
}

struct Ctx<'a> {
    parser: &'a pb::Parser,
    states: HashMap<&'a str, &'a pb::State>,
    header_types: HashMap<&'a str, &'a pb::HeaderType>,
    solver: &'a mut dyn Solver,
    paths: Vec<Path>,
    log: FeasibilityLog,
    /// States reachable from themselves via the transition graph. A
    /// var-length field on such a state forks only min+max witnesses so
    /// loop enumeration stays tractable (see `walk_extracts`).
    cyclic_states: HashSet<String>,
}

#[derive(Clone)]
struct Frame {
    /// Symbolic bit offset of the parse cursor (starts `Const(0)`).
    cursor: Term,
    /// Concrete upper bound on `cursor` (bits) — the width budget.
    cursor_max: usize,
    placed: HashMap<(String, String), (Term, usize)>, // (inst,field) -> (off_term, len)
    constraints: Vec<Constraint>,
    segments: Vec<String>,
    depth: u32,
    /// Per-path entry count for each cyclic state (loop-unroll cap).
    loop_counts: HashMap<String, u32>,
}

impl Default for Frame {
    fn default() -> Self {
        Frame {
            cursor: t_cst(0),
            cursor_max: 0,
            placed: HashMap::new(),
            constraints: Vec::new(),
            segments: Vec::new(),
            depth: 0,
            loop_counts: HashMap::new(),
        }
    }
}

pub(crate) fn enumerate(ir: &pb::Ir, solver: &mut dyn Solver) -> anyhow::Result<Enumeration> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let mut ctx = Ctx {
        parser,
        states: parser.states.iter().map(|s| (s.name.as_str(), s)).collect(),
        header_types: parser
            .header_types
            .iter()
            .map(|h| (h.name.as_str(), h))
            .collect(),
        solver,
        paths: Vec::new(),
        log: FeasibilityLog::default(),
        cyclic_states: cyclic_states(parser),
    };
    let frame = Frame::default();
    walk_state(&mut ctx, &parser.start_state, frame)?;
    ctx.paths.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Enumeration {
        paths: ctx.paths,
        log: ctx.log,
    })
}

/// State names that lie on a cycle (reachable from themselves) via the
/// transition graph: Direct target, Select arm targets, and Select
/// default. Accept/Reject targets contribute no edge.
fn cyclic_states(parser: &pb::Parser) -> HashSet<String> {
    fn target_state(t: &pb::Target) -> Option<&str> {
        match t.kind.as_ref() {
            Some(pb::target::Kind::State(n)) => Some(n.as_str()),
            _ => None,
        }
    }
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for s in &parser.states {
        let mut outs = Vec::new();
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => outs.extend(target_state(t)),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = arm.next.as_ref() {
                        outs.extend(target_state(t));
                    }
                }
                if let Some(t) = sel.default_target.as_ref() {
                    outs.extend(target_state(t));
                }
            }
            None => {}
        }
        succ.insert(s.name.as_str(), outs);
    }
    // A state is cyclic iff it can reach itself. BFS from its successors.
    let mut cyclic = HashSet::new();
    for s in &parser.states {
        let start = s.name.as_str();
        let mut stack: Vec<&str> = succ.get(start).cloned().unwrap_or_default();
        let mut seen: HashSet<&str> = HashSet::new();
        while let Some(cur) = stack.pop() {
            if cur == start {
                cyclic.insert(start.to_string());
                break;
            }
            if seen.insert(cur) {
                stack.extend(succ.get(cur).into_iter().flatten().copied());
            }
        }
    }
    cyclic
}

fn term_of_expr(e: &pb::Expr, frame: &Frame) -> anyhow::Result<Term> {
    match e.kind.as_ref() {
        Some(pb::expr::Kind::Constant(v)) => Ok(Term::Const(*v)),
        Some(pb::expr::Kind::Field(r)) => {
            let (off_term, len) = frame
                .placed
                .get(&(r.header.clone(), r.field.clone()))
                .ok_or_else(|| {
                    anyhow::anyhow!("unresolved field ref `{}.{}`", r.header, r.field)
                })?;
            // Concrete offset -> the cheap Extract; symbolic (a field after a
            // var-length region) -> ExtractAt.
            Ok(match off_term {
                Term::Const(c) => Term::Extract {
                    bit_off: *c as usize,
                    len: *len,
                },
                _ => Term::ExtractAt {
                    off: Box::new(off_term.clone()),
                    len: *len,
                },
            })
        }
        Some(pb::expr::Kind::Bin(b)) => {
            let op = pb::BinOpKind::try_from(b.op)
                .map_err(|_| anyhow::anyhow!("unknown binop {}", b.op))?;
            let l = term_of_expr(
                b.lhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
                frame,
            )?;
            let r = term_of_expr(
                b.rhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
                frame,
            )?;
            Ok(Term::Bin(op, Box::new(l), Box::new(r)))
        }
        None => anyhow::bail!("empty expression"),
    }
}

fn entry_constraint(entry: &pb::KeysetEntry, key: Term) -> Constraint {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => Constraint::Eq(key, *v),
        Some(pb::keyset_entry::Kind::Masked(m)) => Constraint::Masked(key, m.value, m.mask),
        Some(pb::keyset_entry::Kind::Range(r)) => Constraint::InRange(key, r.lo, r.hi),
        // An empty entry matches nothing (mirror interp's eval_entry).
        None => Constraint::Not(Box::new(Constraint::And(vec![]))),
    }
}

fn emit(ctx: &mut Ctx, frame: &Frame, kind: PathKind, bit_len: Term, width: usize) {
    ctx.paths.push(Path {
        id: frame.segments.join("/"),
        kind,
        bit_len,
        width,
        constraints: frame.constraints.clone(),
    });
}

fn walk_state(ctx: &mut Ctx, state_name: &str, mut frame: Frame) -> anyhow::Result<()> {
    frame.depth += 1;
    frame.segments.push(state_name.to_string());
    if frame.depth > ctx.parser.max_depth {
        emit(
            ctx,
            &frame,
            PathKind::Reject {
                reason: "max depth exceeded".into(),
            },
            frame.cursor.clone(),
            frame.cursor_max,
        );
        return Ok(());
    }
    // Testgen loop-unroll cap: a cyclic state may be entered at most
    // TESTGEN_LOOP_UNROLL times per path. Over-cap unrollings are pruned
    // with NO vector emitted (a coverage bound, not parser behavior — the
    // real parser would keep going, so we do not emit a reject). Checked
    // after the `max_depth` reject so that global bound still applies;
    // acyclic states are unaffected.
    if ctx.cyclic_states.contains(state_name) {
        let count = frame.loop_counts.entry(state_name.to_string()).or_insert(0);
        if *count >= TESTGEN_LOOP_UNROLL {
            return Ok(());
        }
        *count += 1;
    }
    ctx.log.reached_states.insert(state_name.to_string());
    let state = *ctx
        .states
        .get(state_name)
        .ok_or_else(|| anyhow::anyhow!("unknown state `{state_name}`"))?;

    // Flatten this state's extracts into (instance, header_type field) work items.
    let mut items: Vec<(String, pb::Field)> = Vec::new();
    for ex in &state.extracts {
        let ht = *ctx
            .header_types
            .get(ex.header_type.as_str())
            .ok_or_else(|| anyhow::anyhow!("unknown header type `{}`", ex.header_type))?;
        let inst = if ex.instance.is_empty() {
            ex.header_type.clone()
        } else {
            ex.instance.clone()
        };
        for f in &ht.fields {
            items.push((inst.clone(), f.clone()));
        }
    }
    walk_extracts(ctx, state, &items, 0, frame)
}

fn walk_extracts(
    ctx: &mut Ctx,
    state: &pb::State,
    items: &[(String, pb::Field)],
    idx: usize,
    mut frame: Frame,
) -> anyhow::Result<()> {
    if idx == items.len() {
        return walk_transition(ctx, state, frame);
    }
    let (inst, field) = &items[idx];
    match field.width.as_ref().and_then(|w| w.width.as_ref()) {
        Some(pb::field_width::Width::Bits(n)) => {
            let n = *n as usize;
            // Truncation fork: packet ends before this field is fully read.
            {
                let mut t = frame.clone();
                t.segments.push(format!("!trunc@{inst}.{}", field.name));
                // avail = cursor + n - 1: one bit short of the field.
                emit(
                    ctx,
                    &t,
                    PathKind::Truncation,
                    t_add(frame.cursor.clone(), t_cst((n - 1) as u64)),
                    frame.cursor_max + n,
                );
            }
            frame.placed.insert(
                (inst.clone(), field.name.clone()),
                (frame.cursor.clone(), n),
            );
            frame.cursor = t_add(frame.cursor, t_cst(n as u64));
            frame.cursor_max += n;
            walk_extracts(ctx, state, items, idx + 1, frame)
        }
        Some(pb::field_width::Width::ByteLen(expr)) => {
            // No per-value forking: the body length stays symbolic. Fork
            // control flow only into {out-of-bounds, body-truncation,
            // continue}. The oob/continue split is at SANITY_BYTES, matching
            // pathid; the width budget uses the tighter interval max.
            let len_term = term_of_expr(expr, &frame)?;
            // Bound the body by `min(interval-max, SANITY)`. This is the single
            // quantity that keeps THREE things consistent: (a) the oob/continue
            // split matches pathid (which mirrors `bound_bytes`); (b) the width
            // budget `8*bound_bytes <= SANITY_BITS` is a sound upper bound on
            // the continue branch's body AND never overflows `usize`/`u32` even
            // if `expr_max` (a u128) is astronomically large; (c) a wrapped or
            // oversized length lands in the oob branch, so no feasible continue
            // layout ever exceeds the width. `expr_max` alone would be unsound
            // for add/mul-wrap into `(expr_max, SANITY_BYTES]`.
            let bound_bytes: u64 = expr_max(expr, ctx.parser)?.min(SANITY_BYTES as u128) as u64;
            let bound_bits: usize = bound_bytes as usize * 8;

            // Out-of-bounds reject: length wraps / exceeds `bound_bytes`
            // (feasible only when the expr can wrap, e.g. ihl<5, or exceed the
            // sane cap; z3 prunes it otherwise). Short witness -> interp
            // "out of bounds".
            {
                let mut oob = frame.clone();
                oob.constraints.push(Constraint::InRange(
                    len_term.clone(),
                    bound_bytes + 1,
                    u64::MAX,
                ));
                if ctx
                    .solver
                    .check(oob.cursor_max.max(1), &oob.constraints)
                    .is_some()
                {
                    oob.segments.push(format!("!oob@{inst}.{}", field.name));
                    emit(
                        ctx,
                        &oob,
                        PathKind::Reject {
                            reason: "out of bounds".into(),
                        },
                        frame.cursor.clone(),
                        frame.cursor_max,
                    );
                }
            }

            // The continue world is the non-wrapping, within-bound lengths.
            frame
                .constraints
                .push(Constraint::InRange(len_term.clone(), 0, bound_bytes));

            // Body-truncation: packet ends inside a non-empty body.
            {
                let mut t = frame.clone();
                t.constraints
                    .push(Constraint::InRange(len_term.clone(), 1, bound_bytes));
                if ctx
                    .solver
                    .check(t.cursor_max.max(1), &t.constraints)
                    .is_some()
                {
                    t.segments.push(format!("!trunc@{inst}.{}", field.name));
                    // avail = cursor + 8*len - 1: one bit short of the body.
                    let bl = t_sub(
                        t_add(frame.cursor.clone(), t_mul(t_cst(8), len_term.clone())),
                        t_cst(1),
                    );
                    emit(
                        ctx,
                        &t,
                        PathKind::Truncation,
                        bl,
                        frame.cursor_max + bound_bits,
                    );
                }
            }

            // Continue: consume the opaque body (not placeable for refs).
            frame.cursor = t_add(frame.cursor, t_mul(t_cst(8), len_term));
            frame.cursor_max += bound_bits;
            walk_extracts(ctx, state, items, idx + 1, frame)
        }
        None => anyhow::bail!("field `{}` has no width", field.name),
    }
}

fn walk_target(ctx: &mut Ctx, target: &pb::Target, frame: Frame) -> anyhow::Result<()> {
    match target.kind.as_ref() {
        Some(pb::target::Kind::State(name)) => walk_state(ctx, name, frame),
        Some(pb::target::Kind::Accept(_)) => {
            emit(
                ctx,
                &frame,
                PathKind::Accept,
                frame.cursor.clone(),
                frame.cursor_max,
            );
            Ok(())
        }
        Some(pb::target::Kind::Reject(r)) => {
            emit(
                ctx,
                &frame,
                PathKind::Reject {
                    reason: r.reason.clone(),
                },
                frame.cursor.clone(),
                frame.cursor_max,
            );
            Ok(())
        }
        None => anyhow::bail!("empty target"),
    }
}

fn walk_transition(ctx: &mut Ctx, state: &pb::State, frame: Frame) -> anyhow::Result<()> {
    match state.transition.as_ref().and_then(|t| t.kind.as_ref()) {
        None => anyhow::bail!("state `{}` has no transition", state.name),
        Some(pb::transition::Kind::Direct(t)) => walk_target(ctx, t, frame),
        Some(pb::transition::Kind::Select(sel)) => {
            let keys: Vec<Term> = sel
                .keys
                .iter()
                .map(|k| term_of_expr(k, &frame))
                .collect::<anyhow::Result<_>>()?;
            let arm_conds: Vec<Constraint> = sel
                .arms
                .iter()
                .map(|arm| {
                    Constraint::And(
                        arm.entries
                            .iter()
                            .zip(&keys)
                            .map(|(e, k)| entry_constraint(e, k.clone()))
                            .collect(),
                    )
                })
                .collect();
            for (i, arm) in sel.arms.iter().enumerate() {
                ctx.log.attempted_arms.insert((state.name.clone(), i));
                let mut child = frame.clone();
                child.constraints.push(arm_conds[i].clone());
                for cond in arm_conds.iter().take(i) {
                    child
                        .constraints
                        .push(Constraint::Not(Box::new(cond.clone())));
                }
                if ctx
                    .solver
                    .check(child.cursor_max.max(1), &child.constraints)
                    .is_none()
                {
                    continue; // infeasible in this context; lint sees it via the log
                }
                ctx.log.feasible_arms.insert((state.name.clone(), i));
                child.segments.push(format!("arm{i}"));
                let target = arm
                    .next
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("select arm has no target"))?;
                walk_target(ctx, target, child)?;
            }
            // Default: all arms negated.
            let mut child = frame;
            for cond in &arm_conds {
                child
                    .constraints
                    .push(Constraint::Not(Box::new(cond.clone())));
            }
            if ctx
                .solver
                .check(child.cursor_max.max(1), &child.constraints)
                .is_some()
            {
                child.segments.push("default".into());
                match sel.default_target.as_ref() {
                    Some(t) => walk_target(ctx, t, child)?,
                    None => {
                        emit(
                            ctx,
                            &child,
                            PathKind::Reject {
                                reason: "no matching select arm".into(),
                            },
                            child.cursor.clone(),
                            child.cursor_max,
                        );
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::*;
    use crate::symex::z3solver::Z3Solver;

    fn enumerate_ir(ir: &pb::Ir) -> Enumeration {
        let mut solver = Z3Solver::new();
        enumerate(ir, &mut solver).unwrap()
    }

    fn count(paths: &[Path], kind: fn(&PathKind) -> bool) -> usize {
        paths.iter().filter(|p| kind(&p.kind)).count()
    }

    #[test]
    fn linear_accept() {
        let ir = ParserBuilder::new("lin", 1)
            .header(HeaderTypeBuilder::new("h").bits("a", 8))
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 2); // accept + trunc@h.a
        assert_eq!(count(&e.paths, |k| *k == PathKind::Accept), 1);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Truncation), 1);
        let accept = e.paths.iter().find(|p| p.kind == PathKind::Accept).unwrap();
        assert_eq!(accept.id, "s");
        // Symbolic bit_len solves to the concrete 8-bit length.
        let mut solver = Z3Solver::new();
        let (_b, bit_len) = solver
            .solve_witness(accept.width, &accept.constraints, &accept.bit_len)
            .unwrap();
        assert_eq!(bit_len, 8);
    }

    #[test]
    fn select_forks() {
        let ir = ParserBuilder::new("sel", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![v(1)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .start("a")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        let ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a/!trunc@h.f", "a/arm0/b", "a/default"]);
    }

    #[test]
    fn shadowed_arm_pruned_and_logged() {
        let ir = ParserBuilder::new("shadow", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![range(0, 255)], to("b")), arm(vec![v(3)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .start("a")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        // arm1 shadowed, default infeasible: only trunc + arm0 remain.
        let ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a/!trunc@h.f", "a/arm0/b"]);
        assert!(e.log.attempted_arms.contains(&("a".into(), 1)));
        assert!(!e.log.feasible_arms.contains(&("a".into(), 1)));
    }

    #[test]
    fn depth_bound_emits_reject() {
        // `s` is a cyclic state, so the loop-unroll cap also gates it; with
        // max_depth == TESTGEN_LOOP_UNROLL the entry that would exceed depth
        // is reached first and the global max_depth reject still fires
        // (checked before the cap), proving the two bounds coexist.
        let md = TESTGEN_LOOP_UNROLL;
        let ir = ParserBuilder::new("loop", md)
            .state(StateBuilder::new("s").goto_(to("s")))
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 1);
        // `s` repeated (md + 1) times: the (md+1)th entry trips max_depth.
        let expected_id = vec!["s"; md as usize + 1].join("/");
        assert_eq!(e.paths[0].id, expected_id);
        assert_eq!(
            e.paths[0].kind,
            PathKind::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }

    #[test]
    fn max_depth_reject_on_acyclic_chain() {
        // A purely ACYCLIC chain longer than max_depth: no state is cyclic,
        // so the loop-unroll cap never applies — the max_depth reject fires
        // on its own. This decouples the global bound from
        // TESTGEN_LOOP_UNROLL (unlike `depth_bound_emits_reject`, which
        // couples cap == max_depth on a self-loop).
        let ir = ParserBuilder::new("chain", 2)
            .state(StateBuilder::new("s0").goto_(to("s1")))
            .state(StateBuilder::new("s1").goto_(to("s2")))
            .state(StateBuilder::new("s2").goto_(to("s3")))
            .state(StateBuilder::new("s3").accept())
            .start("s0")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(e.paths.len(), 1);
        // s0(1) -> s1(2) -> s2(3 > max_depth 2): reject at the 3rd state entered.
        assert_eq!(e.paths[0].id, "s0/s1/s2");
        assert_eq!(
            e.paths[0].kind,
            PathKind::Reject {
                reason: "max depth exceeded".into()
            }
        );
    }

    #[test]
    fn length_forking() {
        // h { n: 2 bits, body: n bytes }: symbolic layout -> ONE accept
        // (continue), one bits-trunc on `n`, one body-trunc. No per-value
        // fork, and no oob path (len = n is a 2-bit value, never wraps).
        let ir = ParserBuilder::new("varlen", 1)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 2)
                    .var_bytes("body", f("h", "n")),
            )
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Accept), 1);
        assert_eq!(count(&e.paths, |k| *k == PathKind::Truncation), 2);
        let mut ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["s", "s/!trunc@h.body", "s/!trunc@h.n"]);
        // The accept witness solves to n=0 (minimized) -> just the 2-bit
        // header, no body.
        let accept = e.paths.iter().find(|p| p.kind == PathKind::Accept).unwrap();
        let mut solver = Z3Solver::new();
        let (_b, bit_len) = solver
            .solve_witness(accept.width, &accept.constraints, &accept.bit_len)
            .unwrap();
        assert_eq!(bit_len, 2);
    }

    #[test]
    fn wrapping_length_forks_out_of_bounds() {
        // ihl-style body length `n*4 - 20` on a 4-bit field: n<5 wraps to a
        // huge u64 -> the oob branch is feasible (a distinct `!oob` reject),
        // while n>=5 gives a small non-wrapping body (continue -> accept).
        let ir = ParserBuilder::new("ihl", 1)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 4)
                    .var_bytes("body", sub(mul(f("h", "n"), c(4)), c(20))),
            )
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        let ids: std::collections::BTreeSet<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains("s/!oob@h.body"), "missing oob path: {ids:?}");
        assert!(ids.contains("s"), "missing accept path: {ids:?}");
        // The oob path really does reject.
        let oob = e.paths.iter().find(|p| p.id == "s/!oob@h.body").unwrap();
        assert_eq!(
            oob.kind,
            PathKind::Reject {
                reason: "out of bounds".into()
            }
        );
    }

    #[test]
    fn cyclic_loop_unroll_capped_for_testgen() {
        // Same self-loop as above but with a LARGE max_depth: the loop
        // forks ~exponentially in loop depth (two branches recurse), so
        // without the unroll cap this explodes / hangs. The cap bounds
        // per-path entries of the cyclic `opt` state to
        // TESTGEN_LOOP_UNROLL, keeping enumeration small and fast — the
        // test terminating quickly IS the perf proof.
        let ir = ParserBuilder::new("optloop", 12)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("len", 4)
                    .var_bytes("body", f("h", "len")),
            )
            .state(StateBuilder::new("opt").extract("h").select(
                vec![f("h", "len")],
                vec![arm(vec![v(0)], accept())],
                to("opt"),
            ))
            .start("opt")
            .build()
            .unwrap();
        let e = enumerate_ir(&ir);
        // Bounded, small path count despite max_depth=12.
        assert!(
            e.paths.len() < 64,
            "expected a bounded path count, got {}",
            e.paths.len()
        );
        assert!(!e.paths.is_empty());
        // No single path enters the cyclic state more than the cap.
        let max_entries = e
            .paths
            .iter()
            .map(|p| p.id.split('/').filter(|seg| *seg == "opt").count())
            .max()
            .unwrap();
        assert!(
            max_entries <= TESTGEN_LOOP_UNROLL as usize,
            "cyclic state entered {max_entries} times, cap is {TESTGEN_LOOP_UNROLL}"
        );
        assert_eq!(max_entries, TESTGEN_LOOP_UNROLL as usize);
    }
}

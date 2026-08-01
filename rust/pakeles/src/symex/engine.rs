//! Path enumeration with symbolic layout.
//!
//! Control-flow *path* is decoupled from concrete *layout*: variable-length
//! fields do NOT fork per length value. Field offsets and the per-path total
//! length are symbolic `Term`s; a var-length field forks control flow only
//! into {continue, body-truncation, out-of-bounds}.
//!
//! Solving is INCREMENTAL: one `Session` mirrors the DFS — every fork
//! pushes a scope, asserts its constraint delta, and pops on backtrack,
//! so the solver stack always equals the current frame's constraint
//! vector and z3 reuses learned state across the prefix-heavy query
//! stream. Each emitted path's witness (small by the length ladder) is
//! extracted at emit time from the hot stack; `testgen` only assembles
//! vectors and interp-verifies.

use super::solver::{Constraint, Session, Solver, Term};
use crate::codegen::p4::expr_max;
use crate::ir::pb;
use std::collections::{HashMap, HashSet};

/// Ceiling on a materializable var-length body: the per-field bound is
/// `min(interval-max, SANITY_BITS)`. A length above it (a wrapping expr like
/// ihl<5 -> ~2^64 bits, or a genuinely huge field) is a semantic reject
/// ("out of bounds"), not a layout to build; it also caps the width budget so
/// the packet BV stays finite. Mirrored by `pathid` (same `min(expr_max,
/// SANITY_BITS)` classifier) so engine and path-id agree per witness.
const SANITY_BITS: usize = 8 * 1024 * 1024;

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
    /// `(packet_bytes, bit_len)` solved at emit time from the session's
    /// hot stack (the path's symbolic bit-length term, minimized by the
    /// ladder, evaluated in the model). Always `Some` for a correctly-
    /// enumerated path (the stack was feasible at emit); `testgen` bails
    /// otherwise.
    pub(crate) witness: Option<(Vec<u8>, usize)>,
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

/// `a > b` over cursor/region-end terms via the wrap window: both sides
/// are bounded far below 2^32 under the path constraints (cursor_max <=
/// SANITY_BITS, region ends <= cursor + SANITY_BITS), so `a - b`
/// lands in [1, WINDOW] exactly when a > b and wraps to >= 2^64 - WINDOW
/// otherwise. Same idiom as the wrapped-length oob split.
const REGION_CMP_WINDOW: u64 = 1 << 32;
fn t_gt(a: Term, b: Term) -> Constraint {
    Constraint::InRange(t_sub(a, b), 1, REGION_CMP_WINDOW)
}

/// OR of constraints via De Morgan (the solver core stays And/Not).
fn c_or(mut cs: Vec<Constraint>) -> Constraint {
    if cs.len() == 1 {
        return cs.pop().expect("len checked");
    }
    Constraint::Not(Box::new(Constraint::And(
        cs.into_iter()
            .map(|c| Constraint::Not(Box::new(c)))
            .collect(),
    )))
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
    pub stats: EnumStats,
}

/// Feasibility-check telemetry for the perf work (always collected; the
/// bookkeeping is nanoseconds against solver calls that run µs–minutes).
/// "Symbolic" = the constraint set contains an `ExtractAt` (a read at a
/// symbolic offset) — the fragment a ground fast path cannot decide.
#[derive(Debug, Default)]
pub struct EnumStats {
    pub checks: u64,
    pub check_wall: std::time::Duration,
    pub symbolic_checks: u64,
    pub symbolic_wall: std::time::Duration,
    pub sat: u64,
    pub unsat: u64,
    /// Check-duration histogram: <1ms, <10ms, <100ms, <1s, <10s, >=10s.
    pub hist: [u64; 6],
    /// Emit-time witness solves: count, wall, and how many ladder rungs
    /// were burned on UNSAT before the succeeding one (rung-skipping
    /// telemetry).
    pub witnesses: u64,
    pub witness_wall: std::time::Duration,
    pub witness_unsat_rungs: u64,
}

/// Wrap-safe interval of a term's value: reads span their declared
/// width, and any node where 64-bit wrapping is possible collapses to
/// `(0, u64::MAX)` — wrapping can make large operands produce SMALL
/// values, so a potential wrap invalidates a positive lower bound (a
/// lower bound of 0 is always safe; the min feeds witness-ladder rung
/// skipping, where an under-estimate only costs a doomed rung attempt).
fn term_interval(t: &Term) -> (u64, u64) {
    const WRAPPED: (u64, u64) = (0, u64::MAX);
    let cap = |min: u128, max: u128| {
        if max > u64::MAX as u128 {
            WRAPPED
        } else {
            (min as u64, max as u64)
        }
    };
    match t {
        Term::Const(v) => (*v, *v),
        Term::Extract { len, .. } | Term::ExtractAt { len, .. } => {
            if *len >= 64 {
                (0, u64::MAX)
            } else {
                (0, (1u64 << len) - 1)
            }
        }
        Term::Bin(op, l, r) => {
            let (lmin, lmax) = term_interval(l);
            let (rmin, rmax) = term_interval(r);
            let (lmin, lmax, rmin, rmax) = (lmin as u128, lmax as u128, rmin as u128, rmax as u128);
            match op {
                pb::BinOpKind::Add => cap(lmin + rmin, lmax + rmax),
                pb::BinOpKind::Sub => {
                    if lmin >= rmax {
                        (lmin as u64 - rmax as u64, lmax as u64 - rmin as u64)
                    } else {
                        WRAPPED // underflow possible
                    }
                }
                pb::BinOpKind::Mul => cap(lmin * rmin, lmax * rmax),
                pb::BinOpKind::Shl => match lmax.checked_shl(rmax.min(127) as u32) {
                    Some(max) => cap(lmin << rmin.min(127), max),
                    None => WRAPPED,
                },
                pb::BinOpKind::Shr => (
                    (lmin >> rmax.min(127)) as u64,
                    (lmax >> rmin.min(127)) as u64,
                ),
                pb::BinOpKind::And => (0, lmax.min(rmax) as u64),
                pb::BinOpKind::Or => cap(lmin.max(rmin), lmax + rmax),
                pb::BinOpKind::Unspecified => unreachable!("validated IR"),
            }
        }
    }
}

fn term_has_extract_at(t: &Term) -> bool {
    match t {
        Term::ExtractAt { .. } => true,
        Term::Bin(_, l, r) => term_has_extract_at(l) || term_has_extract_at(r),
        Term::Const(_) | Term::Extract { .. } => false,
    }
}

fn constraint_has_extract_at(c: &Constraint) -> bool {
    match c {
        Constraint::Eq(t, _) | Constraint::Masked(t, _, _) | Constraint::InRange(t, _, _) => {
            term_has_extract_at(t)
        }
        Constraint::Not(inner) => constraint_has_extract_at(inner),
        Constraint::And(cs) => cs.iter().any(constraint_has_extract_at),
    }
}

struct Ctx<'a> {
    parser: &'a pb::Parser,
    states: HashMap<&'a str, &'a pb::State>,
    header_types: HashMap<&'a str, &'a pb::HeaderType>,
    session: Box<dyn Session + 'a>,
    paths: Vec<Path>,
    log: FeasibilityLog,
    /// States reachable from themselves via the transition graph. A
    /// var-length field on such a state forks only min+max witnesses so
    /// loop enumeration stays tractable (see `walk_extracts`).
    cyclic_states: HashSet<String>,
    /// Declared metadata field widths, keyed by name — used to mask
    /// assignment results to their declared width.
    meta_bits: HashMap<String, u32>,
    stats: EnumStats,
}

impl Ctx<'_> {
    /// All feasibility checks go through here so the stats see every
    /// call. The session stack already holds `cs` (scope discipline);
    /// `cs`/`packet_bits` feed classification and the cross-check.
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> bool {
        let t0 = std::time::Instant::now();
        let sat = self.session.check(packet_bits, cs);
        let dt = t0.elapsed();
        let s = &mut self.stats;
        s.checks += 1;
        s.check_wall += dt;
        if cs.iter().any(constraint_has_extract_at) {
            s.symbolic_checks += 1;
            s.symbolic_wall += dt;
        }
        if sat {
            s.sat += 1;
        } else {
            s.unsat += 1;
        }
        let ms = dt.as_millis();
        let bucket = match ms {
            0 => 0,
            1..=9 => 1,
            10..=99 => 2,
            100..=999 => 3,
            1000..=9999 => 4,
            _ => 5,
        };
        s.hist[bucket] += 1;
        sat
    }
}

#[derive(Clone)]
struct Frame {
    /// Symbolic bit offset of the parse cursor (starts `Const(0)`).
    cursor: Term,
    /// Concrete upper bound on `cursor` (bits) — the width budget.
    cursor_max: usize,
    /// Concrete LOWER bound on `cursor` (bits): fixed widths only, var
    /// bodies count 0. Lets the witness ladder skip statically-doomed
    /// small rungs (a deep tunnel prefix's fixed headers alone can
    /// exceed the 128B first rung). An under-estimate is safe — it only
    /// costs a provably-UNSAT rung attempt.
    cursor_min: usize,
    placed: HashMap<(String, String), (Term, usize)>, // (inst,field) -> (off_term, len)
    constraints: Vec<Constraint>,
    segments: Vec<String>,
    depth: u32,
    /// Per-path entry count for each cyclic state (loop-unroll cap).
    loop_counts: HashMap<String, u32>,
    /// Current symbolic value of each declared metadata field, by name.
    /// Substitution store: assignment replaces the entry (masked to
    /// width); reads clone the current term. Seeded from declared inits
    /// at the root frame (see `enumerate`); `default()` stays empty.
    meta: HashMap<String, Term>,
    /// Sized-region stack: symbolic end bit offsets, innermost last
    /// (see the sized-region design doc, build-time refinements).
    regions: Vec<Term>,
}

impl Default for Frame {
    fn default() -> Self {
        Frame {
            cursor: t_cst(0),
            cursor_max: 0,
            cursor_min: 0,
            placed: HashMap::new(),
            constraints: Vec::new(),
            segments: Vec::new(),
            depth: 0,
            loop_counts: HashMap::new(),
            meta: HashMap::new(),
            regions: Vec::new(),
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
        session: solver.session(),
        paths: Vec::new(),
        log: FeasibilityLog::default(),
        cyclic_states: cyclic_states(parser),
        meta_bits: parser
            .metadata
            .iter()
            .map(|md| (md.name.clone(), md.bits))
            .collect(),
        stats: EnumStats::default(),
    };
    let frame = Frame {
        meta: parser
            .metadata
            .iter()
            .map(|md| (md.name.clone(), t_cst(md.init)))
            .collect(),
        ..Frame::default()
    };
    walk_state(&mut ctx, &parser.start_state, frame)?;
    ctx.paths.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Enumeration {
        paths: ctx.paths,
        log: ctx.log,
        stats: ctx.stats,
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
        // Structural: top - cursor, in bits; exact because
        // cursor <= top holds on continue worlds.
        Some(pb::expr::Kind::Remaining(_)) => {
            let top = frame
                .regions
                .last()
                .ok_or_else(|| anyhow::anyhow!("remaining() with no open region"))?;
            Ok(t_sub(top.clone(), frame.cursor.clone()))
        }
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
        Some(pb::expr::Kind::Metadata(r)) => frame
            .meta
            .get(&r.name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unresolved metadata ref `{}`", r.name)),
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

fn emit(ctx: &mut Ctx, frame: &Frame, kind: PathKind, bit_len: Term, min_bits: usize) {
    // The session stack equals `frame.constraints` here (scope
    // discipline), so the witness comes from hot solver state.
    let t0 = std::time::Instant::now();
    let (witness, rungs_tried) = ctx.session.witness(&frame.constraints, &bit_len, min_bits);
    ctx.stats.witnesses += 1;
    ctx.stats.witness_wall += t0.elapsed();
    ctx.stats.witness_unsat_rungs += rungs_tried.saturating_sub(1) as u64;
    ctx.paths.push(Path {
        id: frame.segments.join("/"),
        kind,
        witness,
    });
    // Progress heartbeat for long regens (stderr; cargo test captures it).
    // Tunnel-scale enumerations run for hours — silence reads as a hang.
    if ctx.paths.len().is_multiple_of(25) {
        eprintln!("ENUM PROGRESS: {} paths", ctx.paths.len());
    }
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
            frame.cursor_min,
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
            // Region trichotomy (design doc, build-time refinements):
            // {crosses the innermost region end -> structural reject,
            // fits the region but the buffer ends mid-field ->
            // truncation, fits -> continue}. Without a region, only the
            // latter two exist.
            let mut scoped = false;
            if let Some(top) = frame.regions.last().cloned() {
                let end = t_add(frame.cursor.clone(), t_cst(n as u64));
                let cross = t_gt(end, top);
                {
                    let mut f = frame.clone();
                    f.constraints.push(cross.clone());
                    ctx.session.push();
                    ctx.session.assert_cs(std::slice::from_ref(&cross));
                    if ctx.check(f.cursor_max.max(1), &f.constraints) {
                        f.segments.push(format!("!roob@{inst}.{}", field.name));
                        emit(
                            ctx,
                            &f,
                            PathKind::Reject {
                                reason: "out of region bounds".into(),
                            },
                            f.cursor.clone(),
                            f.cursor_min,
                        );
                    }
                    ctx.session.pop();
                }
                let fits = Constraint::Not(Box::new(cross));
                frame.constraints.push(fits.clone());
                ctx.session.push();
                ctx.session.assert_cs(std::slice::from_ref(&fits));
                scoped = true;
            }
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
                    frame.cursor_min + n - 1,
                );
            }
            frame.placed.insert(
                (inst.clone(), field.name.clone()),
                (frame.cursor.clone(), n),
            );
            frame.cursor = t_add(frame.cursor, t_cst(n as u64));
            frame.cursor_max += n;
            frame.cursor_min += n;
            let r = walk_extracts(ctx, state, items, idx + 1, frame);
            if scoped {
                ctx.session.pop();
            }
            r
        }
        Some(pb::field_width::Width::BitLen(expr)) => {
            // No per-value forking: the body length stays symbolic. Fork
            // control flow only into {out-of-bounds, body-truncation,
            // continue}. The oob/continue split is at SANITY_BITS, matching
            // pathid; the width budget uses the tighter interval max.
            let len_term = term_of_expr(expr, &frame)?;
            // Bound the body by `min(interval-max, SANITY)`. This is the single
            // quantity that keeps THREE things consistent: (a) the oob/continue
            // split matches pathid (which mirrors `bound_bits`); (b) the width
            // budget `bound_bits <= SANITY_BITS` is a sound upper bound on
            // the continue branch's body AND never overflows `usize`/`u32` even
            // if `expr_max` (a u128) is astronomically large; (c) a wrapped or
            // oversized length lands in the oob branch, so no feasible continue
            // layout ever exceeds the width. `expr_max` alone would be unsound
            // for add/mul-wrap into `(expr_max, SANITY_BITS]`.
            let bound_bits_u64: u64 = expr_max(expr, ctx.parser)?.min(SANITY_BITS as u128) as u64;
            let bound_bits: usize = bound_bits_u64 as usize;

            // Out-of-bounds reject: length wraps / exceeds `bound_bits`
            // (feasible only when the expr can wrap, e.g. ihl<5, or exceed the
            // sane cap; z3 prunes it otherwise). Short witness -> interp
            // "out of bounds". Inside a region the failure set widens to
            // include the body end crossing the region end, and the
            // reason/segment become the structural ones (a wrapped
            // length crosses everything, so one unified fork suffices —
            // matching the interp's avail-free reason rule).
            let region_top = frame.regions.last().cloned();
            let body_end = t_add(frame.cursor.clone(), len_term.clone());
            {
                let mut oob = frame.clone();
                let mut fails = vec![Constraint::InRange(
                    len_term.clone(),
                    bound_bits_u64 + 1,
                    u64::MAX,
                )];
                if let Some(top) = &region_top {
                    fails.push(t_gt(body_end.clone(), top.clone()));
                }
                let (delta, seg, reason) = if region_top.is_some() {
                    (
                        c_or(fails),
                        format!("!roob@{inst}.{}", field.name),
                        "out of region bounds",
                    )
                } else {
                    (
                        fails.pop().expect("one element"),
                        format!("!oob@{inst}.{}", field.name),
                        "out of bounds",
                    )
                };
                oob.constraints.push(delta.clone());
                ctx.session.push();
                ctx.session.assert_cs(std::slice::from_ref(&delta));
                if ctx.check(oob.cursor_max.max(1), &oob.constraints) {
                    oob.segments.push(seg);
                    emit(
                        ctx,
                        &oob,
                        PathKind::Reject {
                            reason: reason.into(),
                        },
                        frame.cursor.clone(),
                        frame.cursor_min,
                    );
                }
                ctx.session.pop();
            }

            // Interval min of the body length (bits) — 0 unless the
            // length expr provably floors higher (e.g. (hdrlen+1)*64).
            // Feeds cursor_min so the witness ladder skips doomed rungs.
            let min_bits = term_interval(&len_term).0.min(bound_bits_u64) as usize;

            // The continue world is the non-wrapping, within-bound lengths
            // that also fit the innermost region, if one is open. Its
            // scope wraps the rest of this state's walk.
            let mut cont = vec![Constraint::InRange(len_term.clone(), 0, bound_bits_u64)];
            if let Some(top) = &region_top {
                cont.push(Constraint::Not(Box::new(t_gt(body_end, top.clone()))));
            }
            frame.constraints.extend(cont.iter().cloned());
            ctx.session.push();
            ctx.session.assert_cs(&cont);

            // Body-truncation: packet ends inside a non-empty body.
            {
                let mut t = frame.clone();
                let delta = Constraint::InRange(len_term.clone(), 1, bound_bits_u64);
                t.constraints.push(delta.clone());
                ctx.session.push();
                ctx.session.assert_cs(std::slice::from_ref(&delta));
                if ctx.check(t.cursor_max.max(1), &t.constraints) {
                    t.segments.push(format!("!trunc@{inst}.{}", field.name));
                    // avail = cursor + len - 1: one bit short of the body.
                    let bl = t_sub(t_add(frame.cursor.clone(), len_term.clone()), t_cst(1));
                    // len >= max(1, interval min) in this fork.
                    emit(
                        ctx,
                        &t,
                        PathKind::Truncation,
                        bl,
                        frame.cursor_min + min_bits.max(1) - 1,
                    );
                }
                ctx.session.pop();
            }

            // Continue: consume the opaque body (not placeable for refs).
            frame.cursor = t_add(frame.cursor, len_term);
            frame.cursor_max += bound_bits;
            frame.cursor_min += min_bits;
            let r = walk_extracts(ctx, state, items, idx + 1, frame);
            ctx.session.pop();
            r
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
                frame.cursor_min,
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
                frame.cursor_min,
            );
            Ok(())
        }
        None => anyhow::bail!("empty target"),
    }
}

fn walk_transition(ctx: &mut Ctx, state: &pb::State, mut frame: Frame) -> anyhow::Result<()> {
    // Assigns run after this state's extracts (already in `frame.placed`)
    // and before its transition. Substitution store: replace the metadata
    // term, masked to its declared width. No pathid change — assignments
    // add no path segments.
    for a in &state.assigns {
        let rhs = term_of_expr(
            a.value
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assign without value"))?,
            &frame,
        )?;
        let bits = ctx.meta_bits[a.metadata.as_str()];
        let masked = if bits >= 64 {
            rhs
        } else {
            Term::Bin(
                pb::BinOpKind::And,
                Box::new(rhs),
                Box::new(Term::Const((1u64 << bits) - 1)),
            )
        };
        frame.meta.insert(a.metadata.clone(), masked);
    }
    walk_region_ops(ctx, state, 0, frame)
}

/// Process `state.region_ops[idx..]` (each op forks like a var-length
/// field: structural-failure reject + constrained continue), then hand
/// off to the transition dispatch. Scope discipline mirrors
/// `walk_extracts`: each continue pushes one session scope, popped
/// after the recursion returns.
fn walk_region_ops(
    ctx: &mut Ctx,
    state: &pb::State,
    idx: usize,
    mut frame: Frame,
) -> anyhow::Result<()> {
    let Some(op) = state.region_ops.get(idx) else {
        return walk_dispatch(ctx, state, frame);
    };
    match op.kind.as_ref() {
        Some(pb::region_op::Kind::Push(e)) => {
            let len_term = term_of_expr(e, &frame)?;
            let bound_bits: u64 = expr_max(e, ctx.parser)?.min(SANITY_BITS as u128) as u64;
            let end_term = t_add(frame.cursor.clone(), len_term.clone());
            // Failure fork: wrapped/oversized length, or (nested) the new
            // end crossing the enclosing region end. One fork, one
            // reason — matching the interp's "region out of bounds".
            let mut fails = vec![Constraint::InRange(
                len_term.clone(),
                bound_bits + 1,
                u64::MAX,
            )];
            if let Some(top) = frame.regions.last() {
                fails.push(t_gt(end_term.clone(), top.clone()));
            }
            let fail = c_or(fails);
            {
                let mut f = frame.clone();
                f.constraints.push(fail.clone());
                ctx.session.push();
                ctx.session.assert_cs(std::slice::from_ref(&fail));
                if ctx.check(f.cursor_max.max(1), &f.constraints) {
                    f.segments.push(format!("!rpush@{}#{idx}", state.name));
                    emit(
                        ctx,
                        &f,
                        PathKind::Reject {
                            reason: "region out of bounds".into(),
                        },
                        f.cursor.clone(),
                        f.cursor_min,
                    );
                }
                ctx.session.pop();
            }
            let ok = Constraint::Not(Box::new(fail));
            frame.constraints.push(ok.clone());
            ctx.session.push();
            ctx.session.assert_cs(std::slice::from_ref(&ok));
            frame.regions.push(end_term);
            let r = walk_region_ops(ctx, state, idx + 1, frame);
            ctx.session.pop();
            r
        }
        Some(pb::region_op::Kind::Pop(_)) => {
            let end = frame
                .regions
                .pop()
                .ok_or_else(|| anyhow::anyhow!("region pop with no open region"))?;
            // Shortfall fork: exact-mode pop with the cursor short of
            // the region end -> "region not exhausted". The witness
            // bit_len is the REGION END, not the cursor: the interp
            // classifies a shortfall with the end beyond the buffer as
            // truncation ("out of bounds"), so the witness must carry
            // the trailing bytes to land in the structural flavor.
            // (The end-past-buffer flavor is the same control point;
            // it is corpus-covered, not separately enumerated.)
            let short = t_gt(end.clone(), frame.cursor.clone());
            {
                let mut f = frame.clone();
                f.constraints.push(short.clone());
                ctx.session.push();
                ctx.session.assert_cs(std::slice::from_ref(&short));
                if ctx.check(f.cursor_max.max(1), &f.constraints) {
                    f.segments.push(format!("!rtrail@{}#{idx}", state.name));
                    emit(
                        ctx,
                        &f,
                        PathKind::Reject {
                            reason: "region not exhausted".into(),
                        },
                        end.clone(),
                        f.cursor_min,
                    );
                }
                ctx.session.pop();
            }
            let exact = Constraint::Eq(t_sub(end, frame.cursor.clone()), 0);
            frame.constraints.push(exact.clone());
            ctx.session.push();
            ctx.session.assert_cs(std::slice::from_ref(&exact));
            let r = walk_region_ops(ctx, state, idx + 1, frame);
            ctx.session.pop();
            r
        }
        None => anyhow::bail!("empty region op"),
    }
}

fn walk_dispatch(ctx: &mut Ctx, state: &pb::State, frame: Frame) -> anyhow::Result<()> {
    fn target_group_key(t: &pb::Target) -> Option<String> {
        match t.kind.as_ref()? {
            pb::target::Kind::State(s) => Some(format!("state:{s}")),
            pb::target::Kind::Accept(_) => Some("accept".into()),
            pb::target::Kind::Reject(r) => Some(format!(
                "reject:{}:{:?}",
                r.reason,
                r.annotations.get("severity")
            )),
        }
    }
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
            // Same-target arms with exact-value entries coalesce into ONE
            // enumerated path under the disjunction of their key
            // constraints: the enumerated unit is the control shape, not
            // the key value (a 3-protocol ext-header arm set is one
            // path). Exact values are pairwise disjoint, so first-match
            // ordering is unaffected; Masked/Range arms can overlap and
            // keep per-arm paths. This is what keeps wide faithful
            // dispatch tables (dpdk_ptype) enumerable.
            let mut groups: Vec<Vec<usize>> = Vec::new();
            {
                let mut by_target: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for (i, arm) in sel.arms.iter().enumerate() {
                    let exact = arm
                        .entries
                        .iter()
                        .all(|e| matches!(e.kind, Some(pb::keyset_entry::Kind::Value(_))));
                    let key = if exact {
                        arm.next.as_ref().and_then(target_group_key)
                    } else {
                        None
                    };
                    match key {
                        Some(k) => {
                            let next = groups.len();
                            let g = *by_target.entry(k).or_insert(next);
                            if g < groups.len() {
                                groups[g].push(i);
                            } else {
                                groups.push(vec![i]);
                            }
                        }
                        None => groups.push(vec![i]),
                    }
                }
            }
            for members in &groups {
                let first = members[0];
                for &m in members {
                    ctx.log.attempted_arms.insert((state.name.clone(), m));
                }
                let mut child = frame.clone();
                let cond = if members.len() == 1 {
                    arm_conds[first].clone()
                } else {
                    // OR via De Morgan — the solver core stays And/Not.
                    Constraint::Not(Box::new(Constraint::And(
                        members
                            .iter()
                            .map(|&m| Constraint::Not(Box::new(arm_conds[m].clone())))
                            .collect(),
                    )))
                };
                let mut delta = vec![cond];
                for (j, cond) in arm_conds.iter().enumerate().take(first) {
                    if !members.contains(&j) {
                        delta.push(Constraint::Not(Box::new(cond.clone())));
                    }
                }
                child.constraints.extend(delta.iter().cloned());
                ctx.session.push();
                ctx.session.assert_cs(&delta);
                let r = if ctx.check(child.cursor_max.max(1), &child.constraints) {
                    // Best-effort per-arm log: a group is feasible as a
                    // whole; individually-dead values inside a live
                    // group are not distinguished (lint boundary).
                    for &m in members {
                        ctx.log.feasible_arms.insert((state.name.clone(), m));
                    }
                    child.segments.push(format!("arm{first}"));
                    match sel.arms[first].next.as_ref() {
                        Some(target) => walk_target(ctx, target, child),
                        None => Err(anyhow::anyhow!("select arm has no target")),
                    }
                } else {
                    Ok(()) // infeasible in this context; lint sees it via the log
                };
                ctx.session.pop();
                r?;
            }
            // Default: all arms negated.
            let mut child = frame;
            let delta: Vec<Constraint> = arm_conds
                .iter()
                .map(|cond| Constraint::Not(Box::new(cond.clone())))
                .collect();
            child.constraints.extend(delta.iter().cloned());
            ctx.session.push();
            ctx.session.assert_cs(&delta);
            let r = if ctx.check(child.cursor_max.max(1), &child.constraints) {
                child.segments.push("default".into());
                match sel.default_target.as_ref() {
                    Some(t) => walk_target(ctx, t, child),
                    None => {
                        emit(
                            ctx,
                            &child,
                            PathKind::Reject {
                                reason: "no matching select arm".into(),
                            },
                            child.cursor.clone(),
                            child.cursor_min,
                        );
                        Ok(())
                    }
                }
            } else {
                Ok(())
            };
            ctx.session.pop();
            r
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
        // The emit-time witness solved the symbolic bit_len to 8 bits.
        let (_b, bit_len) = accept.witness.clone().unwrap();
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
        // The accept witness picks some n in 0..=3 -> the 2-bit header plus
        // an n-byte body (small by the solver's length ladder, not minimal).
        let accept = e.paths.iter().find(|p| p.kind == PathKind::Accept).unwrap();
        let (_b, bit_len) = accept.witness.clone().unwrap();
        assert!([2, 10, 18, 26].contains(&bit_len), "bit_len={bit_len}");
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
    fn select_on_metadata_forks_by_substitution() {
        let ir = crate::builder::meta_loop(); // shared test IR from Task 2
        let e = enumerate_ir(&ir);
        let ids: Vec<&str> = e.paths.iter().map(|p| p.id.as_str()).collect();
        // s1 is cyclic: TESTGEN_LOOP_UNROLL=2 caps its unrollings. Expected feasible
        // accepts: n=0 (arm0 at s0) and n=1, n=2 (arm0 after 1 or 2 s1 entries).
        // Truncation forks per extract as usual.
        assert!(ids.contains(&"s0/!trunc@h.n"));
        assert!(ids.iter().any(|i| i.starts_with("s0/arm0"))); // n == 0
        assert!(ids.iter().any(|i| i.contains("s0/default/s1/arm0"))); // n == 1
                                                                       // z3 must prove n==0 infeasible on the default (loop) branch, i.e. no
                                                                       // path both takes s0/default and asserts h.n == 0.
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

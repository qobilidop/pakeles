//! z3 backend for the solver trait.
//!
//! Feasibility and witnesses are decided over the FIELD-VARIABLE
//! encoding: one fresh 64-bit variable per structurally-distinct read
//! term, bounded to the read's width — no packet bitvector, no barrel
//! shifters, width-independent queries (see `Term`'s doc for the
//! disjoint-regions equisatisfiability argument). The packet encoding
//! survives only as the `PAKELES_SYMEX_XCHECK=1` cross-check oracle.

use super::solver::{Constraint, Session, Solver, Term};
use crate::ir::pb;
use std::collections::{HashMap, HashSet};
use z3::ast::{Ast, BV};

pub(crate) struct Z3Solver {
    ctx: z3::Context,
    /// `PAKELES_SYMEX_XCHECK=1`: decide every feasibility query under
    /// BOTH the field-variable and the packet encoding and panic on
    /// disagreement.
    xcheck: bool,
}

/// Per-region field variables: the variable plus its width-bound
/// assertion (`None` when the read is a full 64 bits). `pending` carries
/// the bounds touched by the current translation batch — in a session,
/// a bound asserted in a sibling scope has been popped, so every batch
/// re-asserts the bounds of the terms it uses (redundant asserts are
/// cheap; missing ones are unsound).
struct FieldVars<'a> {
    vars: HashMap<Term, (BV<'a>, Option<z3::ast::Bool<'a>>)>,
    pending: Vec<z3::ast::Bool<'a>>,
}

impl<'a> FieldVars<'a> {
    fn new() -> Self {
        FieldVars {
            vars: HashMap::new(),
            pending: Vec::new(),
        }
    }
}

fn feas_term<'a>(ctx: &'a z3::Context, fv: &mut FieldVars<'a>, t: &Term) -> BV<'a> {
    match t {
        Term::Const(v) => BV::from_u64(ctx, *v, 64),
        Term::Extract { len, .. } | Term::ExtractAt { len, .. } => {
            if let Some((var, bound)) = fv.vars.get(t) {
                if let Some(b) = bound {
                    fv.pending.push(b.clone());
                }
                return var.clone();
            }
            let var = BV::new_const(ctx, format!("f{}", fv.vars.len()), 64);
            let bound = (*len < 64).then(|| var.bvule(&BV::from_u64(ctx, (1u64 << len) - 1, 64)));
            if let Some(b) = &bound {
                fv.pending.push(b.clone());
            }
            fv.vars.insert(t.clone(), (var.clone(), bound));
            var
        }
        Term::Bin(op, l, r) => {
            let l = feas_term(ctx, fv, l);
            let r = feas_term(ctx, fv, r);
            match op {
                pb::BinOpKind::Add => l.bvadd(&r),
                pb::BinOpKind::Sub => l.bvsub(&r),
                pb::BinOpKind::Mul => l.bvmul(&r),
                pb::BinOpKind::Shl => l.bvshl(&r),
                pb::BinOpKind::Shr => l.bvlshr(&r),
                pb::BinOpKind::And => l.bvand(&r),
                pb::BinOpKind::Or => l.bvor(&r),
                pb::BinOpKind::Unspecified => unreachable!("validated IR"),
            }
        }
    }
}

fn feas_constraint<'a>(
    ctx: &'a z3::Context,
    fv: &mut FieldVars<'a>,
    c: &Constraint,
) -> z3::ast::Bool<'a> {
    match c {
        Constraint::Eq(t, v) => feas_term(ctx, fv, t)._eq(&BV::from_u64(ctx, *v, 64)),
        Constraint::Masked(t, value, mask) => {
            let m = BV::from_u64(ctx, *mask, 64);
            feas_term(ctx, fv, t)
                .bvand(&m)
                ._eq(&BV::from_u64(ctx, value & mask, 64))
        }
        Constraint::InRange(t, lo, hi) => {
            let t = feas_term(ctx, fv, t);
            z3::ast::Bool::and(
                ctx,
                &[
                    &t.bvuge(&BV::from_u64(ctx, *lo, 64)),
                    &t.bvule(&BV::from_u64(ctx, *hi, 64)),
                ],
            )
        }
        Constraint::Not(inner) => feas_constraint(ctx, fv, inner).not(),
        Constraint::And(cs) => {
            let bools: Vec<_> = cs.iter().map(|c| feas_constraint(ctx, fv, c)).collect();
            let refs: Vec<_> = bools.iter().collect();
            z3::ast::Bool::and(ctx, &refs)
        }
    }
}

// ---- packet encoding (cross-check oracle only) ----

fn packet_bv(ctx: &z3::Context, packet_bits: usize) -> BV<'_> {
    // >=1 dummy bit when the packet is empty, kept unconstrained/unread.
    BV::new_const(ctx, "packet", packet_bits.max(1) as u32)
}

fn packet_term<'a>(ctx: &'a z3::Context, packet: &BV<'a>, t: &Term) -> BV<'a> {
    match t {
        Term::Const(v) => BV::from_u64(ctx, *v, 64),
        Term::Extract { bit_off, len } => {
            let total = packet.get_size() as usize;
            // MSB-first: bit_off 0 is the packet BV's highest bit.
            let hi = (total - 1 - bit_off) as u32;
            let lo = (total - bit_off - len) as u32;
            packet.extract(hi, lo).zero_ext(64 - *len as u32)
        }
        Term::ExtractAt { off, len } => {
            // MSB-first extract at a symbolic bit offset: shift down by
            // (w-len)-off and mask the low `len` bits. `off+len <= w`
            // holds under path constraints, so the shift does not wrap.
            let w = packet.get_size();
            let len = *len as u32;
            let off64 = packet_term(ctx, packet, off); // 64-bit value
            let off_w = match w.cmp(&64) {
                std::cmp::Ordering::Greater => off64.zero_ext(w - 64),
                std::cmp::Ordering::Less => off64.extract(w - 1, 0),
                std::cmp::Ordering::Equal => off64,
            };
            let base = BV::from_u64(ctx, (w - len) as u64, w);
            let shift = base.bvsub(&off_w);
            packet.bvlshr(&shift).extract(len - 1, 0).zero_ext(64 - len)
        }
        Term::Bin(op, l, r) => {
            let l = packet_term(ctx, packet, l);
            let r = packet_term(ctx, packet, r);
            match op {
                pb::BinOpKind::Add => l.bvadd(&r),
                pb::BinOpKind::Sub => l.bvsub(&r),
                pb::BinOpKind::Mul => l.bvmul(&r),
                pb::BinOpKind::Shl => l.bvshl(&r),
                pb::BinOpKind::Shr => l.bvlshr(&r),
                pb::BinOpKind::And => l.bvand(&r),
                pb::BinOpKind::Or => l.bvor(&r),
                pb::BinOpKind::Unspecified => unreachable!("validated IR"),
            }
        }
    }
}

fn packet_constraint<'a>(
    ctx: &'a z3::Context,
    packet: &BV<'a>,
    c: &Constraint,
) -> z3::ast::Bool<'a> {
    match c {
        Constraint::Eq(t, v) => packet_term(ctx, packet, t)._eq(&BV::from_u64(ctx, *v, 64)),
        Constraint::Masked(t, value, mask) => {
            let m = BV::from_u64(ctx, *mask, 64);
            packet_term(ctx, packet, t)
                .bvand(&m)
                ._eq(&BV::from_u64(ctx, value & mask, 64))
        }
        Constraint::InRange(t, lo, hi) => {
            let t = packet_term(ctx, packet, t);
            z3::ast::Bool::and(
                ctx,
                &[
                    &t.bvuge(&BV::from_u64(ctx, *lo, 64)),
                    &t.bvule(&BV::from_u64(ctx, *hi, 64)),
                ],
            )
        }
        Constraint::Not(inner) => packet_constraint(ctx, packet, inner).not(),
        Constraint::And(cs) => {
            let bools: Vec<_> = cs
                .iter()
                .map(|c| packet_constraint(ctx, packet, c))
                .collect();
            let refs: Vec<_> = bools.iter().collect();
            z3::ast::Bool::and(ctx, &refs)
        }
    }
}

/// The pre-lever packet-BV feasibility decision, kept as the cross-check
/// oracle for the field-variable encoding.
fn packet_feasible(ctx: &z3::Context, packet_bits: usize, cs: &[Constraint]) -> bool {
    let packet = packet_bv(ctx, packet_bits);
    let solver = z3::Solver::new(ctx);
    for c in cs {
        solver.assert(&packet_constraint(ctx, &packet, c));
    }
    solver.check() == z3::SatResult::Sat
}

// ---- witness construction from a field model ----

/// Evaluate a term under concrete region values, mirroring the z3
/// 64-bit wrapping semantics of `feas_term` exactly (bvshl/bvlshr zero
/// out at shift >= 64; add/sub/mul wrap). Reads absent from `vals` were
/// unconstrained — model completion would give 0; so do we.
fn eval_term(vals: &HashMap<Term, u64>, t: &Term) -> u64 {
    match t {
        Term::Const(v) => *v,
        Term::Extract { .. } | Term::ExtractAt { .. } => vals.get(t).copied().unwrap_or(0),
        Term::Bin(op, l, r) => {
            let l = eval_term(vals, l);
            let r = eval_term(vals, r);
            match op {
                pb::BinOpKind::Add => l.wrapping_add(r),
                pb::BinOpKind::Sub => l.wrapping_sub(r),
                pb::BinOpKind::Mul => l.wrapping_mul(r),
                pb::BinOpKind::Shl => {
                    if r >= 64 {
                        0
                    } else {
                        l << r
                    }
                }
                pb::BinOpKind::Shr => {
                    if r >= 64 {
                        0
                    } else {
                        l >> r
                    }
                }
                pb::BinOpKind::And => l & r,
                pb::BinOpKind::Or => l | r,
                pb::BinOpKind::Unspecified => unreachable!("validated IR"),
            }
        }
    }
}

/// Region terms reachable from a constraint set + length term: the ONLY
/// regions allowed to materialize in a witness. (A session's variable
/// cache also holds sibling branches' regions; leaking those into the
/// packet would write bits this path never placed.)
fn collect_reads(cs: &[Constraint], len: &Term, out: &mut HashSet<Term>) {
    fn term(t: &Term, out: &mut HashSet<Term>) {
        match t {
            Term::Const(_) => {}
            Term::Extract { .. } => {
                out.insert(t.clone());
            }
            Term::ExtractAt { off, .. } => {
                out.insert(t.clone());
                term(off, out);
            }
            Term::Bin(_, l, r) => {
                term(l, out);
                term(r, out);
            }
        }
    }
    fn cons(c: &Constraint, out: &mut HashSet<Term>) {
        match c {
            Constraint::Eq(t, _) | Constraint::Masked(t, _, _) | Constraint::InRange(t, _, _) => {
                term(t, out)
            }
            Constraint::Not(inner) => cons(inner, out),
            Constraint::And(cs) => cs.iter().for_each(|c| cons(c, out)),
        }
    }
    cs.iter().for_each(|c| cons(c, out));
    term(len, out);
}

/// Construct the witness packet from solved region values: each read
/// region's bits land at its (model-concrete) offset MSB-first; every
/// other bit — bodies, never-read fields, pad — is zero. Disjointness of
/// regions under the path constraints (see `Term`'s doc) makes the
/// writes conflict-free; bits at/after `n_bits` (a region cut by a
/// truncation path's length) are skipped.
fn build_packet(vals: &HashMap<Term, u64>, n_bits: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n_bits.div_ceil(8)];
    for (t, v) in vals {
        let (off, len) = match t {
            Term::Extract { bit_off, len } => (*bit_off as u64, *len),
            Term::ExtractAt { off, len } => (eval_term(vals, off), *len),
            _ => unreachable!("vals keys are read terms"),
        };
        for i in 0..len {
            let bit = (off as usize).saturating_add(i);
            if bit >= n_bits {
                continue;
            }
            if (v >> (len - 1 - i)) & 1 == 1 {
                bytes[bit / 8] |= 1 << (7 - (bit % 8));
            }
        }
    }
    bytes
}

/// Small-not-minimal length ladder: try `len <= 128B`, then `<= 4KB`,
/// then unbounded — first SAT wins. (OMT minimize was 1.6x slower for
/// ~7% size; measured 2026-07-25.) Assumptions, not asserts, so learned
/// clauses stay valid across rungs.
const LADDER_BITS: [Option<u64>; 3] = [Some(128 * 8), Some(4096 * 8), None];

/// Run the ladder on `solver` (whose stack already holds the path
/// system), returning the first SAT model. Rungs below `min_bits` (a
/// static lower bound on `len`) are provably UNSAT and skipped without
/// a solver call.
fn ladder_solve<'a>(
    ctx: &'a z3::Context,
    solver: &z3::Solver<'a>,
    len_bv: &BV<'a>,
    min_bits: usize,
    mut wtime: Option<&mut [std::time::Duration; 3]>,
) -> (Option<z3::Model<'a>>, u8) {
    let mut tried = 0u8;
    for bound in LADDER_BITS {
        if let Some(b) = bound {
            if (b as usize) < min_bits {
                continue;
            }
        }
        tried += 1;
        let assumptions: Vec<z3::ast::Bool> = match bound {
            Some(b) => vec![len_bv.bvule(&BV::from_u64(ctx, b, 64))],
            None => vec![],
        };
        let t0 = std::time::Instant::now();
        let sat = solver.check_assumptions(&assumptions) == z3::SatResult::Sat;
        if let Some(w) = wtime.as_deref_mut() {
            w[0] += t0.elapsed();
        }
        if sat {
            return (Some(solver.get_model().expect("model after sat")), tried);
        }
    }
    (None, tried)
}

/// Materialize a witness from a model: read the regions reachable via
/// `cs` + `len`, evaluate the length, construct the packet.
fn model_witness(
    model: &z3::Model,
    fv: &FieldVars,
    cs: &[Constraint],
    len: &Term,
    mut wtime: Option<&mut [std::time::Duration; 3]>,
) -> (Vec<u8>, usize) {
    let t1 = std::time::Instant::now();
    let mut reads = HashSet::new();
    collect_reads(cs, len, &mut reads);
    let vals: HashMap<Term, u64> = reads
        .into_iter()
        .filter_map(|t| {
            let (bv, _) = fv.vars.get(&t)?;
            let v = model.eval(bv, true).and_then(|b| b.as_u64()).unwrap_or(0);
            Some((t, v))
        })
        .collect();
    let actual = eval_term(&vals, len) as usize;
    if let Some(w) = wtime.as_deref_mut() {
        w[1] += t1.elapsed();
    }
    let t2 = std::time::Instant::now();
    let packet = build_packet(&vals, actual);
    if let Some(w) = wtime {
        w[2] += t2.elapsed();
    }
    (packet, actual)
}

impl Z3Solver {
    pub(crate) fn new() -> Self {
        Self {
            ctx: z3::Context::new(&z3::Config::new()),
            xcheck: std::env::var_os("PAKELES_SYMEX_XCHECK").is_some_and(|v| v == "1"),
        }
    }
}

impl Solver for Z3Solver {
    fn feasible(&mut self, packet_bits: usize, cs: &[Constraint]) -> bool {
        let mut fv = FieldVars::new();
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            let b = feas_constraint(&self.ctx, &mut fv, c);
            solver.assert(&b);
        }
        for b in fv.pending.drain(..) {
            solver.assert(&b);
        }
        let sat = solver.check() == z3::SatResult::Sat;
        if self.xcheck {
            let psat = packet_feasible(&self.ctx, packet_bits, cs);
            assert_eq!(
                sat, psat,
                "encoding disagreement (field={sat}, packet={psat}) on {cs:#?}"
            );
        }
        sat
    }

    fn session<'s>(&'s mut self) -> Box<dyn Session + 's> {
        Box::new(Z3Session {
            ctx: &self.ctx,
            solver: z3::Solver::new(&self.ctx),
            fv: FieldVars::new(),
            xcheck: self.xcheck,
            epoch: 0,
            model_cache: None,
            wtime: std::env::var_os("PAKELES_SYMEX_WTIME")
                .is_some_and(|v| v == "1")
                .then(Default::default),
        })
    }

    fn solve_witness(
        &mut self,
        _width: usize,
        cs: &[Constraint],
        len: &Term,
    ) -> Option<(Vec<u8>, usize)> {
        // One-shot variant of the session path: same field system, same
        // ladder, packet constructed (never modeled). `_width` is
        // obsolete in this backend.
        let mut fv = FieldVars::new();
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            let b = feas_constraint(&self.ctx, &mut fv, c);
            solver.assert(&b);
        }
        let len_bv = feas_term(&self.ctx, &mut fv, len);
        for b in fv.pending.drain(..) {
            solver.assert(&b);
        }
        let (model, _tried) = ladder_solve(&self.ctx, &solver, &len_bv, 0, None);
        model.map(|m| model_witness(&m, &fv, cs, len, None))
    }
}

struct Z3Session<'a> {
    ctx: &'a z3::Context,
    solver: z3::Solver<'a>,
    fv: FieldVars<'a>,
    xcheck: bool,
    /// Monotonic stack-state counter: bumped on every push/pop/assert.
    epoch: u64,
    /// Last solved model, tagged with the epoch it is valid for. Sibling
    /// emits at an unchanged stack (e.g. the fixed-field truncation
    /// forks of one state) reuse it — same constraint system, so any
    /// model of it witnesses every such emit; each emit just evaluates
    /// its own bit-length term. DFS order is deterministic, so reuse is
    /// too.
    model_cache: Option<(u64, z3::Model<'a>)>,
    /// `PAKELES_SYMEX_WTIME=1`: aggregate witness-phase breakdown
    /// (solve / model-extract / build), dumped on session drop.
    wtime: Option<[std::time::Duration; 3]>,
}

impl Drop for Z3Session<'_> {
    fn drop(&mut self) {
        if let Some([solve, extract, build]) = self.wtime {
            eprintln!(
                "WITNESS BREAKDOWN: solve {:.3}s, extract {:.3}s, build {:.3}s",
                solve.as_secs_f64(),
                extract.as_secs_f64(),
                build.as_secs_f64(),
            );
        }
    }
}

impl Session for Z3Session<'_> {
    fn push(&mut self) {
        self.epoch += 1;
        self.solver.push();
    }

    fn pop(&mut self) {
        self.epoch += 1;
        self.solver.pop(1);
    }

    fn assert_cs(&mut self, delta: &[Constraint]) {
        self.epoch += 1;
        for c in delta {
            let b = feas_constraint(self.ctx, &mut self.fv, c);
            self.solver.assert(&b);
        }
        // Width bounds touched by this batch — re-asserted even for
        // cached variables, since a sibling scope's assert has been
        // popped (see `FieldVars`).
        for b in self.fv.pending.drain(..) {
            self.solver.assert(&b);
        }
    }

    fn check(&mut self, packet_bits: usize, full_cs: &[Constraint]) -> bool {
        let sat = self.solver.check() == z3::SatResult::Sat;
        if sat {
            // Cache the proof's model: most emits happen at exactly this
            // stack state (an arm's accept/reject, a state's truncation
            // forks), so their witnesses come for free — gated by the
            // small-enough acceptance rule in `witness`.
            let model = self.solver.get_model().expect("model after sat");
            self.model_cache = Some((self.epoch, model));
        }
        if self.xcheck {
            let psat = packet_feasible(self.ctx, packet_bits, full_cs);
            assert_eq!(
                sat, psat,
                "encoding disagreement (field={sat}, packet={psat}) on {full_cs:#?}"
            );
        }
        sat
    }

    fn witness(
        &mut self,
        full_cs: &[Constraint],
        len: &Term,
        min_bits: usize,
    ) -> (Option<(Vec<u8>, usize)>, u8) {
        // Unchanged stack since the last solve or SAT check: reuse that
        // model (0 solver calls) — but only if the length it implies is
        // within the best bound the ladder itself could guarantee (the
        // smallest rung not statically doomed by `min_bits`). A model
        // from a plain check has no small-length bias, so an oversized
        // one falls through to the ladder instead of bloating witnesses.
        let accept_bits = LADDER_BITS
            .iter()
            .flatten()
            .find(|b| **b as usize >= min_bits)
            .copied()
            .unwrap_or(u64::MAX);
        if let Some((epoch, model)) = &self.model_cache {
            if *epoch == self.epoch {
                let out = model_witness(model, &self.fv, full_cs, len, self.wtime.as_mut());
                if out.1 as u64 <= accept_bits {
                    return (Some(out), 0);
                }
            }
        }
        // Scope the `len` translation: its fresh region bounds must not
        // outlive this witness call. The internal push/pop does NOT
        // bump `epoch` (the trait-level stack is unchanged), so the
        // model stays cached for sibling emits.
        self.solver.push();
        let len_bv = feas_term(self.ctx, &mut self.fv, len);
        for b in self.fv.pending.drain(..) {
            self.solver.assert(&b);
        }
        let (model, tried) = ladder_solve(
            self.ctx,
            &self.solver,
            &len_bv,
            min_bits,
            self.wtime.as_mut(),
        );
        self.solver.pop(1);
        match model {
            Some(m) => {
                let out = model_witness(&m, &self.fv, full_cs, len, self.wtime.as_mut());
                self.model_cache = Some((self.epoch, m));
                (Some(out), tried)
            }
            None => (None, tried),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::pb::BinOpKind;

    fn ext(bit_off: usize, len: usize) -> Term {
        Term::Extract { bit_off, len }
    }

    /// Witness bytes for a fully-`w`-bit packet — the surface the byte-
    /// semantics tests were written against (originally the packet
    /// encoding's `check`; the constructed packet must reproduce the
    /// same read semantics).
    fn packet_bytes(s: &mut Z3Solver, w: usize, cs: &[Constraint]) -> Option<Vec<u8>> {
        s.solve_witness(w, cs, &Term::Const(w as u64))
            .map(|(b, _)| b)
    }

    #[test]
    fn trivial_sat_and_unsat() {
        let mut s = Z3Solver::new();
        let sat = packet_bytes(&mut s, 16, &[Constraint::Eq(ext(0, 8), 0xAB)]);
        assert_eq!(sat.unwrap()[0], 0xAB);
        let contradiction = [
            Constraint::Eq(ext(0, 8), 1),
            Constraint::Not(Box::new(Constraint::Eq(ext(0, 8), 1))),
        ];
        assert!(packet_bytes(&mut s, 16, &contradiction).is_none());
        assert!(s.feasible(16, &[Constraint::Eq(ext(0, 8), 0xAB)]));
        assert!(!s.feasible(16, &contradiction));
    }

    #[test]
    fn extract_is_msb_first() {
        let mut s = Z3Solver::new();
        // Constrain bits 4..12 (the middle byte-straddling 8 bits).
        let bytes = packet_bytes(&mut s, 16, &[Constraint::Eq(ext(4, 8), 0xBC)]).unwrap();
        let val = (u16::from_be_bytes([bytes[0], bytes[1]]) >> 4) & 0xFF;
        assert_eq!(val, 0xBC);
    }

    #[test]
    fn arithmetic_matches_interp_wrapping() {
        let mut s = Z3Solver::new();
        // ihl-style: ext(0,4)*4 - 20 == 4  =>  ext = 6
        let term = Term::Bin(
            BinOpKind::Sub,
            Box::new(Term::Bin(
                BinOpKind::Mul,
                Box::new(ext(0, 4)),
                Box::new(Term::Const(4)),
            )),
            Box::new(Term::Const(20)),
        );
        let bytes = packet_bytes(&mut s, 8, &[Constraint::Eq(term, 4)]).unwrap();
        assert_eq!(bytes[0] >> 4, 6);
    }

    #[test]
    fn extract_at_reads_symbolic_offset() {
        // Read 8 bits at a SYMBOLIC offset taken from the first byte's
        // value: with off == 8, the byte at bit-offset 8 (the 2nd byte)
        // must be 0xBC; with off == 16, the 3rd byte.
        let mut s = Z3Solver::new();
        let off = ext(0, 8);
        let read = Term::ExtractAt {
            off: Box::new(off.clone()),
            len: 8,
        };
        let bytes = packet_bytes(
            &mut s,
            24,
            &[
                Constraint::Eq(off.clone(), 8),
                Constraint::Eq(read.clone(), 0xBC),
            ],
        )
        .unwrap();
        assert_eq!(bytes[0], 8);
        assert_eq!(bytes[1], 0xBC);
        let bytes = packet_bytes(
            &mut s,
            24,
            &[Constraint::Eq(off, 16), Constraint::Eq(read, 0xBC)],
        )
        .unwrap();
        assert_eq!(bytes[0], 16);
        assert_eq!(bytes[2], 0xBC);
    }

    #[test]
    fn feasible_field_encoding_semantics() {
        let mut s = Z3Solver::new();
        // Same read term = same region variable: contradictions stay UNSAT.
        let read = Term::ExtractAt {
            off: Box::new(ext(0, 8)),
            len: 8,
        };
        assert!(!s.feasible(
            24,
            &[
                Constraint::Eq(read.clone(), 1),
                Constraint::Not(Box::new(Constraint::Eq(read.clone(), 1))),
            ],
        ));
        // Distinct read terms are independent regions.
        let other = Term::ExtractAt {
            off: Box::new(ext(8, 8)),
            len: 8,
        };
        assert!(s.feasible(32, &[Constraint::Eq(read, 1), Constraint::Eq(other, 2)],));
        // Region variables carry the read's width bound.
        assert!(!s.feasible(16, &[Constraint::Eq(ext(0, 8), 256)]));
        assert!(s.feasible(16, &[Constraint::Eq(ext(0, 8), 255)]));
    }

    #[test]
    fn feasible_agrees_with_packet_encoding() {
        // Forced cross-check: every query below runs under BOTH encodings
        // and the assertion inside `feasible` panics on disagreement. The
        // battery stays within engine-shaped constraints (offsets bounded
        // so off + len <= width, as path constraints guarantee).
        let mut s = Z3Solver::new();
        s.xcheck = true;
        let off = ext(0, 8);
        let read = Term::ExtractAt {
            off: Box::new(off.clone()),
            len: 8,
        };
        let queries: Vec<(Vec<Constraint>, bool)> = vec![
            (vec![Constraint::Eq(ext(0, 8), 0xAB)], true),
            (
                vec![
                    Constraint::Eq(ext(0, 8), 1),
                    Constraint::Not(Box::new(Constraint::Eq(ext(0, 8), 1))),
                ],
                false,
            ),
            (
                vec![
                    Constraint::InRange(off.clone(), 8, 16),
                    Constraint::Eq(read.clone(), 0xBC),
                ],
                true,
            ),
            (
                vec![
                    Constraint::InRange(off.clone(), 8, 16),
                    Constraint::Masked(read.clone(), 0xF0, 0xF0),
                    Constraint::InRange(read.clone(), 0, 0x0F),
                ],
                false,
            ),
            (
                vec![Constraint::And(vec![
                    Constraint::InRange(off, 8, 16),
                    Constraint::Not(Box::new(Constraint::Eq(read, 0))),
                ])],
                true,
            ),
        ];
        for (cs, want) in queries {
            assert_eq!(s.feasible(32, &cs), want, "query {cs:?}");
        }
    }

    #[test]
    fn session_scopes_and_witness_isolation() {
        let mut s = Z3Solver::new();
        let mut sess = s.session();
        let a = ext(0, 8);
        let b = ext(8, 8);
        // Scope 1: constrain region a; witness sees ONLY a.
        sess.push();
        sess.assert_cs(&[Constraint::Eq(a.clone(), 5)]);
        assert!(sess.check(16, &[Constraint::Eq(a.clone(), 5)]));
        let (bytes, bits) = sess
            .witness(&[Constraint::Eq(a.clone(), 5)], &Term::Const(8), 0)
            .0
            .unwrap();
        assert_eq!((bits, bytes[0]), (8, 5));
        // Contradiction inside a deeper scope, gone after pop.
        sess.push();
        sess.assert_cs(&[Constraint::Not(Box::new(Constraint::Eq(a.clone(), 5)))]);
        assert!(!sess.check(16, &[]));
        sess.pop();
        assert!(sess.check(16, &[Constraint::Eq(a.clone(), 5)]));
        sess.pop();
        // Sibling scope: `a`'s var is cached in the session but its
        // constraint (and width bound) are popped — the witness for a
        // path constraining only `b` must not leak region `a`.
        sess.push();
        sess.assert_cs(&[Constraint::Eq(b.clone(), 7)]);
        let (bytes, bits) = sess
            .witness(&[Constraint::Eq(b, 7)], &Term::Const(16), 0)
            .0
            .unwrap();
        assert_eq!((bits, bytes[0], bytes[1]), (16, 0, 7));
        sess.pop();
    }

    #[test]
    fn solve_witness_respects_len_and_unsat() {
        // len term = ext(0,4) (a nibble length in [0,15]). The witness is
        // small (first ladder rung covers all of [0,15]) but NOT minimal:
        // any length satisfying the constraints is valid. The returned
        // packet is exactly `actual` bits.
        let mut s = Z3Solver::new();
        let len = ext(0, 4);
        let (bytes, actual) = s.solve_witness(16, &[], &len).unwrap();
        assert!(actual <= 15);
        assert_eq!(bytes.len(), actual.div_ceil(8));
        let (_bytes, actual) = s
            .solve_witness(16, &[Constraint::InRange(len.clone(), 5, 9)], &len)
            .unwrap();
        assert!((5..=9).contains(&actual));
        // UNSAT -> None.
        assert!(s
            .solve_witness(
                16,
                &[
                    Constraint::Eq(len.clone(), 1),
                    Constraint::Not(Box::new(Constraint::Eq(len.clone(), 1))),
                ],
                &len,
            )
            .is_none());
    }

    #[test]
    fn solve_witness_ladder_escalates_past_first_rung() {
        // A length forced above the 128-byte first rung (but under the 4KB
        // second rung) must still solve — the ladder falls through on the
        // UNSAT first-rung assumption instead of giving up.
        let mut s = Z3Solver::new();
        let len = ext(0, 12); // up to 4095 bits
        let (_bytes, actual) = s
            .solve_witness(4096, &[Constraint::InRange(len.clone(), 2000, 2500)], &len)
            .unwrap();
        assert!((2000..=2500).contains(&actual));
    }

    #[test]
    fn masked_and_range_semantics() {
        let mut s = Z3Solver::new();
        let m = packet_bytes(&mut s, 8, &[Constraint::Masked(ext(0, 8), 0xA0, 0xF0)]).unwrap();
        assert_eq!(m[0] & 0xF0, 0xA0);
        let r = packet_bytes(&mut s, 8, &[Constraint::InRange(ext(0, 8), 5, 7)]).unwrap();
        assert!((5..=7).contains(&r[0]));
    }
}

//! z3 backend for the solver trait.

use super::solver::{Constraint, Solver, Term};
use crate::ir::pb;
use z3::ast::{Ast, BV};

pub(crate) struct Z3Solver {
    ctx: z3::Context,
    /// `PAKELES_SYMEX_XCHECK=1`: decide every `feasible` under BOTH the
    /// field-variable and the packet encoding and panic on disagreement.
    xcheck: bool,
}

/// Per-region field variables for the feasibility encoding: one fresh
/// 64-bit variable per structurally-distinct read term, bounded to the
/// read's width. Equisatisfiable with the packet encoding because read
/// regions within a path are pairwise disjoint (see `Term`'s doc).
struct FieldVars<'a> {
    vars: std::collections::HashMap<Term, BV<'a>>,
    bounds: Vec<z3::ast::Bool<'a>>,
}

impl Z3Solver {
    pub(crate) fn new() -> Self {
        Self {
            ctx: z3::Context::new(&z3::Config::new()),
            xcheck: std::env::var_os("PAKELES_SYMEX_XCHECK").is_some_and(|v| v == "1"),
        }
    }

    /// Packet variable: one bitvector of `packet_bits` (>=1 dummy bit
    /// when the packet is empty, kept unconstrained and unread).
    fn packet<'a>(&'a self, packet_bits: usize) -> BV<'a> {
        BV::new_const(&self.ctx, "packet", packet_bits.max(1) as u32)
    }

    fn term<'a>(&'a self, packet: &BV<'a>, t: &Term) -> BV<'a> {
        match t {
            Term::Const(v) => BV::from_u64(&self.ctx, *v, 64),
            Term::Extract { bit_off, len } => {
                let total = packet.get_size() as usize;
                // MSB-first: bit_off 0 is the packet BV's highest bit.
                let hi = (total - 1 - bit_off) as u32;
                let lo = (total - bit_off - len) as u32;
                packet.extract(hi, lo).zero_ext(64 - *len as u32)
            }
            Term::ExtractAt { off, len } => {
                // MSB-first extract at a symbolic bit offset: the `len` bits
                // at offset `off` occupy LSB positions [w-off-len, w-off),
                // so shift down by (w-len)-off and mask the low `len` bits.
                // `off+len <= w` holds under path constraints, so the shift
                // (w-len)-off does not wrap.
                let w = packet.get_size();
                let len = *len as u32;
                let off64 = self.term(packet, off); // 64-bit value
                let off_w = match w.cmp(&64) {
                    std::cmp::Ordering::Greater => off64.zero_ext(w - 64),
                    std::cmp::Ordering::Less => off64.extract(w - 1, 0),
                    std::cmp::Ordering::Equal => off64,
                };
                let base = BV::from_u64(&self.ctx, (w - len) as u64, w);
                let shift = base.bvsub(&off_w);
                packet.bvlshr(&shift).extract(len - 1, 0).zero_ext(64 - len)
            }
            Term::Bin(op, l, r) => {
                let l = self.term(packet, l);
                let r = self.term(packet, r);
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

    fn constraint<'a>(&'a self, packet: &BV<'a>, c: &Constraint) -> z3::ast::Bool<'a> {
        match c {
            Constraint::Eq(t, v) => self.term(packet, t)._eq(&BV::from_u64(&self.ctx, *v, 64)),
            Constraint::Masked(t, value, mask) => {
                let m = BV::from_u64(&self.ctx, *mask, 64);
                self.term(packet, t)
                    .bvand(&m)
                    ._eq(&BV::from_u64(&self.ctx, value & mask, 64))
            }
            Constraint::InRange(t, lo, hi) => {
                let t = self.term(packet, t);
                z3::ast::Bool::and(
                    &self.ctx,
                    &[
                        &t.bvuge(&BV::from_u64(&self.ctx, *lo, 64)),
                        &t.bvule(&BV::from_u64(&self.ctx, *hi, 64)),
                    ],
                )
            }
            Constraint::Not(inner) => self.constraint(packet, inner).not(),
            Constraint::And(cs) => {
                let bools: Vec<_> = cs.iter().map(|c| self.constraint(packet, c)).collect();
                let refs: Vec<_> = bools.iter().collect();
                z3::ast::Bool::and(&self.ctx, &refs)
            }
        }
    }

    /// Field-variable translation of a term: reads become per-region
    /// 64-bit variables, arithmetic mirrors `term` (same wrapping 64-bit
    /// semantics), and no packet bitvector exists — checks stay
    /// width-independent with no shifters to bit-blast.
    fn feas_term<'a>(&'a self, fv: &mut FieldVars<'a>, t: &Term) -> BV<'a> {
        match t {
            Term::Const(v) => BV::from_u64(&self.ctx, *v, 64),
            Term::Extract { len, .. } | Term::ExtractAt { len, .. } => {
                if let Some(v) = fv.vars.get(t) {
                    return v.clone();
                }
                let var = BV::new_const(&self.ctx, format!("f{}", fv.vars.len()), 64);
                if *len < 64 {
                    fv.bounds
                        .push(var.bvule(&BV::from_u64(&self.ctx, (1u64 << len) - 1, 64)));
                }
                fv.vars.insert(t.clone(), var.clone());
                var
            }
            Term::Bin(op, l, r) => {
                let l = self.feas_term(fv, l);
                let r = self.feas_term(fv, r);
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

    fn feas_constraint<'a>(&'a self, fv: &mut FieldVars<'a>, c: &Constraint) -> z3::ast::Bool<'a> {
        match c {
            Constraint::Eq(t, v) => self.feas_term(fv, t)._eq(&BV::from_u64(&self.ctx, *v, 64)),
            Constraint::Masked(t, value, mask) => {
                let m = BV::from_u64(&self.ctx, *mask, 64);
                self.feas_term(fv, t)
                    .bvand(&m)
                    ._eq(&BV::from_u64(&self.ctx, value & mask, 64))
            }
            Constraint::InRange(t, lo, hi) => {
                let t = self.feas_term(fv, t);
                z3::ast::Bool::and(
                    &self.ctx,
                    &[
                        &t.bvuge(&BV::from_u64(&self.ctx, *lo, 64)),
                        &t.bvule(&BV::from_u64(&self.ctx, *hi, 64)),
                    ],
                )
            }
            Constraint::Not(inner) => self.feas_constraint(fv, inner).not(),
            Constraint::And(cs) => {
                let bools: Vec<_> = cs.iter().map(|c| self.feas_constraint(fv, c)).collect();
                let refs: Vec<_> = bools.iter().collect();
                z3::ast::Bool::and(&self.ctx, &refs)
            }
        }
    }

    /// The pre-lever packet-BV feasibility decision, kept as the
    /// cross-check oracle for the field-variable encoding.
    fn packet_feasible(&self, packet_bits: usize, cs: &[Constraint]) -> bool {
        let packet = self.packet(packet_bits);
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            solver.assert(&self.constraint(&packet, c));
        }
        solver.check() == z3::SatResult::Sat
    }

    /// Read the top `n_bits` of the completed model byte by byte
    /// (MSB-first; a partial trailing byte lands in the high bits, pad bits
    /// zero — canonical form by construction). Indexing is anchored to the
    /// packet BV's true size, so `n_bits < packet.get_size()` (a witness
    /// shorter than its width budget) reads the correct top bits.
    fn model_packet(&self, model: &z3::Model, packet: &BV, n_bits: usize) -> Vec<u8> {
        let total = packet.get_size() as usize;
        let mut bytes = vec![0u8; n_bits.div_ceil(8)];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let msb_off = 8 * i;
            let width = 8.min(n_bits - msb_off);
            let hi = (total - 1 - msb_off) as u32;
            let lo = (total - msb_off - width) as u32;
            let v = model
                .eval(&packet.extract(hi, lo), true)
                .and_then(|b| b.as_u64())
                .unwrap_or(0);
            *byte = (v as u8) << (8 - width);
        }
        bytes
    }
}

impl Solver for Z3Solver {
    fn feasible(&mut self, packet_bits: usize, cs: &[Constraint]) -> bool {
        let mut fv = FieldVars {
            vars: std::collections::HashMap::new(),
            bounds: Vec::new(),
        };
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            let b = self.feas_constraint(&mut fv, c);
            solver.assert(&b);
        }
        for b in &fv.bounds {
            solver.assert(b);
        }
        let sat = solver.check() == z3::SatResult::Sat;
        if self.xcheck {
            let psat = self.packet_feasible(packet_bits, cs);
            assert_eq!(
                sat, psat,
                "encoding disagreement (field={sat}, packet={psat}) on {cs:#?}"
            );
        }
        sat
    }

    fn solve_witness(
        &mut self,
        width: usize,
        cs: &[Constraint],
        len: &Term,
    ) -> Option<(Vec<u8>, usize)> {
        // Small-not-minimal witness via a plain solver and a length ladder:
        // try `len <= 128B`, then `<= 4KB`, then unbounded — first SAT wins.
        // OMT `Optimize::minimize` solved the same queries 1.6x slower for a
        // ~7% witness-size win (linux_flow_dissector, 779 paths: 38.6min ->
        // 24.1min solve, 51KB -> 55KB total witness bytes; unbounded plain
        // SAT is 2x faster again but bloats witnesses 22x — measured
        // 2026-07-25). Assumptions (not asserts) keep learned clauses valid
        // across rungs.
        const LADDER_BITS: [Option<u64>; 3] = [Some(128 * 8), Some(4096 * 8), None];
        let packet = self.packet(width);
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            solver.assert(&self.constraint(&packet, c));
        }
        let len_bv = self.term(&packet, len);
        for bound in LADDER_BITS {
            let assumptions: Vec<z3::ast::Bool> = match bound {
                Some(b) => vec![len_bv.bvule(&BV::from_u64(&self.ctx, b, 64))],
                None => vec![],
            };
            if solver.check_assumptions(&assumptions) == z3::SatResult::Sat {
                let model = solver.get_model().expect("model after sat");
                let actual = model.eval(&len_bv, true).and_then(|b| b.as_u64())? as usize;
                return Some((self.model_packet(&model, &packet, actual), actual));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::pb::BinOpKind;

    fn ext(bit_off: usize, len: usize) -> Term {
        Term::Extract { bit_off, len }
    }

    /// Packet-encoding witness bytes for a fully-`w`-bit packet — the
    /// old `check` surface the byte-semantics tests were written
    /// against, now reached through `solve_witness`.
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

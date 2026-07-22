//! z3 backend for the solver trait.

use super::solver::{Constraint, Solver, Term};
use crate::ir::pb;
use z3::ast::{Ast, BV};

pub(crate) struct Z3Solver {
    ctx: z3::Context,
}

impl Z3Solver {
    pub(crate) fn new() -> Self {
        Self {
            ctx: z3::Context::new(&z3::Config::new()),
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

    /// Read the top `n_bits` of the completed model byte by byte
    /// (MSB-first; a partial trailing byte lands in the high bits, pad bits
    /// zero — canonical form by construction). Indexing is anchored to the
    /// packet BV's true size, so `n_bits < packet.get_size()` (a minimized
    /// witness shorter than its width budget) reads the correct top bits.
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
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> Option<Vec<u8>> {
        let packet = self.packet(packet_bits);
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            solver.assert(&self.constraint(&packet, c));
        }
        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model().expect("model after sat");
                Some(self.model_packet(&model, &packet, packet_bits))
            }
            _ => None,
        }
    }

    fn solve_witness(
        &mut self,
        width: usize,
        cs: &[Constraint],
        len: &Term,
    ) -> Option<(Vec<u8>, usize)> {
        let packet = self.packet(width);
        let opt = z3::Optimize::new(&self.ctx);
        for c in cs {
            opt.assert(&self.constraint(&packet, c));
        }
        // Minimize the total-length term → smallest packet for this path.
        // Lengths are small positive values (< 2^63), so unsigned vs.
        // signed BV optimization coincide.
        let len_bv = self.term(&packet, len);
        opt.minimize(&len_bv);
        match opt.check(&[]) {
            z3::SatResult::Sat => {
                let model = opt.get_model().expect("model after sat");
                let actual = model.eval(&len_bv, true).and_then(|b| b.as_u64())? as usize;
                Some((self.model_packet(&model, &packet, actual), actual))
            }
            _ => None,
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

    #[test]
    fn trivial_sat_and_unsat() {
        let mut s = Z3Solver::new();
        let sat = s.check(16, &[Constraint::Eq(ext(0, 8), 0xAB)]);
        assert_eq!(sat.unwrap()[0], 0xAB);
        let unsat = s.check(
            16,
            &[
                Constraint::Eq(ext(0, 8), 1),
                Constraint::Not(Box::new(Constraint::Eq(ext(0, 8), 1))),
            ],
        );
        assert!(unsat.is_none());
    }

    #[test]
    fn extract_is_msb_first() {
        let mut s = Z3Solver::new();
        // Constrain bits 4..12 (the middle byte-straddling 8 bits).
        let bytes = s.check(16, &[Constraint::Eq(ext(4, 8), 0xBC)]).unwrap();
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
        let bytes = s.check(8, &[Constraint::Eq(term, 4)]).unwrap();
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
        let bytes = s
            .check(
                24,
                &[
                    Constraint::Eq(off.clone(), 8),
                    Constraint::Eq(read.clone(), 0xBC),
                ],
            )
            .unwrap();
        assert_eq!(bytes[0], 8);
        assert_eq!(bytes[1], 0xBC);
        let bytes = s
            .check(24, &[Constraint::Eq(off, 16), Constraint::Eq(read, 0xBC)])
            .unwrap();
        assert_eq!(bytes[0], 16);
        assert_eq!(bytes[2], 0xBC);
    }

    #[test]
    fn solve_witness_minimizes_length() {
        // len term = ext(0,4) (a nibble length in [0,15]); minimizing over
        // a 16-bit width picks the smallest feasible length. Unconstrained
        // -> 0; constrained InRange[5,9] -> 5. The returned packet is
        // exactly `actual` bits.
        let mut s = Z3Solver::new();
        let len = ext(0, 4);
        let (bytes, actual) = s.solve_witness(16, &[], &len).unwrap();
        assert_eq!(actual, 0);
        assert!(bytes.is_empty());
        let (_bytes, actual) = s
            .solve_witness(16, &[Constraint::InRange(len.clone(), 5, 9)], &len)
            .unwrap();
        assert_eq!(actual, 5);
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
    fn masked_and_range_semantics() {
        let mut s = Z3Solver::new();
        let m = s
            .check(8, &[Constraint::Masked(ext(0, 8), 0xA0, 0xF0)])
            .unwrap();
        assert_eq!(m[0] & 0xF0, 0xA0);
        let r = s.check(8, &[Constraint::InRange(ext(0, 8), 5, 7)]).unwrap();
        assert!((5..=7).contains(&r[0]));
    }
}

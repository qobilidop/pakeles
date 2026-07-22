//! Deliberately minimal solver abstraction — not a pysmt. The engine
//! compiles path conditions to this tiny constraint form; backends
//! decide bitvector encodings. z3 is the only backend in slice 2; the
//! trait exists so solver-agnostic benchmarking stays possible.

use crate::ir::pb;

/// A 64-bit term over the symbolic packet.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Term {
    /// Zero-extended extract of `len` bits (MSB-first) at a CONCRETE
    /// `bit_off`. The common case (fields before any var-length region).
    Extract {
        bit_off: usize,
        len: usize,
    },
    /// Zero-extended extract of `len` bits (MSB-first) at a SYMBOLIC bit
    /// offset `off` from the packet start — a field placed after a
    /// variable-length region, whose offset is an expression over earlier
    /// fields. `off + len <= packet width` holds under the path
    /// constraints (offsets accumulate bounded var-lengths; see
    /// engine::walk_extracts), so the shift-mask encoding never wraps.
    ExtractAt {
        off: Box<Term>,
        len: usize,
    },
    Const(u64),
    Bin(pb::BinOpKind, Box<Term>, Box<Term>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Constraint {
    Eq(Term, u64),
    /// key & mask == value & mask
    Masked(Term, u64, u64),
    /// lo <= key <= hi (unsigned, inclusive)
    InRange(Term, u64, u64),
    Not(Box<Constraint>),
    And(Vec<Constraint>),
}

pub(crate) trait Solver {
    /// SAT: a completed packet of exactly ceil(packet_bits/8) bytes
    /// (unconstrained bits filled by solver model completion).
    /// None: UNSAT. Used only for feasibility (path pruning); the witness
    /// packet comes from `solve_witness`.
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> Option<Vec<u8>>;

    /// One minimal-length witness for a control-flow path: solve `cs` over
    /// a `width`-bit packet MINIMIZING the total-length term `len`, then
    /// return `(packet, actual_bits)` where `actual_bits` is `len` in the
    /// model and `packet` is exactly its top `actual_bits` bits (canonical,
    /// partial trailing byte zero-padded). `None` if UNSAT. `width` is the
    /// per-path upper bound on `len` (see engine `Frame::cursor_max`), so
    /// every read fits inside the packet BV.
    fn solve_witness(
        &mut self,
        width: usize,
        cs: &[Constraint],
        len: &Term,
    ) -> Option<(Vec<u8>, usize)>;
}

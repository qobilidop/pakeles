//! Deliberately minimal solver abstraction — not a pysmt. The engine
//! compiles path conditions to this tiny constraint form; backends
//! decide bitvector encodings. z3 is the only backend in slice 2; the
//! trait exists so solver-agnostic benchmarking stays possible.

use crate::ir::pb;

/// A 64-bit term over the symbolic packet.
///
/// `Eq + Hash` because the field-variable encoding keys per-region
/// variables by structural term identity: the engine only ever builds
/// `Extract`/`ExtractAt` from its placed map, so structurally equal
/// read terms denote the same placement (region) and distinct ones
/// denote disjoint regions (the cursor only advances).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// One-shot path feasibility: SAT/UNSAT of `cs` — the stateless
    /// twin of `Session::check`, kept as the encoding's directly-
    /// testable surface (production enumeration always goes through a
    /// session). `packet_bits` only feeds the packet-encoding
    /// cross-check (`PAKELES_SYMEX_XCHECK=1`).
    #[cfg_attr(not(test), allow(dead_code))]
    fn feasible(&mut self, packet_bits: usize, cs: &[Constraint]) -> bool;

    /// Open an incremental session whose push/pop scopes mirror the
    /// engine's DFS: each fork asserts only its constraint delta, checks
    /// against the accumulated stack, and witnesses are extracted from
    /// the hot solver state at path-emit time.
    fn session<'s>(&'s mut self) -> Box<dyn Session + 's>;

    /// One-shot small-length witness for a constraint set: the stateless
    /// twin of `Session::witness` (same ladder, same constructed-packet
    /// semantics), kept as the directly-testable surface. `(packet,
    /// actual_bits)` with the packet exactly `actual_bits` bits
    /// (canonical, partial trailing byte zero-padded); `None` if UNSAT.
    /// `width` is obsolete in the field-variable backend.
    #[cfg_attr(not(test), allow(dead_code))]
    fn solve_witness(
        &mut self,
        width: usize,
        cs: &[Constraint],
        len: &Term,
    ) -> Option<(Vec<u8>, usize)>;
}

/// Incremental solving over the engine's DFS. Scope discipline: the
/// engine pushes a scope, asserts the fork's constraint delta, checks
/// and/or recurses, then pops — so the solver stack always equals the
/// current frame's constraint vector, and z3 reuses learned state
/// across the (sibling- and prefix-heavy) query stream.
pub(crate) trait Session {
    fn push(&mut self);
    fn pop(&mut self);
    /// Assert `delta` in the current scope.
    fn assert_cs(&mut self, delta: &[Constraint]);
    /// SAT/UNSAT of the current stack. `packet_bits` and `full_cs`
    /// (the frame's complete constraint vector, equal to the stack)
    /// only feed the packet-encoding cross-check.
    fn check(&mut self, packet_bits: usize, full_cs: &[Constraint]) -> bool;
    /// Witness for the current stack, preferring a small `len` (same
    /// ladder as `solve_witness`): `(packet, actual_bits)`. Only regions
    /// reachable from `full_cs` + `len` are materialized — the session's
    /// variable cache may hold sibling branches' regions, which must not
    /// leak into this path's packet. `None` = UNSAT (an engine bug at
    /// emit time: every emitted path's stack was checked feasible).
    /// Also returns how many ladder rungs were attempted (telemetry).
    /// `min_bits` is a static lower bound on `len` — rungs below it are
    /// skipped without a solver call (they are provably UNSAT).
    fn witness(
        &mut self,
        full_cs: &[Constraint],
        len: &Term,
        min_bits: usize,
    ) -> (Option<(Vec<u8>, usize)>, u8);
}

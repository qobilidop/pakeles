//! Symbolic execution over the IR (slice 2 core).

pub mod cov;
pub mod engine;
pub mod lint;
pub mod pathid;
pub(crate) mod solver;
pub mod testgen;
pub(crate) mod z3solver;

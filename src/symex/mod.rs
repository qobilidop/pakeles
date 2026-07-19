//! Symbolic execution over the IR (slice 2 core).

pub mod cov;
pub mod engine;
pub mod lint;
pub mod pathid;
pub mod testgen;
pub(crate) mod solver;
pub(crate) mod z3solver;

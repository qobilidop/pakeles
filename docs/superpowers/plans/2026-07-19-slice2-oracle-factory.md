# PakelesIR Slice 2 ("The Oracle Factory") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Symbolic execution over the IR yielding `pakeles testgen` (path-complete committed vector suite), `pakeles lint`, `pakeles cov`, and path-sensitive validation — per `../specs/2026-07-19-slice2-design.md`.

**Architecture:** New `src/testvec.rs` (proto io + BitString canonicalization), `src/symex/` (engine: layout-concretized path enumeration; solver trait; z3 impl), interp gains an optional decision trace, validate gains a dataflow pass. CLI: `testgen`, `lint`, `cov`.

**Tech Stack:** z3 crate (system libz3, bindgen) behind default-on `symex` feature.

## Global Constraints

- All commands via `./dev.sh`. Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint`.
- Proto-first: testvec schema is normative; expressions/messages never Rust-only.
- No silent caps: the all-SAT length cap (1024) errors loudly when hit.
- Commit per green task, Claude trailer.

### Task 1: testvec proto + BitString canonicalization

Create `proto/pakeles/testvec/v1alpha1/testvec.proto` (package `pakeles.testvec.v1alpha1`; imports nothing):
`BitString{string data_hex=1; uint64 bit_len=2}`;
`TestSuite{string parser_name=1; string ir_version=2; repeated TestVector vectors=3}`;
`TestVector{string id=1; Category category=2; BitString packet=3; Expected expected=4}`;
`enum Category{UNSPECIFIED/ACCEPT/REJECT/TRUNCATION}`;
`Expected{oneof outcome{Accepted accept=1; Rejected reject=2}}`;
`Accepted{repeated ExpectedHeader headers=1}`; `Rejected{string reason=1}`;
`ExpectedHeader{string instance=1; repeated ExpectedField fields=2}`;
`ExpectedField{string name=1; oneof value{uint64 uint=2; string bytes_hex=3}}`.
Extend `build.rs` to compile both protos. Create `src/testvec.rs`: `pb` include; `Bits{bytes: Vec<u8>, bit_len: usize}` Rust-native type; `Bits::from_pb(&BitString) -> (Bits, Vec<String> warnings)` (canonicalize: pad/truncate/zero pad bits; warnings on any correction); `Bits::to_pb` (canonical, lowercase hex); suite `to_json/from_json`. Tests: canonicalization (short-pad, long-truncate, pad-bit zeroing, warnings emitted), roundtrip, buf lint. Commit `feat: testvec schema + BitString canonicalization`.

### Task 2: solver trait + z3 backend + devcontainer

Dockerfile: add `libz3-dev libclang-dev` to apt list. Cargo: `z3 = {version="0.12", optional=true}`, `[features] default=["symex"] symex=["dep:z3"]`. Create `src/symex/solver.rs`:
```rust
pub(crate) enum Term { Extract{bit_off: usize, len: usize}, Const(u64), Bin(pb::BinOpKind, Box<Term>, Box<Term>) }
pub(crate) enum Constraint { Eq(Term,u64), Masked(Term,u64,u64), InRange(Term,u64,u64), Not(Box<Constraint>) }
pub(crate) trait Solver {
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> Option<Vec<u8>>; // Sat -> completed packet bytes
    fn all_values(&mut self, packet_bits: usize, cs: &[Constraint], of: &Term, cap: usize) -> anyhow::Result<Vec<u64>>;
}
```
`src/symex/z3solver.rs`: packet = one BV(packet_bits) (guard packet_bits==0: use BV(1) unused); Term→BV via extract+zero-extend to 64; wrapping arith matches interp; model completion for bytes. Tests: trivial eq sat/unsat; all_values on a 4-bit extract returns 16 values; masked/range semantics mirror `eval_entry` (share truth-table test data with interp's tests). Commit.

### Task 3: engine — path enumeration with layout concretization

`src/symex/mod.rs`. Walk from start state, DFS, carrying: concrete bit cursor, per-instance concrete field ranges, constraint stack, depth (reject fork at max_depth like interp), path-ID segments. Var-length field: build Term from its expr over already-placed fields; `all_values` (cap 1024) → fork per value with `Eq(len_term, v)` pushed, ID segment `state.field=<v>b`; a value making cursor overflow usize or exceed a sanity bound (1 MiB) becomes a REJECT `out of bounds` path (witness = bits up to the var field's start). Truncation forks: after enumerating a state's extracts, for each field emit truncation path `!trunc@inst.field` with bit_len = field_off + len − 1 (skip len==0 var fields). Select: per arm push entry constraints + negated earlier arms (Not(entry) per key — note multi-key arms negate the *conjunction*: use `Not` of each earlier arm's per-key conjunction — encode arm condition as Vec<Constraint> and wrap earlier ones in a single Not(And(..)): add `And(Vec<Constraint>)` variant to Constraint for this); SAT-check incrementally, prune UNSAT forks; default arm = all arms negated; missing default = reject `no matching select arm` path. Output: `Vec<Path>{ id, category, bit_len, constraints, outcome_hint }`. Unit tests on tiny hand-built IRs: linear accept (1 path + truncations), select fork counts, shadowed arm pruned (arm `v(3)` after `range(0,7)` yields no path), self-loop depth bound, ihl-style length forking (16 values → 11 accept layouts + 5 oob rejects for a miniature 2-bit version). Commit.

### Task 4: testgen — witnesses, expected outputs, committed suite

`src/symex/testgen.rs`: per path, solver `check` → witness bytes → canonical `Bits{bytes, bit_len}` → run reference interpreter → `Expected` (assert outcome category matches the path's expectation; mismatch = engine bug, hard error). Suite sorted by id. CLI `testgen [--ir] [--out PATH]` (default stdout). Generate + commit `testdata/eth_ipv4_tcp.vectors.json`. Tests: `committed_vectors_replay_green` — load committed suite, run every vector through interp, expected must match (this, not solver re-runs, is the CI-stable check); suite contains all three categories; ids unique & sorted. Commit `feat: testgen + committed conformance suite`.

### Task 5: lint

`src/symex/lint.rs`: from enumeration byproducts — unreachable states (never entered on any feasible path), dead arms (every fork attempt UNSAT), plus validate() errors surfaced and BitString canonical warnings when linting a suite file (later). CLI `lint [--ir]` exit 1 on findings, prints `state parse_x: unreachable` / `state parse_y arm 2: unsatisfiable (shadowed)`. Tests: clean example lints clean; hand-built IR with shadowed arm and orphan state reports both. Commit.

### Task 6: cov + path-sensitive validation

Interp: add `pub trace: Vec<TraceStep>` to ParseResult (`TraceStep{state: String, decision: Decision}`, `Decision::{Arm(usize), Default, Direct}`) — populated always (cheap). Reconstruct path IDs identically to the engine (shared id-building helper in `src/symex/pathid.rs`, used by both; var-length segments from concrete extracted values). CLI `cov --pcap [--ir]`: enumerate total paths (symex), map each packet via trace → id, report `exercised/total` + per-path hit counts, list unexercised ids. Test: fixture pcap covers 4 distinct paths of the example's total; totals match engine count. Validation dataflow: `validate.rs` fixpoint — definitely-extracted instance set per state (intersection over predecessors, start = ∅), select/length refs must be in-set at point of use (intra-state: earlier extracts count); new test: IR referencing a field extracted on only one branch is rejected. Commit.

### Task 7: close-out

Full gate; README: add testgen/lint/cov to quickstart + vectors-are-committed-artifacts note; update spec's slice list if drifted; memory update; merge `slice2-oracle-factory` → main (re-run gate post-merge), push.

## Self-Review Notes

Spec coverage: decisions 1–5 → T3/T4 (paths, witnesses), T1 (format, BitString), T2 (solver); low-level items: concretization T3, truncation T3, IDs T3+T6 shared helper, expected-via-interp T4, trait T2, lint T5, cov T6, dataflow T6, build T2. Type names consistent: `Bits`, `Term`, `Constraint`, `Path`, `TraceStep` defined before use; `Constraint::And` added in T3 where first needed.

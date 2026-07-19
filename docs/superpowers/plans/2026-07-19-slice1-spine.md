# PakelesIR Slice 1 ("The Spine") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One protocol description (Ethernet→IPv4→TCP) authored via a Rust builder, serialized as proto3 IR, executed by a reference interpreter, visualized as Graphviz, and diffed green against `tshark -T json` on a real pcap.

**Architecture:** Single crate `pakeles` (lib + bin). proto3 schema (`pakeles.ir.v1alpha1`) is the normative IR; prost+pbjson generate Rust types with protojson-compliant JSON. Modules: `ir` (generated types + validation), `builder`, `interp`, `viz`, `oracle` (tshark diff), `cli`. All commands run inside the devcontainer image via `./dev.sh` (host has only Docker).

**Tech Stack:** Rust stable (rust:1-bookworm), prost/prost-build 0.13, pbjson/pbjson-build 0.7, serde_json, clap 4, pcap-parser 0.16, insta 1, thiserror 2, anyhow 1; buf CLI for proto lint; tshark + graphviz in-container.

## Global Constraints

- Every build/test command runs as `./dev.sh <cmd>` (docker wrapper); nothing assumes host toolchains.
- The proto schema is normative: no IR concept exists only in Rust. Expressions are operator trees in the schema — no strings-with-syntax.
- `pub(crate)` by default; modules interact through public interfaces only; `ir` depends on no other internal module.
- Test fixtures under `testdata/` are language-neutral data files (pcap, IR JSON, expected JSON).
- Commit after every green test cycle. Commit messages end with the Claude Co-Authored-By trailer.
- Avoid Rust-keyword field names in proto (`default_target` not `default`, `instance` not `as`, `constant` not `const`).

## Design decisions locked by this plan (were open questions)

1. **Automaton encoding: explicit state graph** with a mandatory parser-level `max_depth` bound (per-header-stack bounds join when header stacks land, ≥ slice 5). Rationale: 1:1 with P4's parser sublanguage (the ceiling principle and the future frontend), matches Leapfrog-style automata tooling, natural for the visualizer; a structured-loop view can be derived later, not stored.
2. **Slice-1 operator inventory:** expression ops `ADD, SUB, MUL, SHL, SHR, AND, OR` over `u64`, leaves `constant` and `field` ref; select keysets `value | masked | range`. Comparison lives in select keysets, not general predicates (P4-shaped). Grown, never shrunk, by later slices.
3. **Field extraction semantics:** fixed-width fields are big-endian (network order), MSB-first at bit granularity, value-typed `u64` (width ≤ 64 for now); variable-length fields are opaque byte runs whose length in bytes is an expression over previously extracted fields.
4. **tshark diff scope:** compare only fields annotated `tshark.key`, numeric values only (hex `0x…` or decimal string forms normalized). Address-typed rendering (`ip.src` dotted quad) is out of slice 1 — documented limitation, resolved by the annotation/formatting work in slice 3.

## File Structure

```
.devcontainer/Dockerfile, devcontainer.json
dev.sh                          # docker run wrapper (the only entry point)
rust-toolchain.toml, Cargo.toml, build.rs, .gitignore
buf.yaml                        # lint/breaking config (module root: proto/)
proto/pakeles/ir/v1alpha1/ir.proto
src/lib.rs
src/ir/mod.rs                   # generated-code include + load/save + versioning consts
src/ir/validate.rs              # well-formedness
src/builder.rs                  # ParserBuilder etc.
src/examples.rs                 # eth_ipv4_tcp() description (annotated)
src/interp/mod.rs               # Interp entry: run(ir, bytes) -> ParseResult
src/interp/bits.rs              # read_bits / byte cursor
src/interp/eval.rs              # expr eval + keyset match
src/viz.rs                      # to_dot
src/oracle/mod.rs               # tshark subprocess + JSON field lookup + normalize + diff
src/pcapio.rs                   # minimal pcap writer (fixtures) + pcap-parser read wrapper
src/cli.rs, src/main.rs         # clap: run | viz | diff-tshark
src/bin/gen_fixtures.rs         # writes testdata/basic.pcap deterministically
testdata/basic.pcap             # committed output of gen_fixtures
```

---

### Task 1: Devcontainer + repo scaffolding

**Files:** Create `.devcontainer/Dockerfile`, `.devcontainer/devcontainer.json`, `dev.sh`, `rust-toolchain.toml`, `.gitignore`, `Cargo.toml`, `src/lib.rs`, `src/main.rs`.

**Interfaces:** Produces `./dev.sh <cmd>` — runs any command in the pinned image with repo at `/work`, cargo cache + target in named volumes.

- [ ] **Step 1: Write the Dockerfile**

```dockerfile
FROM rust:1-bookworm

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      protobuf-compiler tshark graphviz \
 && rm -rf /var/lib/apt/lists/*

ARG BUF_VERSION=1.47.2
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf

ENV PROTOC=/usr/bin/protoc CARGO_TARGET_DIR=/target
```

- [ ] **Step 2: Write devcontainer.json**

```json
{
  "name": "pakeles",
  "build": { "dockerfile": "Dockerfile" },
  "workspaceFolder": "/work",
  "workspaceMount": "source=${localWorkspaceFolder},target=/work,type=bind",
  "mounts": [
    "source=pakeles-target,target=/target,type=volume",
    "source=pakeles-cargo,target=/usr/local/cargo/registry,type=volume"
  ]
}
```

- [ ] **Step 3: Write dev.sh (repo root), `chmod +x`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm \
  -v "$PWD":/work -w /work \
  -v pakeles-target:/target \
  -v pakeles-cargo:/usr/local/cargo/registry \
  pakeles-dev "$@"
```

- [ ] **Step 4: Scaffolding files**

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
```
`.gitignore`:
```
/target
```
`Cargo.toml`:
```toml
[package]
name = "pakeles"
version = "0.1.0"
edition = "2021"

[dependencies]
```
`src/lib.rs`: empty for now. `src/main.rs`:
```rust
fn main() {}
```

- [ ] **Step 5: Verify the environment end-to-end**

Run: `./dev.sh cargo test` — expect compile + `0 tests` pass (image builds on first run; slow once).
Run: `./dev.sh sh -c 'protoc --version && buf --version && tshark --version | head -1 && dot -V'` — expect four version lines.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "chore: devcontainer + cargo scaffolding"` (with trailer).

### Task 2: proto3 IR schema + codegen plumbing

**Files:** Create `proto/pakeles/ir/v1alpha1/ir.proto`, `buf.yaml`, `build.rs`, `src/ir/mod.rs`; modify `Cargo.toml`, `src/lib.rs`. Test: `src/ir/mod.rs` (unit tests inline).

**Interfaces:** Produces generated types in `pakeles::ir::pb` (notably `Ir, Parser, HeaderType, Field, State, Transition, Target, Select, SelectArm, KeysetEntry, Expr, BinOp, BinOpKind, Extract, FieldWidth`), plus `ir::to_json(&Ir) -> String`, `ir::from_json(&str) -> Result<Ir>`, `ir::to_bytes(&Ir) -> Vec<u8>`, `ir::from_bytes(&[u8]) -> Result<Ir>`, const `ir::IR_VERSION: &str = "0.1.0"`.

- [ ] **Step 1: Write the schema** — full content of `ir.proto`:

```proto
syntax = "proto3";
package pakeles.ir.v1alpha1;

message Ir {
  string ir_version = 1;
  Parser parser = 2;
}

message Parser {
  string name = 1;
  repeated HeaderType header_types = 2;
  repeated State states = 3;
  string start_state = 4;
  uint32 max_depth = 5;
  map<string, string> annotations = 15;
}

message HeaderType {
  string name = 1;
  repeated Field fields = 2;
  map<string, string> annotations = 15;
}

message Field {
  string name = 1;
  FieldWidth width = 2;
  map<string, string> annotations = 15;
}

message FieldWidth {
  oneof width {
    uint32 bits = 1;      // fixed width, big-endian unsigned, <= 64
    Expr byte_len = 2;    // opaque bytes; length in bytes = expr
  }
}

message Expr {
  oneof kind {
    uint64 constant = 1;
    FieldRef field = 2;
    BinOp bin = 3;
  }
}

message FieldRef {
  string header = 1;      // header *instance* name
  string field = 2;
}

message BinOp {
  BinOpKind op = 1;
  Expr lhs = 2;
  Expr rhs = 3;
}

enum BinOpKind {
  BIN_OP_KIND_UNSPECIFIED = 0;
  BIN_OP_KIND_ADD = 1;
  BIN_OP_KIND_SUB = 2;
  BIN_OP_KIND_MUL = 3;
  BIN_OP_KIND_SHL = 4;
  BIN_OP_KIND_SHR = 5;
  BIN_OP_KIND_AND = 6;
  BIN_OP_KIND_OR = 7;
}

message State {
  string name = 1;
  repeated Extract extracts = 2;
  Transition transition = 3;
  map<string, string> annotations = 15;
}

message Extract {
  string header_type = 1;
  string instance = 2;    // defaults to header_type when empty
}

message Transition {
  oneof kind {
    Target direct = 1;
    Select select = 2;
  }
}

message Target {
  oneof kind {
    string state = 1;
    Accept accept = 2;
    Reject reject = 3;
  }
}

message Accept {}
message Reject { string reason = 1; }

message Select {
  repeated Expr keys = 1;
  repeated SelectArm arms = 2;
  Target default_target = 3;
}

message SelectArm {
  repeated KeysetEntry entries = 1;  // one per key
  Target next = 2;
}

message KeysetEntry {
  oneof kind {
    uint64 value = 1;
    Masked masked = 2;
    Range range = 3;
  }
}

message Masked { uint64 value = 1; uint64 mask = 2; }
message Range { uint64 lo = 1; uint64 hi = 2; }
```

- [ ] **Step 2: buf.yaml (root) with module at proto/**

```yaml
version: v2
modules:
  - path: proto
lint:
  use:
    - STANDARD
breaking:
  use:
    - FILE
```

Run: `./dev.sh buf lint` — expect clean (fix naming complaints if any).

- [ ] **Step 3: build.rs + deps**

`build.rs`:
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/pakeles/ir/v1alpha1/ir.proto";
    println!("cargo:rerun-if-changed={proto}");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor = out.join("ir_descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor)
        .boxed(".pakeles.ir.v1alpha1.BinOp.lhs")
        .boxed(".pakeles.ir.v1alpha1.BinOp.rhs")
        .compile_protos(&[proto], &["proto"])?;
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(&descriptor)?)?
        .build(&[".pakeles.ir.v1alpha1"])?;
    Ok(())
}
```
`Cargo.toml` additions:
```toml
[dependencies]
prost = "0.13"
pbjson = "0.7"
pbjson-types = "0.7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
thiserror = "2"

[build-dependencies]
prost-build = "0.13"
pbjson-build = "0.7"
```

- [ ] **Step 4: Write failing roundtrip test in `src/ir/mod.rs`**

```rust
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/pakeles.ir.v1alpha1.rs"));
    include!(concat!(env!("OUT_DIR"), "/pakeles.ir.v1alpha1.serde.rs"));
}

pub const IR_VERSION: &str = "0.1.0";

use anyhow::Result;
use prost::Message;

pub fn to_bytes(ir: &pb::Ir) -> Vec<u8> { ir.encode_to_vec() }
pub fn from_bytes(b: &[u8]) -> Result<pb::Ir> { Ok(pb::Ir::decode(b)?) }
pub fn to_json(ir: &pb::Ir) -> Result<String> { Ok(serde_json::to_string_pretty(ir)?) }
pub fn from_json(s: &str) -> Result<pb::Ir> { Ok(serde_json::from_str(s)?) }

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> pb::Ir {
        pb::Ir {
            ir_version: IR_VERSION.into(),
            parser: Some(pb::Parser {
                name: "tiny".into(),
                max_depth: 1,
                start_state: "s".into(),
                states: vec![pb::State {
                    name: "s".into(),
                    transition: Some(pb::Transition {
                        kind: Some(pb::transition::Kind::Direct(pb::Target {
                            kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                        })),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }
    }

    #[test]
    fn roundtrip_binary_and_json() {
        let ir = tiny();
        assert_eq!(from_bytes(&to_bytes(&ir)).unwrap(), ir);
        assert_eq!(from_json(&to_json(&ir).unwrap()).unwrap(), ir);
    }
}
```
`src/lib.rs`: `pub mod ir;`

- [ ] **Step 5: Run to fail, then to pass** — `./dev.sh cargo test` (first run fails until build.rs/deps in place; expect final PASS `roundtrip_binary_and_json`).

- [ ] **Step 6: Commit** — `feat: normative proto3 IR schema (v1alpha1) with prost+pbjson codegen`.

### Task 3: IR well-formedness validation

**Files:** Create `src/ir/validate.rs`; modify `src/ir/mod.rs` (`pub mod validate;`).

**Interfaces:** Produces `validate(&pb::Ir) -> Result<(), Vec<String>>` (all violations, human-readable, stable order). Rules: parser present; `max_depth >= 1`; state names unique & non-empty; `start_state` and every `Target::state` resolve; header type names unique; field names unique per header; fixed widths in `1..=64`; select arm `entries.len() == keys.len()`; every `FieldRef` resolves to a field of a header instance extracted earlier on every path to its use point (slice-1 simplification: instance extracted in the *same state, earlier in `extracts`*, or in any state — check global instance existence + intra-state ordering only; document as TODO-tightened-in-slice-2 via symex reachability — this simplification IS the slice boundary, not a placeholder); masked/range/value entries fit the key's bit width when the key is a fixed-width field ref.

- [ ] **Step 1: Failing tests** — one test per rule, e.g.:

```rust
#[test]
fn rejects_unresolved_target() {
    let mut ir = tiny();               // from a shared test-helpers fn
    // point transition at a state that doesn't exist
    set_direct_target(&mut ir, "nope");
    let errs = validate(&ir).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("unknown state `nope`")));
}
```
(Write the full set: `rejects_missing_parser`, `rejects_zero_max_depth`, `rejects_dup_state`, `rejects_unresolved_start`, `rejects_unresolved_target`, `rejects_bad_width`, `rejects_arity_mismatch`, `rejects_unknown_field_ref`, `accepts_tiny`.)

- [ ] **Step 2: Implement** `validate` as a single pass collecting `Vec<String>`; helper `fn targets(t: &pb::Transition) -> Vec<&pb::Target>`.
- [ ] **Step 3: `./dev.sh cargo test validate` → PASS.**
- [ ] **Step 4: Commit** — `feat: IR well-formedness validation`.

### Task 4: Builder API

**Files:** Create `src/builder.rs`; modify `src/lib.rs`.

**Interfaces:** Produces:
```rust
pub struct ParserBuilder { /* name, max_depth, headers, states */ }
impl ParserBuilder {
    pub fn new(name: &str, max_depth: u32) -> Self;
    pub fn header(self, h: HeaderTypeBuilder) -> Self;
    pub fn state(self, s: StateBuilder) -> Self;
    pub fn start(self, state: &str) -> Self;
    pub fn build(self) -> anyhow::Result<pb::Ir>;   // runs validate()
}
pub struct HeaderTypeBuilder;   // ::new(name), .bits(name, n), .bits_ann(name, n, key, val), .var_bytes(name, expr)
pub struct StateBuilder;        // ::new(name), .extract(header_type), .select(keys, arms, default), .goto_(target), .accept(), .reject(reason)
// Expr helpers (free fns): c(u64) -> Expr, f(header, field) -> Expr, mul/sub/add/shl(Expr, Expr) -> Expr
// Target helpers: to(state), accept(), reject(reason)
// Arm helper: arm(entries, target); entry helpers: v(u64), masked(v, m), range(lo, hi)
```

- [ ] **Step 1: Failing test** — build `tiny` with the builder, assert equal to the hand-constructed proto from Task 2's test helper; second test: builder output passes `validate`; third: builder surfaces validation errors (`build()` on bad graph errs).
- [ ] **Step 2: Implement** (thin sugar over pb types — no logic beyond assembling messages and defaulting `instance` to the header type name).
- [ ] **Step 3: `./dev.sh cargo test builder` → PASS. Commit** — `feat: ergonomic builder API`.

### Task 5: Ethernet→IPv4→TCP description

**Files:** Create `src/examples.rs`; modify `src/lib.rs`, `Cargo.toml` (dev-dep `insta = { version = "1", features = ["json"] }`).

**Interfaces:** Produces `examples::eth_ipv4_tcp() -> pb::Ir`. Structure: headers `ethernet{dst:48,src:48,ethertype:16}`, `ipv4{version:4, ihl:4, dscp:6, ecn:2, total_len:16, id:16, flags:3, frag_offset:13, ttl:8, protocol:8, checksum:16, src:32, dst:32, options:var_bytes(sub(mul(f("ipv4","ihl"),c(4)),c(20)))}`, `tcp{sport:16, dport:16, seq:32, ack:32, data_offset:4, reserved:4, flags:8, window:16, checksum:16, urgent:16}`. States: `parse_ethernet` (extract ethernet; select on `f("ethernet","ethertype")`: `0x0800` → `parse_ipv4`, default reject "unsupported ethertype"), `parse_ipv4` (extract ipv4; select on `f("ipv4","protocol")`: `6` → `parse_tcp`, default reject "unsupported ip protocol"), `parse_tcp` (extract tcp; accept). `max_depth: 4`. tshark annotations (`tshark.key`) on: ethertype→`eth.type`, version→`ip.version`, ttl→`ip.ttl`, protocol→`ip.proto`, total_len→`ip.len`, checksum→`ip.checksum`, sport→`tcp.srcport`, dport→`tcp.dstport`.

- [ ] **Step 1: Failing test** — `examples::eth_ipv4_tcp()` passes `validate`; insta JSON snapshot of `ir::to_json` output (`cargo insta` review flow: first run creates snapshot).
- [ ] **Step 2: Implement via builder. `./dev.sh cargo test examples` → PASS (accept snapshot). Commit** — `feat: eth/ipv4/tcp example description`.

### Task 6: Reference interpreter (reject mode)

**Files:** Create `src/interp/mod.rs`, `src/interp/bits.rs`, `src/interp/eval.rs`; modify `src/lib.rs`.

**Interfaces:** Produces:
```rust
pub struct ParseResult { pub outcome: Outcome, pub headers: Vec<ParsedHeader> }
#[derive(PartialEq, Debug)] pub enum Outcome { Accept, Reject { reason: String } }
pub struct ParsedHeader { pub instance: String, pub header_type: String, pub start_bit: usize, pub fields: Vec<ParsedField> }
pub struct ParsedField { pub name: String, pub bit_offset: usize, pub bit_len: usize, pub value: FieldValue }
#[derive(PartialEq, Debug)] pub enum FieldValue { Uint(u64), Bytes(Vec<u8>) }
pub fn run(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<ParseResult>;   // Err = malformed IR only; packet problems are Reject
```
Reject reasons (exact strings, used by tests): `"out of bounds"`, `"max depth exceeded"`, `"no matching select arm"` (only when `default_target` absent), plus description-authored reasons.

- [ ] **Step 1: bits.rs TDD.** Failing tests:
```rust
#[test] fn reads_msb_first() {
    let b = [0xAB, 0xCD];
    assert_eq!(read_bits(&b, 0, 4).unwrap(), 0xA);
    assert_eq!(read_bits(&b, 4, 8).unwrap(), 0xBC);
    assert_eq!(read_bits(&b, 0, 16).unwrap(), 0xABCD);
}
#[test] fn oob_is_none() { assert!(read_bits(&[0xFF], 4, 8).is_none()); }
```
Implement `pub(crate) fn read_bits(bytes: &[u8], bit_off: usize, n: usize) -> Option<u64>` (loop bit-by-bit is fine — this is the *reference*; clarity beats speed).

- [ ] **Step 2: eval.rs TDD.** `eval_expr(&pb::Expr, &Env) -> Result<u64>` with `Env = HashMap<(String, String), u64>`; wrapping arithmetic; `eval_entry(&pb::KeysetEntry, key: u64) -> bool`. Tests: `mul(f(..),c(4))` with env, masked match `(v & m) == (value & m)`, range inclusive.

- [ ] **Step 3: Driver TDD.** Tests in `interp/mod.rs` against `examples::eth_ipv4_tcp()`:
  - `parses_tcp_packet`: hand-built 54-byte Eth+IPv4(ihl=5)+TCP byte vector (write the bytes in the test with named constants); assert Accept, `ethernet.ethertype == 0x0800`, `ipv4.protocol == 6`, `ipv4.options == Bytes(vec![])`, `tcp.dport` correct, header `start_bit`s at 0/112/272.
  - `parses_ihl6_options`: ihl=6 variant, 4 option bytes captured, tcp offset shifts by 32 bits.
  - `rejects_udp`: protocol byte 17 → `Reject{reason: "unsupported ip protocol"}`.
  - `rejects_truncated`: 20-byte packet → `Reject{reason: "out of bounds"}`.
  - `depth_bound_respected`: craft IR with `s -> s` self-loop, `max_depth: 3` → `Reject{reason: "max depth exceeded"}` (validates the loop guard without header stacks).
- [ ] **Step 4: Implement driver** — cursor in bits; per state: run `extracts` (each field via `read_bits`/byte-run, populate env + `ParsedHeader`), then transition (`direct` or select: eval keys, first matching arm wins, else `default_target`, else reject). Depth = states entered.
- [ ] **Step 5: `./dev.sh cargo test interp` → PASS. Commit** — `feat: reference interpreter (reject mode)`.

### Task 7: Fixture pcap + pcap reading

**Files:** Create `src/pcapio.rs`, `src/bin/gen_fixtures.rs`, `testdata/basic.pcap` (generated, committed); modify `Cargo.toml` (`pcap-parser = "0.16"`), `src/lib.rs`.

**Interfaces:** Produces `pcapio::write_pcap(path, &[Vec<u8>]) -> Result<()>` (classic pcap, LINKTYPE_ETHERNET=1, snaplen 65535, zero timestamps for determinism) and `pcapio::read_packets(path) -> Result<Vec<Vec<u8>>>` (via pcap-parser, legacy + pcapng). `gen_fixtures` writes `testdata/basic.pcap`: pkt1 = the Task 6 TCP packet (correct IPv4 checksum — compute by hand once, hardcode), pkt2 = ihl=6 options variant, pkt3 = UDP packet (proto 17), pkt4 = truncated ethernet (10 bytes).

- [ ] **Step 1: Failing test** — write then read roundtrip through a temp file; `read_packets("testdata/basic.pcap")` returns 4 packets with pkt1 54 bytes.
- [ ] **Step 2: Implement; run `./dev.sh cargo run --bin gen_fixtures`; `git add testdata/basic.pcap`.**
- [ ] **Step 3: Integration test** `interp_over_fixture_pcap`: run interpreter over all 4 → `[Accept, Accept, Reject, Reject]`.
- [ ] **Step 4: `./dev.sh cargo test` → PASS. Commit** — `feat: pcap io + deterministic fixture pcap`.

### Task 8: Graphviz visualizer

**Files:** Create `src/viz.rs`; modify `src/lib.rs`.

**Interfaces:** Produces `viz::to_dot(&pb::Ir) -> String` — digraph; box node per state listing extracts; edges labeled with keyset (e.g. `ethertype == 0x0800`, `default`); doubled-circle virtual `accept` node, diamond `reject` nodes labeled with reason.

- [ ] **Step 1: Failing test** — insta snapshot of `to_dot(&examples::eth_ipv4_tcp())`; assert contains `"parse_ipv4" -> "parse_tcp"`.
- [ ] **Step 2: Implement; verify render: `./dev.sh sh -c 'cargo run -- viz > /tmp/g.dot && dot -Tsvg /tmp/g.dot -o /tmp/g.svg && echo OK'` → OK.** (CLI arrives Task 10; until then call via a tiny `#[test]` or defer the dot render check to Task 10 — fold it there if simpler.)
- [ ] **Step 3: Commit** — `feat: parse-graph visualizer`.

### Task 9: tshark oracle diff

**Files:** Create `src/oracle/mod.rs`; modify `src/lib.rs`.

**Interfaces:** Produces:
```rust
pub struct FieldDiff { pub packet: usize, pub tshark_key: String, pub ours: u64, pub theirs: Option<u64>, pub raw: String }
pub struct DiffReport { pub packets: usize, pub compared: usize, pub mismatches: Vec<FieldDiff> }
pub fn diff_pcap(ir: &pb::Ir, pcap: &Path) -> anyhow::Result<DiffReport>;
pub(crate) fn normalize(raw: &str) -> Option<u64>;          // "0x0800"→2048, "6"→6, else None
pub(crate) fn lookup<'a>(layers: &'a serde_json::Value, key: &str) -> Option<&'a str>;
```
Semantics: run `tshark -r <pcap> -T json` as subprocess; for each packet our interpreter Accepts, for each extracted `Uint` field annotated `tshark.key`, look up `_source.layers.<prefix-before-first-dot>.<key>` (value may be string or array-of-strings — take first), normalize, compare. Fields tshark omits count as mismatches (`theirs: None`). Reject-outcome packets are skipped (tshark will still dissect them — that asymmetry is diagnose-mode's future job, out of slice 1).

- [ ] **Step 1: Unit tests (no subprocess):** `normalize` cases; `lookup` against a hand-written `serde_json::json!` layers value including the array case.
- [ ] **Step 2: Integration test** `fixture_pcap_diffs_green` (runs in-container where tshark exists; guard with `if which tshark fails { eprintln!("skipping"); return }` so host IDEs don't break): `diff_pcap(&eth_ipv4_tcp(), "testdata/basic.pcap")` → `mismatches.is_empty()`, `compared >= 16` (8 annotated fields × 2 accepted packets).
- [ ] **Step 3: Implement; `./dev.sh cargo test oracle` → PASS.** Debug loop if red: print tshark's actual JSON for pkt1, fix key names/normalization — the oracle is the boss; our description bends.
- [ ] **Step 4: Commit** — `feat: tshark differential oracle`.

### Task 10: CLI

**Files:** Create `src/cli.rs`; rewrite `src/main.rs`; modify `Cargo.toml` (`clap = { version = "4", features = ["derive"] }`).

**Interfaces:** `pakeles run --pcap <file> [--ir <file.json>]` (default IR: built-in example; prints one JSON line per packet: outcome + fields), `pakeles viz [--ir <file>]` (dot to stdout), `pakeles diff-tshark --pcap <file> [--ir <file>]` (report to stdout; exit 1 on mismatches), `pakeles export-ir [--json|--binary]` (writes the example IR — the file other tools consume).

- [ ] **Step 1: Failing tests** — call `cli::main_with(args: &[&str]) -> anyhow::Result<i32>` directly (no assert_cmd needed): `run` on fixture returns 0 and prints 4 lines; `diff-tshark` on fixture returns 0.
- [ ] **Step 2: Implement thin dispatch onto lib functions. Verify by hand:**
```
./dev.sh cargo run -- diff-tshark --pcap testdata/basic.pcap
./dev.sh sh -c 'cargo run -- viz | dot -Tsvg -o /tmp/g.svg && echo rendered'
```
- [ ] **Step 3: `./dev.sh cargo test` (all) → PASS. Commit** — `feat: pakeles CLI (run, viz, diff-tshark, export-ir)`.

### Task 11: Polish + slice close-out

**Files:** Modify `README.md`; create `docs/superpowers/specs/2026-07-19-slice1-decisions.md`.

- [ ] **Step 1: Full gate:** `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint'` → all green (fix anything that isn't).
- [ ] **Step 2: README** — what PakelesIR is (3 sentences from the spec vision), quickstart (`./dev.sh cargo test`, the three CLI commands), pointer to spec + plan docs.
- [ ] **Step 3: Decisions doc** — record the four "Design decisions locked by this plan" (automaton encoding, op inventory, extraction semantics, tshark-diff scope) with their rationale, marking the corresponding spec open-questions resolved.
- [ ] **Step 4: Commit** — `docs: README + slice-1 design decisions`. Slice 1 done: tag nothing, but update memory.

## Self-Review Notes

- **Spec coverage:** slice-1 spec bullet list = devcontainer ✓(T1), proto schema ✓(T2), builder ✓(T4), interpreter reject mode ✓(T6), Eth→IPv4→TCP ✓(T5), diff-tshark green on real pcap ✓(T7+T9), visualizer ✓(T8). CLI names match spec (`run, diff-tshark, viz`; `vectors/lint/coverage/doc` are later slices; `export-ir` added as the IR-file-as-contract enabler).
- **Type consistency:** `pb::` paths and helper names (`c/f/mul/sub`, `read_bits`, `eval_expr`, `normalize`, `to_dot`, `diff_pcap`) used consistently across tasks; `Outcome::Reject` reasons are exact strings shared by T6 tests, T7 fixture expectations, and T9 skip logic.
- **Known simplification (deliberate, not placeholder):** validation's field-ref scoping is instance-existence + intra-state order, tightened by symex-based reachability in slice 2; tshark diff covers numeric fields only, addresses join in slice 3.

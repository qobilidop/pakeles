# Slice 4 design: the datapath

Date: 2026-07-19. Extends the v0 spec. Deliverables: `gen c` (portable
C99 parser), `gen ebpf` (self-contained eBPF C variant), conformance of
both against the full 164-vector suite (C via a generated harness
binary; eBPF executed under the rbpf userspace VM), gallery additions.
This is the slice where "provably agreeing artifacts" spans four
implementations: interpreter, Lua dissector, C parser, eBPF program.

## Design

- **One core shape for both targets: iterative state loop.** `parse()`
  is a single function: `for (depth = 0; depth < MAX_DEPTH; depth++)
  switch (state) { ... }`. No recursion, no unbounded loops, no calls
  except an inlinable `read_bits` — deliberately the shape the kernel
  verifier wants (bounded loop, flat control flow), and equally clean
  as portable C. The Lua backend's per-state functions were the
  readable-artifact choice; the datapath's choice is
  verifier-compatibility. Both compile from the same IR walk.
- **C API (reject mode, bit-granular)**: `int pk_<name>_parse(const
  uint8_t *buf, uint64_t bit_len, pk_<name>_result_t *out)`.
  Bit-granular length means the C backend is conformance-testable
  against **all 164 vectors** including the bit-granular truncations
  (the Lua backend could only take the 28 byte-aligned ones through
  pcap). Result: outcome + reason code (generated enum: 3 built-ins +
  authored reasons, plus `reason_str()` table) + `consumed_bits` +
  per-instance presence flags + typed field structs (smallest uintN
  fitting the width; variable-length fields as `bit_off`/`bit_len`
  into the caller's buffer — zero-copy).
- **Arithmetic**: u64 wrapping natively matches the reference
  semantics (unlike Lua's signed doubles — one less caveat). Length
  checks in division form (`len > (bit_len - off) / 8`) to avoid u64
  overflow on wrapped lengths.
- **C conformance**: a generated harness `main.c` (stdin: `bit_len
  hex` per vector; stdout: outcome, reason string, consumed bits,
  every field) compiled with `cc -std=c99 -Wall -Werror` in-container;
  the Rust test feeds all 164 vectors and compares against the
  reference interpreter field-for-field.
- **eBPF variant**: single self-contained C file, same iterative core,
  entry `uint64_t pk_entry(void *mem, uint64_t mem_len)` where `mem` =
  8-byte LE bit_len + packet bytes (a harness convention — rbpf's raw
  VM hands us one buffer; in-kernel XDP wiring is future work).
  Returns a packed verdict: outcome(8b) | reason(8b) | consumed(48b).
  Compiled `clang -O2 -target bpf`, `.text` extracted with
  llvm-objcopy, executed under **rbpf** (userspace eBPF VM — no root,
  no kernel). Verdict-level conformance on all 164 vectors;
  field-level conformance is the portable-C harness's job (same
  emitted core). Known bound noted in the generated header: result
  struct lives on the BPF stack (512-byte limit) — large parsers will
  need a redesign when they arrive.
- **Toolchain**: devcontainer adds `clang` + `llvm`; `rbpf` as a
  dev-dependency.
- **Gallery**: `parser.c`, `parser.h`, `ebpf.c` join
  `examples/eth_ipv4_tcp/`, equality-guarded like the rest.

## Non-goals

Kernel loading / XDP section scaffolding / libbpf skeletons (rbpf
proves semantics; kernel packaging is by-pull later), checksum/offload
concerns, `diff rbpf` as a CLI command (tests only this slice), P4
(slice 5).

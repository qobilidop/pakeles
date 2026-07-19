# Pakeles Slice 4 ("The Datapath") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per `../specs/2026-07-19-slice4-design.md`: `gen c`, `gen ebpf`, full-suite conformance for both (C harness binary; rbpf VM), gallery.

**Global constraints:** as prior slices. Generated C must compile with `cc -std=c99 -Wall -Wextra -Werror`; generated eBPF with `clang -O2 -target bpf -Werror`.

### Task 1: C emitter core + `gen c`
`src/codegen/c.rs`: `generate_c(&pb::Ir) -> Result<CArtifacts { header: String, source: String }>`. Header: include guard, `<stdint.h>/<stddef.h>`, outcome enum, reason enum (`PK_R_OUT_OF_BOUNDS/MAX_DEPTH/NO_MATCHING_ARM` + authored reasons sorted, values stable), per-instance field structs (uintN by width; var fields as `bit_off`/`bit_len` u64 pair), result struct (outcome, reason, consumed_bits, per-instance `present` flags + structs), `parse()` + `reason_str()` prototypes, prefix `pk_<parser>_`. Source: `read_bits` (bit loop, static), iterative `for(depth) switch(state)` core; select as if/else on extracted fields (`out->inst.field` promoted to u64); masked `(k & m) == (v & m)`; range `lo <= k && k <= hi`; var-length in division form. Shared expr-to-C emitter. CLI `gen c [--ir] [--out-dir]` writing `<name>.c/.h`. Test: generate for example + tiny IRs; compile in-container `cc -std=c99 -Wall -Wextra -Werror -c` both files — compilation IS the test this task.

### Task 2: C conformance harness — all 164 vectors
`generate_c_harness(&pb::Ir) -> String` (main.c): reads `bit_len hex` lines from stdin; per line: decode hex, call parse, print one line `outcome reason_str consumed inst.field=<dec>… inst.var=<hex|-># …` for present instances (var fields printed as hex slice of buf via bit_off/len, `-` when empty). Rust test `c_backend_conformance`: write parser+harness to tmp, `cc` them, spawn once, feed all 164 vectors (committed suite) on stdin, parse stdout, compare per vector against `interp::run_bits` (outcome, reason, consumed_bits, every field value incl. var bytes). Zero mismatches required.

### Task 3: eBPF variant + rbpf conformance
Dockerfile: add `clang llvm`. Cargo: `[dev-dependencies] rbpf = "0.2"`. `generate_ebpf(&pb::Ir) -> Result<String>`: single file — same core emitted with `static __attribute__((always_inline))` helpers, no libc, entry `uint64_t pk_entry(void *mem, uint64_t mem_len)`: guard `mem_len >= 8`, read LE bit_len, packet = mem+8, guard `bit_len` fits `(mem_len-8)*8`, run core on stack result, return `(outcome<<56)|(reason<<48)|(consumed & 0xFFFFFFFFFFFFULL)`. CLI `gen ebpf [--ir] [--out]`. Test `ebpf_backend_conformance`: emit, `clang -O2 -target bpf -c` to tmp, `llvm-objcopy -O binary --only-section=.text` → raw bytecode, `rbpf::EbpfVmRaw` per vector: mem = bit_len LE bytes + packet; execute; decode verdict; compare outcome+reason+consumed against interp for all 164. Also compile-only check with `-Werror`.

### Task 4: gallery + close-out
`gen_examples` writes `parser.h`, `parser.c`, `ebpf.c`; equality tests beside the generators; example README table rows; main README (quickstart lines + slice-4 status + four-implementations claim); full gate both feature configs; merge `slice4-datapath` → main; push; memory.

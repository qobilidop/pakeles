# Flow-Dissector Rung 0 (Oracle Spine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `linux_flow_dissector` example plus the full oracle spine — a golden factory, a committed version-tagged golden `flow_keys` corpus, and an unprivileged `diff flow-dissector` gate — so Pakeles's extracted `flow_keys` are proven to agree, packet-for-packet, with a flow dissector run *in the kernel*.

**Architecture:** Rung 0 touches no parser IR features (reuses eth/IPv4/IPv6/TCP/UDP parsing). A **privileged, out-of-gate golden factory** compiles a small in-repo flow-dissector BPF program, runs it via `BPF_PROG_TEST_RUN` over a packet corpus, and emits version-tagged golden `flow_keys` (fidelity-identical to upstream `bpf_flow.c` for rung-0 protocols; upstream swaps in at rung 1). The everyday **unprivileged** `diff flow-dissector` oracle runs Pakeles's parse, applies a harness-side `flow_keys` projection (Rust), and compares to the committed goldens.

**Tech Stack:** Rust (crate + oracle), Python eDSL, C (`clang -target bpf` + raw `bpf()` syscall capture), bash, Docker (`./dev.sh` unprivileged; `docker run --privileged` for the factory only).

## Global Constraints

- All normal tooling runs in Docker via `./dev.sh` (unprivileged). The gate stays: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest`.
- **The golden factory (Task 5) requires `bpf()`, which is EPERM under `./dev.sh`.** Run factory steps with `docker run --privileged -v "$PWD":/work -w /work pakeles-dev sh -c '...'` (proven: privileged → `bpf()` works; unprivileged → EPERM). Never wire the factory into the normal gate.
- The eDSL is the single source of truth for examples; `ir.json` is generated + Rust-canonicalized (`pakeles fmt-ir`); regenerate via `scripts/gen-examples.sh`. This plan adds a **second** example, so the generation machinery must generalize to a list, not hardcode one name.
- Rung-0 `flow_keys` subset (the only fields compared): `nhoff, thoff, n_proto, addr_proto, ip_proto, sport, dport, ipv4_src, ipv4_dst, ipv6_src, ipv6_dst`. Fields outside this subset are never compared; document, never silently skip.
- Golden files are **kernel-version-tagged** (`flow_keys.linux-<ver>.golden.json`); the version is recorded inside the file too.
- Commit after every task.

---

### Task 1: `linux_flow_dissector` example + generalize the gen machinery

**Files:**
- Create: `py/src/pakeles/examples/linux_flow_dissector.py`
- Modify: `src/bin/gen_examples.rs` (iterate a list of examples), `scripts/gen-examples.sh` (phase-1 loop)
- Create (generated, committed): `examples/linux_flow_dissector/` (`linux_flow_dissector.ir.json`, `.py` mirror, `gen/*`, `conformance/*`)
- Modify: `src/examples.rs` (add a loader + guards for the new example)

**Interfaces:**
- Produces: `pub fn linux_flow_dissector() -> pb::Ir` (loader, mirrors `eth_ipvx_l4()`); a committed gallery under `examples/linux_flow_dissector/`.

- [ ] **Step 1: Author the eDSL example**

Create `py/src/pakeles/examples/linux_flow_dissector.py` — the rung-0 flow-dissector target. Its parse mirrors `eth_ipvx_l4` (Ethernet → IPv4|IPv6 → TCP|UDP); it is the permanent home the flow-dissector initiative grows in. Copy the structure of `py/src/pakeles/examples/eth_ipvx_l4.py`, rename the parser to `linux_flow_dissector`, and keep the same headers/states (eth, ipv4 with options varbit, ipv6 with 16-byte var_bytes addrs, tcp, udp; demux eth→ipv4/ipv6, ip→tcp/udp). End with:

```python
if __name__ == "__main__":
    print(linux_flow_dissector().to_json())
```

- [ ] **Step 2: Generalize `gen_examples.rs` to a list**

In `src/bin/gen_examples.rs`, extract the per-example body into a helper and call it for each example:

```rust
fn regenerate(name: &str) -> anyhow::Result<()> {
    let dir = std::path::Path::new("examples").join(name);
    let gen = dir.join("gen");
    let conformance = dir.join("conformance");
    std::fs::create_dir_all(&gen)?;
    std::fs::create_dir_all(&conformance)?;
    let ir = pakeles::ir::from_json(&std::fs::read_to_string(dir.join(format!("{name}.ir.json")))?)?;
    std::fs::copy(format!("py/src/pakeles/examples/{name}.py"), dir.join(format!("{name}.py")))?;
    std::fs::write(gen.join("dissector.lua"), pakeles::codegen::lua::generate_lua(&ir)?)?;
    std::fs::write(gen.join("doc.md"), pakeles::docgen::generate_markdown(&ir)?)?;
    std::fs::write(gen.join("graph.dot"), pakeles::viz::to_dot(&ir))?;
    let c = pakeles::codegen::c::generate_c(&ir)?;
    std::fs::write(gen.join("parser.h"), c.header)?;
    std::fs::write(gen.join("parser.c"), c.source)?;
    std::fs::write(gen.join("parser.bpf.c"), pakeles::codegen::c::generate_bpf(&ir)?)?;
    std::fs::write(gen.join("parser.p4"), pakeles::codegen::p4::generate_p4(&ir)?)?;
    let suite = pakeles::symex::testgen::generate(&ir)?;
    std::fs::write(conformance.join("vectors.json"), pakeles::testvec::suite_to_json(&suite)?)?;
    let (packets, _) = pakeles::testvec::suite_to_packets(&suite);
    pakeles::pcapio::write_pcap(&conformance.join("vectors.pcap"), &packets)?;
    let _ = std::process::Command::new("dot").arg("-Tsvg").arg("-o")
        .arg(gen.join("graph.svg")).arg(gen.join("graph.dot")).status();
    println!("examples/{name} regenerated");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    for name in ["eth_ipvx_l4", "linux_flow_dissector"] {
        regenerate(name)?;
    }
    Ok(())
}
```

- [ ] **Step 3: Generalize `scripts/gen-examples.sh`**

Replace the single-example body with a loop:

```bash
#!/usr/bin/env bash
# Regenerate the gallery from its single source of truth, the Python eDSL.
set -euo pipefail
cd "$(dirname "$0")/.."
for name in eth_ipvx_l4 linux_flow_dissector; do
  ir="examples/$name/$name.ir.json"
  mkdir -p "examples/$name"
  tmp="$(mktemp)"
  PYTHONPATH=py/src python3 -m "pakeles.examples.$name" > "$tmp"
  cargo run --quiet --bin pakeles -- fmt-ir --ir "$tmp" --out "$ir"
  rm -f "$tmp"
done
cargo run --quiet --bin gen_fixtures
cargo run --quiet --bin gen_examples
echo "gallery regenerated from py/src/pakeles/examples/*.py"
```

- [ ] **Step 4: Add the loader + guards in `src/examples.rs`**

Add alongside `eth_ipvx_l4()`:

```rust
/// The linux_flow_dissector example, parsed from its committed IR.
pub fn linux_flow_dissector() -> pb::Ir {
    crate::ir::from_json(include_str!(
        "../examples/linux_flow_dissector/linux_flow_dissector.ir.json"
    ))
    .expect("committed linux_flow_dissector IR must parse")
}
```

In the `tests` module add guards mirroring the existing ones (`embedded_ir_parses_and_validates`, `committed_ir_json_is_canonical`, `committed_py_example_current`) but for `linux_flow_dissector` paths.

- [ ] **Step 5: Generate, then run the full gate**

Run: `./dev.sh scripts/gen-examples.sh` (creates/commits the new gallery dir).
Then: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cd py && ruff check . && pyright && pytest' 2>&1 | grep -E "test result:|passed|error|FAILED|Finished"`
Expected: all green; the new example's guards pass; `git status examples/linux_flow_dissector` shows the committed artifacts.

- [ ] **Step 6: Commit**

```bash
git add py/src/pakeles/examples/linux_flow_dissector.py src/bin/gen_examples.rs scripts/gen-examples.sh src/examples.rs examples/linux_flow_dissector Cargo.toml
git commit -m "feat: linux_flow_dissector example + multi-example gen machinery"
```
(Add `examples/linux_flow_dissector/linux_flow_dissector.ir.json` to Cargo's `include` list for the new `include_str!`.)

---

### Task 2: `FlowKeys` data model + golden file format

**Files:**
- Create: `src/oracle/flow_dissector.rs` (start with just the types)
- Modify: `src/oracle/mod.rs` (add `pub mod flow_dissector;`)

**Interfaces:**
- Produces: `FlowKeys` (serde), `GoldenEntry { packet_hex: String, keys: FlowKeys }`, `GoldenFile { kernel_version: String, keys_subset: Vec<String>, entries: Vec<GoldenEntry> }`.

- [ ] **Step 1: Write the failing test**

In `src/oracle/flow_dissector.rs`:

```rust
//! Flow-dissector differential oracle: our parse (projected to bpf_flow_keys)
//! vs golden flow_keys captured from a flow dissector run in the kernel via
//! BPF_PROG_TEST_RUN. Rung 0: eth/IPv4/IPv6/TCP/UDP subset.
use serde::{Deserialize, Serialize};

/// The rung-0 subset of `struct bpf_flow_keys`. Addresses are lowercase
/// hex (ipv4 = 8 chars, ipv6 = 32 chars, empty if absent); ports and
/// protocols are host-order integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowKeys {
    pub nhoff: u16,
    pub thoff: u16,
    pub n_proto: u16,
    pub addr_proto: u16,
    pub ip_proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub ipv4_src: String,
    pub ipv4_dst: String,
    pub ipv6_src: String,
    pub ipv6_dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry { pub packet_hex: String, pub keys: FlowKeys }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub kernel_version: String,
    pub keys_subset: Vec<String>,
    pub entries: Vec<GoldenEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_file_roundtrips() {
        let g = GoldenFile {
            kernel_version: "6.8.0".into(),
            keys_subset: vec!["nhoff".into()],
            entries: vec![GoldenEntry {
                packet_hex: "aabb".into(),
                keys: FlowKeys { nhoff: 14, ..Default::default() },
            }],
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: GoldenFile = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entries[0].keys.nhoff, 14);
        assert_eq!(back.kernel_version, "6.8.0");
    }
}
```

Add `pub mod flow_dissector;` to `src/oracle/mod.rs`.

- [ ] **Step 2: Run to verify fail, then pass**

Run: `./dev.sh cargo test --lib flow_dissector::tests::golden_file_roundtrips 2>&1 | grep -E "test result:|error"`
Expected: fails if `serde`/`serde_json` derive isn't wired; add them if needed (they are already deps via `pbjson`/`serde_json`). Then PASS.

- [ ] **Step 3: Commit**

```bash
git add src/oracle/flow_dissector.rs src/oracle/mod.rs
git commit -m "feat(oracle): flow_keys data model + golden file format"
```

---

### Task 3: Harness-side `flow_keys` projection

**Files:**
- Modify: `src/oracle/flow_dissector.rs`

**Interfaces:**
- Consumes: `crate::interp::{run, ParseResult, ParsedHeader, FieldValue}`.
- Produces: `pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Option<FlowKeys>>` — `None` if the parse rejects (no flow key).

- [ ] **Step 1: Write the failing test**

Add to `src/oracle/flow_dissector.rs`:

```rust
#[cfg(test)]
mod project_tests {
    use super::*;
    #[test]
    fn projects_v4_tcp_fixture() {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::tcp_packet(); // eth/ipv4/tcp, sport 12345 dport 443
        let k = super::project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ipv4_dst, "0a000002");
    }
}
```

- [ ] **Step 2: Implement `project`**

Read the parse result's headers/fields by instance name (the IR uses instances `ethernet, ipv4, ipv6, tcp, udp`). Map: `nhoff` = byte offset (`start_bit/8`) of the `ipv4`/`ipv6` header; `thoff` = offset of `tcp`/`udp`; `n_proto`/`addr_proto` = `ethernet.ethertype`; `ip_proto` = `ipv4.protocol` or `ipv6.next_header`; `sport`/`dport` = transport ports; addresses from the IP header fields (`ipv4.src`/`dst` as `FieldValue::Uint` → 8-hex; `ipv6.src`/`dst` as `FieldValue::Bytes` → 32-hex). Helper to fetch a header by instance and a field's value:

```rust
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Option<FlowKeys>> {
    let res = crate::interp::run(ir, packet)?;
    if !matches!(res.outcome, crate::interp::Outcome::Accept) {
        return Ok(None);
    }
    let hdr = |inst: &str| res.headers.iter().find(|h| h.instance == inst);
    let u = |inst: &str, f: &str| -> Option<u64> {
        hdr(inst)?.fields.iter().find(|x| x.name == f).and_then(|x| match &x.value {
            crate::interp::FieldValue::Uint(v) => Some(*v),
            _ => None,
        })
    };
    let bytes = |inst: &str, f: &str| -> Option<Vec<u8>> {
        hdr(inst)?.fields.iter().find(|x| x.name == f).and_then(|x| match &x.value {
            crate::interp::FieldValue::Bytes(b) => Some(b.clone()),
            _ => None,
        })
    };
    let mut k = FlowKeys::default();
    k.n_proto = u("ethernet", "ethertype").unwrap_or(0) as u16;
    k.addr_proto = k.n_proto;
    let ip_inst = if hdr("ipv4").is_some() { "ipv4" } else { "ipv6" };
    k.nhoff = (hdr(ip_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    if ip_inst == "ipv4" {
        k.ip_proto = u("ipv4", "protocol").unwrap_or(0) as u8;
        k.ipv4_src = format!("{:08x}", u("ipv4", "src").unwrap_or(0));
        k.ipv4_dst = format!("{:08x}", u("ipv4", "dst").unwrap_or(0));
    } else {
        k.ip_proto = u("ipv6", "next_header").unwrap_or(0) as u8;
        k.ipv6_src = bytes("ipv6", "src").map(hex).unwrap_or_default();
        k.ipv6_dst = bytes("ipv6", "dst").map(hex).unwrap_or_default();
    }
    let t_inst = if hdr("tcp").is_some() { "tcp" } else { "udp" };
    k.thoff = (hdr(t_inst).map(|h| h.start_bit).unwrap_or(0) / 8) as u16;
    k.sport = u(t_inst, "sport").unwrap_or(0) as u16;
    k.dport = u(t_inst, "dport").unwrap_or(0) as u16;
    Ok(Some(k))
}

fn hex(b: Vec<u8>) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
```

- [ ] **Step 3: Run the test**

Run: `./dev.sh cargo test --lib flow_dissector::project_tests 2>&1 | grep -E "test result:|FAILED"`
Expected: PASS. (If `thoff`/addr hex differ, the fixture's actual bytes govern — verify against `crate::fixtures::tcp_packet` and adjust the *expected* values, not the projection, unless the projection is wrong.)

- [ ] **Step 4: Commit**

```bash
git add src/oracle/flow_dissector.rs
git commit -m "feat(oracle): parse -> flow_keys projection (harness-side, option A)"
```

---

### Task 4: `diff flow-dissector` oracle + CLI verb

**Files:**
- Modify: `src/oracle/flow_dissector.rs` (add `diff_goldens`), `src/cli.rs` (add `Oracle::FlowDissector`)

**Interfaces:**
- Produces: `pub struct FlowDiffReport { pub compared: usize, pub mismatches: Vec<String> }`, `pub fn diff_goldens(ir: &pb::Ir, golden: &GoldenFile) -> anyhow::Result<FlowDiffReport>`; CLI `pakeles diff flow-dissector --ir <?> --goldens <file>`.

- [ ] **Step 1: Write the failing test**

Add to `src/oracle/flow_dissector.rs`:

```rust
#[cfg(test)]
mod diff_tests {
    use super::*;
    fn golden_from_fixture() -> GoldenFile {
        let ir = crate::examples::linux_flow_dissector();
        let pkt = crate::fixtures::tcp_packet();
        let keys = super::project(&ir, &pkt).unwrap().unwrap();
        GoldenFile {
            kernel_version: "test".into(),
            keys_subset: vec!["nhoff".into(), "thoff".into(), "sport".into(), "dport".into()],
            entries: vec![GoldenEntry {
                packet_hex: pkt.iter().map(|b| format!("{b:02x}")).collect(),
                keys,
            }],
        }
    }
    #[test]
    fn diff_green_on_self() {
        let ir = crate::examples::linux_flow_dissector();
        let report = diff_goldens(&ir, &golden_from_fixture()).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn diff_catches_mismatch() {
        let ir = crate::examples::linux_flow_dissector();
        let mut g = golden_from_fixture();
        g.entries[0].keys.dport = 1; // corrupt
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
    }
}
```

- [ ] **Step 2: Implement `diff_goldens`**

```rust
pub struct FlowDiffReport { pub compared: usize, pub mismatches: Vec<String> }

pub fn diff_goldens(ir: &pb::Ir, golden: &GoldenFile) -> anyhow::Result<FlowDiffReport> {
    let mut report = FlowDiffReport { compared: 0, mismatches: Vec::new() };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = crate::testvec::hex_to_bytes(&e.packet_hex)?; // reuse existing hex decoder
        let ours = project(ir, &pkt)?
            .ok_or_else(|| anyhow::anyhow!("vector {i}: our parse rejected"))?;
        report.compared += 1;
        for field in &golden.keys_subset {
            let (o, t) = field_pair(field, &ours, &e.keys);
            if o != t {
                report.mismatches.push(format!("vector {i}: {field}: ours={o} golden={t}"));
            }
        }
    }
    Ok(report)
}
```

Add a `field_pair(name, ours, golden) -> (String, String)` helper returning the two stringified values for a subset field name (match on the 11 field names). Reuse the crate's existing hex decoder (`crate::testvec` has hex parsing — check its exact name and use it).

- [ ] **Step 3: Wire the CLI verb**

In `src/cli.rs`, add to `enum Oracle`:

```rust
    /// Diff our projected flow_keys against kernel-captured goldens.
    FlowDissector {
        #[arg(long)]
        ir: Option<PathBuf>,
        #[arg(long, default_value = "examples/linux_flow_dissector/conformance/flow_keys.golden.json")]
        goldens: PathBuf,
    },
```

And a match arm in `main_with` mirroring the `Bmv2` arm: load IR (default `linux_flow_dissector()` when `--ir` absent — extend `load_ir` or inline), read+parse the golden JSON, call `diff_goldens`, print mismatches, return 1 on any.

- [ ] **Step 4: Run the tests**

Run: `./dev.sh cargo test --lib flow_dissector 2>&1 | grep -E "test result:|FAILED"`
Expected: all PASS (roundtrip + project + diff green + diff-catches-mismatch).

- [ ] **Step 5: Commit**

```bash
git add src/oracle/flow_dissector.rs src/cli.rs
git commit -m "feat(oracle): diff flow-dissector verb + golden comparison"
```

---

### Task 5: The golden factory (privileged; out of gate)

**Files:**
- Create: `oracle/flow_dissector/factory/flow_dissector.bpf.c` (in-repo minimal dissector, rung-0)
- Create: `oracle/flow_dissector/factory/capture.c` (raw-syscall load + `BPF_PROG_TEST_RUN` + emit golden JSON)
- Create: `oracle/flow_dissector/factory/corpus.txt` (rung-0 packets, one hex per line)
- Create: `oracle/flow_dissector/factory/capture.sh` (build + run + write golden file)
- Create: `dev-priv.sh` (privileged variant of `dev.sh`, for the factory only)

**Interfaces:**
- Produces: `flow_keys.linux-<ver>.golden.json` from a corpus, via `bpf()` in a privileged container.

- [ ] **Step 1: The in-repo flow-dissector BPF program**

`oracle/flow_dissector/factory/flow_dissector.bpf.c` — extend the proven spike program to fill the full rung-0 subset for eth/IPv4/IPv6/TCP/UDP:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define ETH_P_IP_BE   0x0008
#define ETH_P_IPV6_BE 0xdd86
static __attribute__((always_inline)) void ports(void *th, void *end,
        struct bpf_flow_keys *k) {
    struct { __be16 s, d; } *p = th;
    if ((void *)(p + 1) <= end) { k->sport = p->s; k->dport = p->d; }
}
int dissect(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data, *data_end = (void *)(long)skb->data_end;
    struct bpf_flow_keys *k = skb->flow_keys;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return BPF_DROP;
    k->nhoff = sizeof(*eth); k->n_proto = eth->h_proto; k->addr_proto = eth->h_proto;
    if (eth->h_proto == ETH_P_IP_BE) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return BPF_DROP;
        k->ip_proto = ip->protocol; k->ipv4_src = ip->saddr; k->ipv4_dst = ip->daddr;
        k->thoff = sizeof(*eth) + sizeof(*ip);
        if (ip->protocol == 6 || ip->protocol == 17) ports((void *)ip + sizeof(*ip), data_end, k);
    } else if (eth->h_proto == ETH_P_IPV6_BE) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return BPF_DROP;
        k->ip_proto = ip6->nexthdr;
        __builtin_memcpy(k->ipv6_src, &ip6->saddr, 16);
        __builtin_memcpy(k->ipv6_dst, &ip6->daddr, 16);
        k->thoff = sizeof(*eth) + sizeof(*ip6);
        if (ip6->nexthdr == 6 || ip6->nexthdr == 17) ports((void *)ip6 + sizeof(*ip6), data_end, k);
    }
    return BPF_OK;
}
```

- [ ] **Step 2: The capture tool**

`oracle/flow_dissector/factory/capture.c` — reuse the proven spike loader (raw `bpf(BPF_PROG_LOAD, FLOW_DISSECTOR)` + `BPF_PROG_TEST_RUN`), but: read packets (hex) from `corpus.txt`, run each, and print a `GoldenFile` JSON to stdout with `kernel_version` from `uname()` and each entry's `packet_hex` + decoded `FlowKeys` (nhoff, thoff, n_proto=ntohs, addr_proto=ntohs, ip_proto, sport=ntohs, dport=ntohs, ipv4_src/dst as 8-hex, ipv6_src/dst as 32-hex). The raw load + test_run bytes are exactly the spike code that already worked.

- [ ] **Step 3: The privileged runner scripts**

`dev-priv.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t pakeles-dev .devcontainer >/dev/null
exec docker run --rm --privileged -v "$PWD":/work -w /work pakeles-dev "$@"
```
`oracle/flow_dissector/factory/capture.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
ver="$(uname -r)"
clang -O2 -target bpf -I/usr/include/aarch64-linux-gnu -c flow_dissector.bpf.c -o /tmp/fd.o
llvm-objcopy -O binary --only-section=.text /tmp/fd.o /tmp/fd.text
clang -O2 -o /tmp/capture capture.c
/tmp/capture /tmp/fd.text corpus.txt > "../../../examples/linux_flow_dissector/conformance/flow_keys.linux-${ver%%-*}.golden.json"
echo "captured goldens for kernel ${ver}"
```

- [ ] **Step 4: Author the corpus + run the factory (PRIVILEGED)**

Write `corpus.txt` with rung-0 packets (hex, one per line): eth/v4/tcp, eth/v4/udp, eth/v6/tcp, eth/v6/udp (derive from `src/fixtures.rs` or hand-write valid packets).
Run: `chmod +x dev-priv.sh oracle/flow_dissector/factory/capture.sh && ./dev-priv.sh oracle/flow_dissector/factory/capture.sh`
Expected: a `flow_keys.linux-<ver>.golden.json` is written under the example's `conformance/`; eyeball that `nhoff`/`thoff`/ports/addresses are sane for each packet.

- [ ] **Step 5: Commit**

```bash
git add oracle/ dev-priv.sh examples/linux_flow_dissector/conformance/flow_keys.linux-*.golden.json
git commit -m "feat(oracle): golden factory — kernel flow_keys via BPF_PROG_TEST_RUN"
```

---

### Task 6: Close the loop — wire `diff flow-dissector` into the gate

**Files:**
- Modify: `src/oracle/flow_dissector.rs` (a gate test that diffs the committed goldens), `src/cli.rs` (a CLI smoke test)

**Interfaces:**
- Consumes: the committed `flow_keys.linux-*.golden.json` (Task 5) and `linux_flow_dissector()` (Task 1).

- [ ] **Step 1: Write the gate test**

Add to `src/oracle/flow_dissector.rs` (discovers whatever golden file is committed):

```rust
#[test]
fn committed_goldens_agree() {
    let dir = std::path::Path::new("examples/linux_flow_dissector/conformance");
    let golden_path = std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.file_name().unwrap().to_str().unwrap().starts_with("flow_keys.linux-"))
        .expect("a committed golden file exists");
    let g: GoldenFile = serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
    let report = diff_goldens(&crate::examples::linux_flow_dissector(), &g).unwrap();
    assert!(report.compared >= 4, "corpus too small: {}", report.compared);
    assert!(report.mismatches.is_empty(),
        "Pakeles disagrees with the kernel flow dissector:\n{}", report.mismatches.join("\n"));
}
```

- [ ] **Step 2: Run it**

Run: `./dev.sh cargo test --lib committed_goldens_agree 2>&1 | grep -E "test result:|FAILED|disagree"`
Expected: PASS — Pakeles's projected `flow_keys` match the kernel-captured goldens for the whole corpus. **This is rung 0's definition of done.**
If it fails: a real disagreement between our parse/projection and the kernel — investigate (do NOT edit goldens to force green; the kernel is the boss).

- [ ] **Step 3: Full gate**

Run: `./dev.sh sh -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && buf lint && cd py && ruff check . && pyright && pytest' 2>&1 | grep -E "test result:|passed|error|FAILED|Finished|All checks"`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add src/oracle/flow_dissector.rs src/cli.rs
git commit -m "test(oracle): gate on kernel flow_keys agreement (rung 0 DoD)"
```

---

### Task 7: Docs + CI golden-refresh job

**Files:**
- Modify: `README.md`, `examples/linux_flow_dissector/README.md` (create), `.github/workflows/ci.yml`

**Interfaces:** none (docs + CI).

- [ ] **Step 1: Gallery README**

Create `examples/linux_flow_dissector/README.md` explaining: this is the flow-dissector north-star (rung 0 = eth/IPv4/IPv6/TCP/UDP), the golden-diff oracle, that goldens are kernel-`BPF_PROG_TEST_RUN` captures (rung-0 source = in-repo dissector, fidelity-equal to upstream `bpf_flow.c`; upstream arrives at rung 1), and the scope boundary (bounded core, not the heuristic tail). Link the design spec.

- [ ] **Step 2: Root README + factory doc**

Add a line to `README.md` describing `dev-priv.sh` and the golden factory (privileged, out-of-gate; refresh with `./dev-priv.sh oracle/flow_dissector/factory/capture.sh`).

- [ ] **Step 3: CI golden-refresh job (manual/scheduled)**

Add a separate `.github/workflows/flow-dissector-goldens.yml` job (workflow_dispatch + optional schedule) on `ubuntu-latest` (privileged BPF allowed) that runs the factory and uploads/commits refreshed goldens. Keep it OUT of the required gate — the gate only diffs committed goldens (Task 6).

- [ ] **Step 4: Full gate + commit**

Run the full gate once more (expect green), then:
```bash
git add README.md examples/linux_flow_dissector/README.md .github/workflows/flow-dissector-goldens.yml
git commit -m "docs,ci: flow-dissector gallery README + golden-refresh job"
```

---

## Self-Review

**Spec coverage:**
- `linux_flow_dissector` example, own home (rung 0) → Task 1. ✓
- Golden factory (bpf via test_run, version-tagged, privileged) → Task 5. ✓
- Committed golden corpus → Task 5 (corpus + goldens). ✓
- `diff flow-dissector` unprivileged oracle + gate → Tasks 3–4, 6. ✓
- Harness-side projection (option A) → Task 3. ✓
- Output contract (rung-0 subset, documented) → Global Constraints + Task 2. ✓
- Scope boundary + "in-repo dissector now, upstream at rung 1" → Task 7 README. ✓
- No IR changes at rung 0 → confirmed (Task 1 reuses eth/IP/TCP/UDP parsing). ✓

**Placeholder scan:** The BPF program, capture approach (reuses proven spike code), projection, oracle, and CLI wiring have concrete code. Two spots reference existing helpers to look up by exact name rather than reprint (`crate::testvec` hex decoder in Task 4; `Cargo.toml include` in Task 1) — the engineer must grep the one symbol, not invent behavior. Corpus packet bytes (Task 5 Step 4) are authored from `src/fixtures.rs`, named there.

**Type consistency:** `FlowKeys`/`GoldenFile`/`GoldenEntry` defined in Task 2 are used unchanged in Tasks 3/4/6; `project` and `diff_goldens` signatures match across tasks; the `Oracle::FlowDissector` verb matches the existing `Oracle` enum pattern.

**Ordering & risk:** Task 5 is the only privileged, not-in-normal-gate task — flagged in Global Constraints and run via `dev-priv.sh`. Tasks 2–4 are fully testable unprivileged before any golden exists (they use fixture-derived self-goldens). Task 6 depends on Task 5's committed goldens and is the loop-closing DoD. Each task ends green and committed.

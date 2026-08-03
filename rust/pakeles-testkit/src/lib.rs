//! Shared conformance harnesses for the gallery.
//!
//! Every gallery example — synthetic (guarded from the core crate's
//! tests) or real-world (guarded from its own example crate) — runs the
//! same battery: each generated backend is executed for real (cc,
//! clang + rbpf, tshark, BMv2) and compared against the reference
//! interpreter over the committed vector suite, and every committed
//! `gen/` artifact is equality-guarded against fresh generation. This
//! crate exists because `#[cfg(test)]` code cannot cross crate
//! boundaries: the harnesses live here once, dev-depended on by core
//! and by every example crate.
//!
//! Every harness skips (with an eprintln) when its external tool is
//! absent, so the suite degrades gracefully outside the dev container.

use pakeles::interp::{FieldValue, Outcome, ParsedHeader};
use pakeles::ir::pb;
use std::path::Path;

/// Collision-free scratch directory for conformance tests and downstream
/// benchmark tests. Contents are removed automatically when the guard drops.
pub fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
}

/// Load an example's committed conformance suite, or `None` when its
/// `conformance/vectors.json` is absent. The suite is a generated
/// artifact that may be gitignored during fast iteration (it churns on
/// every IR/testgen change), so conformance tests SKIP when it hasn't
/// been regenerated: `./dev.sh scripts/gen-examples.sh`.
pub fn committed_suite(example_dir: &Path) -> Option<pakeles::testvec::ValidatedTestSuite> {
    let path = example_dir.join("conformance/vectors.json");
    if !path.exists() {
        eprintln!(
            "skipping: {} not generated (run ./dev.sh scripts/gen-examples.sh)",
            path.display()
        );
        return None;
    }
    Some(pakeles::testvec::suite_from_json(&std::fs::read_to_string(&path).unwrap()).unwrap())
}

/// Fold repeated instances (loop iterations) down to the LAST
/// occurrence per instance, keeping first-seen order. The interpreter
/// reports every loop iteration in its header list; only the terminal
/// link is stored by the backends and is the conformance surface.
pub fn last_headers_by_instance(headers: &[ParsedHeader]) -> Vec<&ParsedHeader> {
    let mut order: Vec<&str> = Vec::new();
    let mut last: std::collections::HashMap<&str, &ParsedHeader> = std::collections::HashMap::new();
    for h in headers {
        if !order.contains(&h.instance.as_str()) {
            order.push(h.instance.as_str());
        }
        last.insert(h.instance.as_str(), h);
    }
    order.into_iter().map(|i| last[i]).collect()
}

/// Full-suite conformance: the compiled C parser must agree with the
/// reference interpreter on every vector in the suite — including the
/// bit-granular truncations pcap could not carry to the Lua backend —
/// on outcome, reason, consumed bits, and every field. With no suite
/// (not generated, or a non-gallery IR) the compile check still runs.
pub fn c_backend_conformance(
    ir: &pakeles::ir::ValidatedIr,
    suite: Option<&pakeles::testvec::ValidatedTestSuite>,
) {
    if !pakeles::process::is_available("cc", &["--version"]) {
        eprintln!("skipping: cc not available");
        return;
    }
    let name = ir.parser.as_ref().unwrap().name.clone();
    let arts = pakeles::codegen::c::generate_c(ir).unwrap();
    let harness = pakeles::codegen::c::generate_c_harness(ir).unwrap();
    let scratch = tempdir(&format!("pakeles_cconf_{name}_"));
    let dir = scratch.path();
    pakeles::fsutil::atomic_write(&dir.join("parser.h"), &arts.header).unwrap();
    pakeles::fsutil::atomic_write(&dir.join("parser.c"), &arts.source).unwrap();
    pakeles::fsutil::atomic_write(&dir.join("main.c"), &harness).unwrap();
    let cc = pakeles::process::run(
        std::process::Command::new("cc")
            .args([
                "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "parser.c", "main.c", "-o",
                "harness",
            ])
            .current_dir(dir),
        pakeles::process::ProcessLimits::default(),
    )
    .unwrap();
    assert!(
        cc.status.success(),
        "cc: {}",
        String::from_utf8_lossy(&cc.stderr)
    );

    let Some(suite) = suite else {
        return;
    };
    let mut input = String::new();
    let mut bits_list = Vec::new();
    for v in &suite.vectors {
        let (bits, _) = pakeles::testvec::Bits::from_pb(v.packet.as_ref().unwrap()).unwrap();
        let hex = if bits.bytes.is_empty() {
            "-".to_string()
        } else {
            pakeles::testvec::hex_encode(&bits.bytes)
        };
        input.push_str(&format!("{} {hex}\n", bits.bit_len));
        bits_list.push(bits);
    }
    let out = pakeles::process::run_with_input(
        &mut std::process::Command::new(dir.join("harness")),
        Some(input.into_bytes()),
        pakeles::process::ProcessLimits {
            timeout: std::time::Duration::from_secs(300),
            max_output_bytes_per_stream: 512 * 1024 * 1024,
        },
    )
    .unwrap();
    assert!(out.status.success());
    assert!(!out.stdout_truncated, "C harness output exceeded 512 MiB");
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(lines.len(), suite.vectors.len());

    let mut mismatches = Vec::new();
    for ((line, vector), bits) in lines.iter().zip(&suite.vectors).zip(&bits_list) {
        let reference = pakeles::interp::run_bits(ir, bits).unwrap();
        let mut parts = line.split('|');
        let outcome = parts.next().unwrap_or("");
        let reason = parts.next().unwrap_or("");
        let consumed: u64 = parts.next().unwrap_or("0").parse().unwrap_or(u64::MAX);
        let c_fields: std::collections::HashMap<&str, &str> =
            parts.filter_map(|p| p.split_once('=')).collect();

        match &reference.outcome {
            Outcome::Accept => {
                if outcome != "accept" {
                    mismatches.push(format!("{}: outcome {outcome} want accept", vector.id));
                }
            }
            Outcome::Reject { reason: want } => {
                if outcome != "reject" || reason != want {
                    mismatches.push(format!(
                        "{}: outcome/reason {outcome}/{reason} want reject/{want}",
                        vector.id
                    ));
                }
            }
        }
        if consumed != reference.consumed_bits as u64 {
            mismatches.push(format!(
                "{}: consumed {consumed} want {}",
                vector.id, reference.consumed_bits
            ));
        }
        for h in last_headers_by_instance(&reference.headers) {
            for f in &h.fields {
                let key = format!("{}.{}", h.instance, f.name);
                let got = c_fields.get(key.as_str()).copied();
                let want = match &f.value {
                    FieldValue::Uint(u) => u.to_string(),
                    FieldValue::Bits(b) => pakeles::testvec::hex_encode(b),
                };
                // The C parser records a var field's offsets only
                // after the bounds check passes, so a field the
                // interpreter carries as its *failure point* is
                // simply absent — that asymmetry is fine; every
                // *successfully extracted* field must match.
                if let Some(got) = got {
                    if got != want {
                        mismatches.push(format!("{}: {key}={got} want {want}", vector.id));
                    }
                } else if !matches!(&f.value, FieldValue::Bits(b) if b.is_empty()) {
                    mismatches.push(format!("{}: {key} missing (want {want})", vector.id));
                }
            }
        }
        for (name, want) in &reference.metadata {
            let key = format!("meta.{name}");
            let got = c_fields.get(key.as_str()).copied();
            match got {
                Some(got) if got == want.to_string() => {}
                Some(got) => {
                    mismatches.push(format!("{}: {key}={got} want {want}", vector.id));
                }
                None => {
                    mismatches.push(format!("{}: {key} missing (want {want})", vector.id));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// eBPF conformance: compile with clang -target bpf, extract .text,
/// execute under the rbpf userspace VM per vector, compare the packed
/// verdict (outcome | reason | consumed) against the reference
/// interpreter for every vector in the suite. With no suite the
/// compile check still runs.
pub fn bpf_backend_conformance(
    ir: &pakeles::ir::ValidatedIr,
    suite: Option<&pakeles::testvec::ValidatedTestSuite>,
) {
    for tool in ["clang", "llvm-objcopy"] {
        if !pakeles::process::is_available(tool, &["--version"]) {
            eprintln!("skipping: {tool} not available");
            return;
        }
    }
    let name = ir.parser.as_ref().unwrap().name.clone();
    let bpf = pakeles::codegen::c::generate_bpf(ir).unwrap();
    let scratch = tempdir(&format!("pakeles_bpf_{name}_"));
    let dir = scratch.path();
    pakeles::fsutil::atomic_write(&dir.join("bpf.c"), &bpf).unwrap();
    let cc = pakeles::process::run(
        std::process::Command::new("clang")
            .args([
                "-O2", "-target", "bpf", "-Werror", "-c", "bpf.c", "-o", "bpf.o",
            ])
            .current_dir(dir),
        pakeles::process::ProcessLimits::default(),
    )
    .unwrap();
    assert!(
        cc.status.success(),
        "clang: {}",
        String::from_utf8_lossy(&cc.stderr)
    );
    let oc = pakeles::process::run(
        std::process::Command::new("llvm-objcopy")
            .args(["-O", "binary", "--only-section=.text", "bpf.o", "bpf.bin"])
            .current_dir(dir),
        pakeles::process::ProcessLimits::default(),
    )
    .unwrap();
    assert!(
        oc.status.success(),
        "objcopy: {}",
        String::from_utf8_lossy(&oc.stderr)
    );
    let prog = std::fs::read(dir.join("bpf.bin")).unwrap();
    assert!(!prog.is_empty());

    let Some(suite) = suite else {
        return;
    };
    let reasons = pakeles::codegen::c::reason_table(ir.parser.as_ref().unwrap());
    // rbpf's default verifier hardcodes the pre-5.2 kernel's
    // 4096-insn cap; the kernel's own limit has been 1M since 5.2
    // and dpdk_ptype's program crosses 4096. The interp cross-check
    // below is the oracle here, so the verifier only needs
    // well-formedness.
    fn relaxed_verifier(prog: &[u8]) -> Result<(), std::io::Error> {
        if prog.is_empty() || !prog.len().is_multiple_of(8) {
            return Err(std::io::Error::other(
                "program size must be a multiple of 8",
            ));
        }
        Ok(())
    }
    let mut vm = rbpf::EbpfVmRaw::new(None).unwrap();
    vm.set_verifier(relaxed_verifier).unwrap();
    vm.set_program(&prog).unwrap();
    let mut mismatches = Vec::new();
    for v in &suite.vectors {
        let (bits, _) = pakeles::testvec::Bits::from_pb(v.packet.as_ref().unwrap()).unwrap();
        let reference = pakeles::interp::run_bits(ir, &bits).unwrap();
        let mut mem = (bits.bit_len as u64).to_le_bytes().to_vec();
        mem.extend_from_slice(&bits.bytes);
        let verdict = vm.execute_program(&mut mem).unwrap();
        let outcome = (verdict >> 56) as u8;
        let reason_code = ((verdict >> 48) & 0xFF) as u32;
        let consumed = verdict & 0xFFFF_FFFF_FFFF;
        let reason_str = reasons
            .iter()
            .find(|(_, c)| *c == reason_code)
            .map(|(r, _)| r.as_str())
            .unwrap_or("");
        match &reference.outcome {
            Outcome::Accept if outcome == 0 => {}
            Outcome::Reject { reason } if outcome == 1 && reason == reason_str => {}
            other => mismatches.push(format!(
                "{}: verdict outcome={outcome} reason={reason_str:?}, interp {other:?}",
                v.id
            )),
        }
        if consumed != reference.consumed_bits as u64 {
            mismatches.push(format!(
                "{}: consumed {consumed} want {}",
                v.id, reference.consumed_bits
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// Run tshark with args, dropping root (root disables Lua scripts).
fn tshark_unprivileged(args: &[&str]) -> anyhow::Result<pakeles::process::ProcessOutput> {
    let script = r#"if [ "$(id -u)" = "0" ]; then
  exec env HOME=/tmp setpriv --reuid=nobody --regid=nogroup --clear-groups tshark "$@"
else
  exec tshark "$@"
fi"#;
    pakeles::process::run(
        std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("tshark")
            .args(args),
        pakeles::process::ProcessLimits {
            timeout: std::time::Duration::from_secs(300),
            max_output_bytes_per_stream: 512 * 1024 * 1024,
        },
    )
}

type ExpectedFields = Vec<(String, Option<pakeles::testvec::pb::expected_field::Value>)>;

/// interp headers -> the (inst, fields) shape used by the Lua harness.
fn headers_to_expected(headers: &[&ParsedHeader]) -> Vec<(String, ExpectedFields)> {
    headers
        .iter()
        .map(|h| {
            (
                h.instance.clone(),
                h.fields
                    .iter()
                    .map(|f| {
                        let v = match &f.value {
                            FieldValue::Uint(u) => {
                                Some(pakeles::testvec::pb::expected_field::Value::Uint(*u))
                            }
                            FieldValue::Bits(b) => {
                                Some(pakeles::testvec::pb::expected_field::Value::Bits(
                                    pakeles::testvec::Bits {
                                        bytes: b.clone(),
                                        bit_len: f.bit_len,
                                    }
                                    .to_pb(),
                                ))
                            }
                        };
                        (f.name.clone(), v)
                    })
                    .collect(),
            )
        })
        .collect()
}

/// The full loop: symbolic vectors -> pcap -> tshark running our
/// generated dissector -> JSON diffed against expected fields.
pub fn lua_backend_conformance(
    ir: &pakeles::ir::ValidatedIr,
    suite: &pakeles::testvec::ValidatedTestSuite,
    min_compared: usize,
) {
    if !pakeles::process::is_available("tshark", &["--version"]) {
        eprintln!("skipping: tshark not available");
        return;
    }
    let parser = ir.parser.as_ref().unwrap();
    let name = parser.name.clone();
    let proto = format!("pakeles_{}", parser.name);
    let (packets, indices) = pakeles::testvec::suite_to_packets(suite).unwrap();

    let scratch = tempdir(&format!("pakeles_lua_{name}_"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let lua_path = scratch.path().join("dissector.lua");
    let pcap_path = scratch.path().join("vectors.pcap");
    pakeles::fsutil::atomic_write(&lua_path, pakeles::codegen::lua::generate_lua(ir).unwrap())
        .unwrap();
    pakeles::pcapio::write_pcap(&pcap_path, &packets).unwrap();

    let out = tshark_unprivileged(&[
        "-X",
        &format!("lua_script:{}", lua_path.display()),
        "-r",
        pcap_path.to_str().unwrap(),
        "-T",
        "json",
    ])
    .unwrap();
    assert!(
        out.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout_truncated, "tshark JSON exceeded 512 MiB");
    let dissected: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(dissected.len(), packets.len());

    let field_meta = |inst: &str, name: &str| -> Option<&pb::Field> {
        parser.states.iter().find_map(|s| {
            s.extracts.iter().find_map(|ex| {
                (pakeles::codegen::lua::instance_name(ex) == inst)
                    .then(|| {
                        parser
                            .header_types
                            .iter()
                            .find(|h| h.name == ex.header_type)?
                            .fields
                            .iter()
                            .find(|f| f.name == name)
                    })
                    .flatten()
            })
        })
    };

    let mut mismatches: Vec<String> = Vec::new();
    let mut compared = 0usize;
    for (dis, &vi) in dissected.iter().zip(&indices) {
        let vector = &suite.vectors[vi];
        let layers = &dis["_source"]["layers"];
        assert!(
            layers.get(&proto).is_some(),
            "{}: our proto layer missing",
            vector.id
        );
        // Accept vectors carry expected headers in the schema;
        // reject vectors don't, so re-derive them from the
        // reference interpreter (which the suite replay already
        // validates).
        let expected_headers = match vector.expected.as_ref().and_then(|e| e.outcome.as_ref()) {
            Some(pakeles::testvec::pb::expected::Outcome::Accept(a)) => a
                .headers
                .iter()
                .map(|h| {
                    (
                        h.instance.clone(),
                        h.fields
                            .iter()
                            .map(|f| (f.name.clone(), f.value.clone()))
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>(),
            _ => {
                let (bits, _) =
                    pakeles::testvec::Bits::from_pb(vector.packet.as_ref().unwrap()).unwrap();
                let res = pakeles::interp::run_bits(ir, &bits).unwrap();
                headers_to_expected(&last_headers_by_instance(&res.headers))
            }
        };
        // A looped instance (e.g. `ext_opt`) appears more than once in
        // an accept vector's schema-baked headers, but tshark's
        // `-T json` collapses the repeated subtrees under duplicate
        // keys to the last occurrence. Compare against the last
        // occurrence per instance, keeping first-seen order. (The
        // reject branch is already last-per-instance via
        // `last_headers_by_instance`, so this is a no-op there.)
        let expected_headers = {
            let mut order: Vec<String> = Vec::new();
            let mut latest: std::collections::HashMap<String, ExpectedFields> =
                std::collections::HashMap::new();
            for (inst, fields) in expected_headers {
                if !latest.contains_key(&inst) {
                    order.push(inst.clone());
                }
                latest.insert(inst, fields);
            }
            order
                .into_iter()
                .map(|inst| {
                    let fields = latest.remove(&inst).unwrap();
                    (inst, fields)
                })
                .collect::<Vec<_>>()
        };
        for (inst, fields) in &expected_headers {
            for (fname, fval) in fields {
                let key = format!("{proto}.{inst}.{fname}");
                let raw = pakeles::oracle::lookup(layers, &key);
                match fval {
                    Some(pakeles::testvec::pb::expected_field::Value::Uint(want)) => {
                        compared += 1;
                        let format = field_meta(inst, fname)
                            .and_then(|f| f.display.as_ref())
                            .and_then(|d| pb::DisplayFormat::try_from(d.format).ok())
                            .unwrap_or_default();
                        let got = raw.and_then(|r| pakeles::oracle::normalize_typed(r, format));
                        if got != Some(*want) {
                            mismatches
                                .push(format!("{}: {key} ours={want} tshark={raw:?}", vector.id));
                        }
                    }
                    Some(pakeles::testvec::pb::expected_field::Value::Bits(want)) => {
                        if want.bit_len == 0 {
                            continue; // zero-length fields aren't added
                        }
                        // tshark renders byte ranges; the Lua backend
                        // refuses non-whole-byte runs, so data_hex here
                        // is exactly the run's bytes.
                        compared += 1;
                        let got: String = raw
                            .unwrap_or_default()
                            .chars()
                            .filter(|c| *c != ':')
                            .collect::<String>()
                            .to_lowercase();
                        if got != want.data_hex {
                            mismatches.push(format!(
                                "{}: {key} ours={} tshark={got}",
                                vector.id, want.data_hex
                            ));
                        }
                    }
                    None => {}
                }
            }
        }
        // Metadata is per-parse (not per header instance), so it
        // sits outside the per-instance fold above.
        if let Some(pakeles::testvec::pb::expected::Outcome::Accept(a)) =
            vector.expected.as_ref().and_then(|e| e.outcome.as_ref())
        {
            for m in &a.metadata {
                let key = format!("{proto}.meta.{}", m.name);
                compared += 1;
                let raw = pakeles::oracle::lookup(layers, &key);
                let got = raw.and_then(pakeles::oracle::normalize);
                if got != Some(m.value) {
                    mismatches.push(format!(
                        "{}: {key} ours={} tshark={raw:?}",
                        vector.id, m.value
                    ));
                }
            }
        }
    }
    let _ = std::fs::remove_file(&lua_path);
    let _ = std::fs::remove_file(&pcap_path);
    assert!(
        compared >= min_compared,
        "suspiciously few comparisons: {compared}"
    );
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// Verdict-compare the suite's byte-aligned vectors against BMv2
/// `simple_switch` running the generated P4-16 program.
pub fn bmv2_backend_conformance(
    ir: &pakeles::ir::ValidatedIr,
    suite: &pakeles::testvec::ValidatedTestSuite,
    min_compared: usize,
) {
    if !pakeles::oracle::bmv2::tools_available() {
        eprintln!("skipping: p4 toolchain not available");
        return;
    }
    let report = pakeles::oracle::bmv2::diff_suite(ir, suite).unwrap();
    assert!(
        report.compared >= min_compared,
        "suspiciously few byte-aligned vectors: {}",
        report.compared
    );
    assert!(
        report.mismatches.is_empty(),
        "{} mismatches:\n{}",
        report.mismatches.len(),
        report.mismatches.join("\n")
    );
}

/// Equality-guard every committed `gen/` artifact of an example
/// against fresh generation: dissector.lua, parser.h, parser.c,
/// parser.bpf.c, doc.md, graph.dot, and parser.p4 — or, where a
/// backend refuses by design (`gen p4` on region-bearing
/// descriptions, `gen lua` on >32-bit fields), the committed
/// *-UNSUPPORTED.txt marker. Drift means someone edited a
/// generated file or changed a generator without regenerating:
/// `./dev.sh scripts/gen-examples.sh`.
pub fn committed_artifacts_current(ir: &pakeles::ir::ValidatedIr, example_dir: &Path) {
    let gen = example_dir.join("gen");
    let check = |file: &str, fresh: &str| {
        let committed = std::fs::read_to_string(gen.join(file))
            .unwrap_or_else(|e| panic!("{}: {e}", gen.join(file).display()));
        assert_eq!(
            fresh,
            committed,
            "{} drifted; regenerate: ./dev.sh scripts/gen-examples.sh",
            gen.join(file).display()
        );
    };
    match pakeles::codegen::lua::generate_lua(ir) {
        Ok(lua) => check("dissector.lua", &lua),
        // Keep this marker format in step with gen_examples
        // (pakeles-dev), which writes the file.
        Err(e) if e.to_string().contains("not supported by the Lua backend") => check(
            "LUA-UNSUPPORTED.txt",
            &format!("gen lua: {e}\n(see docs/designs/2026-07-31-quic-initial-design.md)\n"),
        ),
        Err(e) => panic!("generate_lua: {e}"),
    }
    let arts = pakeles::codegen::c::generate_c(ir).unwrap();
    check("parser.h", &arts.header);
    check("parser.c", &arts.source);
    check(
        "parser.bpf.c",
        &pakeles::codegen::c::generate_bpf(ir).unwrap(),
    );
    check("doc.md", &pakeles::docgen::generate_markdown(ir).unwrap());
    check("graph.dot", &pakeles::viz::to_dot(ir));
    match pakeles::codegen::p4::generate_p4(ir) {
        Ok(p4) => check("parser.p4", &p4),
        // Keep this marker format in step with gen_examples
        // (pakeles-cli), which writes the file.
        Err(e) if e.to_string().contains("P4-16 parser expressiveness") => check(
            "P4-UNSUPPORTED.txt",
            &format!("gen p4: {e}\n(see docs/superpowers/specs/2026-07-29-sized-region-tlv-ir-design.md)\n"),
        ),
        Err(e) => panic!("generate_p4: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pakeles::interp::ParsedField;

    #[test]
    fn last_headers_by_instance_folds_loops() {
        let mk = |inst: &str, next: u64, off: usize| ParsedHeader {
            instance: inst.into(),
            header_type: inst.into(),
            start_bit: off,
            fields: vec![ParsedField {
                name: "next_header".into(),
                value: FieldValue::Uint(next),
                bit_offset: off,
                bit_len: 8,
            }],
        };
        let hs = vec![
            mk("ipv6", 60, 112),
            mk("ext_opt", 0, 432),  // DestOpts (first link)
            mk("ext_opt", 17, 496), // HopByHop (last link)
            mk("udp", 0, 560),
        ];
        let last = last_headers_by_instance(&hs);
        let insts: Vec<&str> = last.iter().map(|h| h.instance.as_str()).collect();
        assert_eq!(insts, ["ipv6", "ext_opt", "udp"]); // one ext_opt, first-seen order
        let ext = last.iter().find(|h| h.instance == "ext_opt").unwrap();
        match &ext.fields[0].value {
            FieldValue::Uint(v) => assert_eq!(*v, 17), // the LAST link's next_header
            _ => panic!(),
        }
    }
}

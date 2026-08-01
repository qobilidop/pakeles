//! C99 emitter (portable datapath parser) and its eBPF variant.
//!
//! Both targets share one core shape: a single `parse` function built
//! as `for (depth) { switch (state) { ... } }` — no recursion, no
//! unbounded loops, no external calls. That is deliberately the shape
//! the kernel verifier wants, and it is equally clean as portable C.
//!
//! u64 wrapping arithmetic matches reference semantics natively.
//! Length feasibility uses division form to dodge u64 overflow on
//! wrapped lengths.

use crate::ir::pb;
use anyhow::{bail, Context, Result};
use std::fmt::Write;

pub struct CArtifacts {
    pub header: String,
    pub source: String,
}

/// One header per distinct instance name, keeping the LAST extraction
/// (matching datapath backends, which overwrite a single struct per
/// instance). Preserves first-seen instance order. Rung 2: stacked
/// instances (loop back-edges) appear multiple times in the interpreter's
/// header list; only the terminal link is stored by the backends and is
/// the conformance surface.
///
/// Reasons get stable codes: the three built-ins, then authored
/// reasons sorted. Returns (reason, code) pairs. Public because the
/// conformance harness (pakeles-testkit) decodes the eBPF verdict's
/// reason byte with it — it is part of the generated ABI.
pub fn reason_table(parser: &pb::Parser) -> Vec<(String, u32)> {
    let mut authored = std::collections::BTreeSet::new();
    let mut visit_target = |t: &pb::Target| {
        if let Some(pb::target::Kind::Reject(r)) = &t.kind {
            authored.insert(r.reason.clone());
        }
    };
    for s in &parser.states {
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => visit_target(t),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = &arm.next {
                        visit_target(t);
                    }
                }
                if let Some(t) = &sel.default_target {
                    visit_target(t);
                }
            }
            None => {}
        }
    }
    let mut out = vec![
        ("out of bounds".to_string(), 1),
        ("max depth exceeded".to_string(), 2),
        ("no matching select arm".to_string(), 3),
        ("out of region bounds".to_string(), 4),
        ("region out of bounds".to_string(), 5),
        ("region not exhausted".to_string(), 6),
    ];
    let mut next = 16u32;
    for r in authored {
        if out.iter().any(|(existing, _)| *existing == r) {
            continue;
        }
        out.push((r, next));
        next += 1;
    }
    out
}

fn reason_ident(reason: &str) -> String {
    let mut s = String::from("PK_R_");
    for ch in reason.chars() {
        s.push(if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    s
}

fn uint_type(bits: u32) -> &'static str {
    match bits {
        1..=8 => "uint8_t",
        9..=16 => "uint16_t",
        17..=32 => "uint32_t",
        _ => "uint64_t",
    }
}

/// Header instances in extraction order: (instance, header type).
fn instances(parser: &pb::Parser) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for s in &parser.states {
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                ex.header_type.clone()
            } else {
                ex.instance.clone()
            };
            if !out.iter().any(|(i, _)| *i == inst) {
                out.push((inst, ex.header_type.clone()));
            }
        }
    }
    out
}

fn expr_c(e: &pb::Expr) -> Result<String> {
    match e.kind.as_ref() {
        // Structural bytes to the innermost region end. Only legal
        // with a region open (validator), so rsp >= 1 here; the mask
        // keeps the index verifier-bounded (see `region_locals`).
        Some(pb::expr::Kind::Remaining(_)) => {
            Ok("((pk_region_end[(pk_rsp - 1u) & PK_RMASK] - off) >> 3)".to_string())
        }
        Some(pb::expr::Kind::Constant(v)) => Ok(format!("{v}ULL")),
        Some(pb::expr::Kind::Field(r)) => Ok(format!("(uint64_t)out->{}.{}", r.header, r.field)),
        Some(pb::expr::Kind::Bin(b)) => {
            let l = expr_c(
                b.lhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
            )?;
            let r = expr_c(
                b.rhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
            )?;
            let op = match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Add) => "+",
                Ok(pb::BinOpKind::Sub) => "-",
                Ok(pb::BinOpKind::Mul) => "*",
                Ok(pb::BinOpKind::Shl) => "<<",
                Ok(pb::BinOpKind::Shr) => ">>",
                Ok(pb::BinOpKind::And) => "&",
                Ok(pb::BinOpKind::Or) => "|",
                _ => bail!("unspecified binop"),
            };
            Ok(format!("({l} {op} {r})"))
        }
        Some(pb::expr::Kind::Metadata(r)) => Ok(format!("out->m_{}", r.name)),
        None => bail!("empty expression"),
    }
}

fn entry_c(entry: &pb::KeysetEntry, key: &str) -> String {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => format!("{key} == {v}ULL"),
        Some(pb::keyset_entry::Kind::Masked(m)) => {
            format!("({key} & {}ULL) == {}ULL", m.mask, m.value & m.mask)
        }
        Some(pb::keyset_entry::Kind::Range(r)) => {
            format!("({}ULL <= {key} && {key} <= {}ULL)", r.lo, r.hi)
        }
        None => "0".into(),
    }
}

/// eBPF buffer contract: the caller must pass a buffer of at least
/// `PK_BUF_MASK + 1` bytes, and packets no longer than that. Every
/// packet index is masked with it, which is DEAD for in-contract
/// packets (the length guards already bound each access) but
/// load-bearing for the kernel verifier — it bounds the index register
/// directly instead of relying on back-propagation from a guard on a
/// derived value. Same device as the region-stack index mask.
///
/// The default covers every committed conformance vector; a caller with
/// a smaller scratch buffer (an XDP wrapper, say) overrides it with
/// `-DPK_BUF_MASK=...` to give the verifier a tighter bound.
const BPF_BUF_MASK: usize = 4095;

struct Emit<'a> {
    parser: &'a pb::Parser,
    prefix: String,
    reasons: Vec<(String, u32)>,
    /// Static state-entry bit alignment, for the byte-load fast path.
    entry_align: std::collections::HashMap<String, Option<u32>>,
    /// eBPF variant: mask every packet index (see `BPF_BUF_MASK`).
    masked_loads: bool,
}

impl<'a> Emit<'a> {
    fn new(parser: &'a pb::Parser) -> Self {
        Self {
            prefix: format!("pk_{}", parser.name),
            reasons: reason_table(parser),
            entry_align: super::entry_alignments(parser),
            masked_loads: false,
            parser,
        }
    }

    /// The eBPF variant of the same emitter.
    fn new_bpf(parser: &'a pb::Parser) -> Self {
        Self {
            masked_loads: true,
            ..Self::new(parser)
        }
    }

    /// Packet byte index, masked in the eBPF variant.
    fn byte_index(&self, expr: &str) -> String {
        if self.masked_loads {
            format!("({expr}) & PK_BUF_MASK")
        } else {
            expr.to_string()
        }
    }

    /// True when some fixed-width field falls back to the bit loop.
    fn needs_bit_reader(&self) -> bool {
        self.any_fixed_field(|emit, s, inst, f, n| {
            emit.byte_load_expr(s, inst, &f.name, n).is_none()
        })
    }

    /// Does `pred` hold for any fixed-width field in any state?
    fn any_fixed_field(
        &self,
        pred: impl Fn(&Self, &pb::State, &str, &pb::Field, u32) -> bool,
    ) -> bool {
        self.parser.states.iter().any(|s| {
            s.extracts.iter().any(|ex| {
                let inst = if ex.instance.is_empty() {
                    &ex.header_type
                } else {
                    &ex.instance
                };
                self.parser
                    .header_types
                    .iter()
                    .filter(|ht| ht.name == ex.header_type)
                    .any(|ht| {
                        ht.fields.iter().any(|f| {
                            match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                                Some(pb::field_width::Width::Bits(n)) => pred(self, s, inst, f, *n),
                                _ => false,
                            }
                        })
                    })
            })
        })
    }

    /// A statically byte-aligned, whole-byte field reads as `n/8`
    /// direct byte loads instead of `n` iterations of the bit loop.
    /// Semantics are identical (big-endian, MSB-first); the win is
    /// size: the eBPF verifier walks every unrolled instruction, and
    /// the bit loop is what pushed `tls_clienthello` past the 1M-insn
    /// budget (see docs/designs/2026-07-29-tls-ebpf-deliverable.md).
    fn byte_load_expr(&self, s: &pb::State, inst: &str, field: &str, n: u32) -> Option<String> {
        if !n.is_multiple_of(8) || n > 64 {
            return None;
        }
        if super::field_alignment(self.parser, &self.entry_align, s, inst, field)? != 0 {
            return None;
        }
        let nbytes = n / 8;
        let parts: Vec<String> = (0..nbytes)
            .map(|i| {
                let shift = 8 * (nbytes - 1 - i);
                // Through pk_byte_at, whose guard is on the SAME value
                // it indexes — the verifier does not back-propagate a
                // refinement made on a different register.
                let load = format!(
                    "(uint64_t)buf[{}]",
                    self.byte_index(&format!("(off >> 3) + {i}"))
                );
                if shift == 0 {
                    load
                } else {
                    format!("({load} << {shift})")
                }
            })
            .collect();
        Some(parts.join(" | "))
    }

    fn structs(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        for (inst, ht_name) in instances(self.parser) {
            let ht = self
                .parser
                .header_types
                .iter()
                .find(|h| h.name == ht_name)
                .ok_or_else(|| anyhow::anyhow!("unknown header type `{ht_name}`"))?;
            writeln!(w, "typedef struct {{")?;
            for f in &ht.fields {
                match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(n)) => {
                        writeln!(w, "  {} {};", uint_type(*n), f.name)?;
                    }
                    Some(pb::field_width::Width::ByteLen(_)) => {
                        writeln!(w, "  uint64_t {}_bit_off;", f.name)?;
                        writeln!(w, "  uint64_t {}_bit_len;", f.name)?;
                    }
                    None => bail!("field `{}` has no width", f.name),
                }
            }
            writeln!(w, "}} {p}_{inst}_t;")?;
            writeln!(w)?;
        }
        writeln!(w, "typedef struct {{")?;
        writeln!(w, "  uint8_t outcome; /* 0 = accept, 1 = reject */")?;
        writeln!(w, "  uint16_t reason; /* {p}_reason */")?;
        writeln!(w, "  uint64_t consumed_bits;")?;
        for (inst, _) in instances(self.parser) {
            writeln!(w, "  uint8_t {inst}_present;")?;
            writeln!(w, "  {p}_{inst}_t {inst};")?;
        }
        for md in &self.parser.metadata {
            writeln!(w, "  uint64_t m_{};", md.name)?;
        }
        writeln!(w, "}} {p}_result_t;")?;
        Ok(w)
    }

    fn header(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        let guard = format!("{}_H", p.to_uppercase());
        writeln!(
            w,
            "/* Generated by pakeles from `{}`. Do not edit:",
            self.parser.name
        )?;
        writeln!(w, " * regenerate with `pakeles gen c`. */")?;
        writeln!(w, "#ifndef {guard}")?;
        writeln!(w, "#define {guard}")?;
        writeln!(w)?;
        writeln!(w, "#include <stdint.h>")?;
        writeln!(w, "#include <stddef.h>")?;
        writeln!(w)?;
        writeln!(
            w,
            "enum {{ {}_ACCEPT = 0, {}_REJECT = 1 }};",
            p.to_uppercase(),
            p.to_uppercase()
        )?;
        writeln!(w)?;
        writeln!(w, "typedef enum {{")?;
        writeln!(w, "  PK_R_NONE = 0,")?;
        for (reason, code) in &self.reasons {
            writeln!(w, "  {} = {code}, /* \"{reason}\" */", reason_ident(reason))?;
        }
        writeln!(w, "}} {p}_reason_t;")?;
        writeln!(w)?;
        w.push_str(&self.structs()?);
        writeln!(w)?;
        writeln!(
            w,
            "/* Parse `bit_len` bits of `buf` (reject mode). Returns outcome. */"
        )?;
        writeln!(
            w,
            "int {p}_parse(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out);"
        )?;
        writeln!(w, "const char *{p}_reason_str(uint16_t reason);")?;
        writeln!(w)?;
        writeln!(w, "#endif /* {guard} */")?;
        Ok(w)
    }

    /// The parse core: shared between portable C and eBPF (the eBPF
    /// variant additionally masks every packet index — see
    /// `BPF_BUF_MASK`).
    fn core(&self, static_qual: &str) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        if self.masked_loads {
            writeln!(
                w,
                "/* Buffer contract: `buf` must hold at least PK_BUF_MASK + 1 bytes."
            )?;
            writeln!(
                w,
                " * Every packet index is masked with it — dead at runtime (the"
            )?;
            writeln!(
                w,
                " * length guards already bound each access), but it bounds the index"
            )?;
            writeln!(
                w,
                " * register directly, which is what the kernel verifier tracks. */"
            )?;
            writeln!(w, "#ifndef PK_BUF_MASK")?;
            writeln!(w, "#define PK_BUF_MASK {BPF_BUF_MASK}u")?;
            writeln!(w, "#endif")?;
            writeln!(w)?;
        }
        // Emitted only when some field actually needs the bit path —
        // a fully byte-aligned parser would otherwise carry an unused
        // static function (-Werror=unused-function).
        if self.needs_bit_reader() {
            writeln!(
            w,
            "{static_qual} uint64_t pk_read_bits(const uint8_t *buf, uint64_t avail, uint64_t off, uint32_t n) {{"
        )?;
            writeln!(w, "  (void)avail;")?;
            writeln!(w, "  uint64_t v = 0;")?;
            writeln!(w, "  uint32_t i;")?;
            writeln!(w, "  for (i = 0; i < n; i++) {{")?;
            writeln!(w, "    uint64_t pos = off + i;")?;
            writeln!(
                w,
                "    v = (v << 1) | (uint64_t)((buf[{}] >> (7 - (pos & 7))) & 1);",
                self.byte_index("pos >> 3")
            )?;
            writeln!(w, "  }}")?;
            writeln!(w, "  return v;")?;
            writeln!(w, "}}")?;
            writeln!(w)?;
        }

        // State ids.
        for (i, s) in self.parser.states.iter().enumerate() {
            writeln!(w, "#define PK_S_{} {i}", s.name.to_uppercase())?;
        }
        writeln!(w)?;

        writeln!(
            w,
            "{static_qual} int {p}_parse_core(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out) {{"
        )?;
        writeln!(w, "  uint64_t off = 0;")?;
        writeln!(
            w,
            "  uint32_t state = PK_S_{};",
            self.parser.start_state.to_uppercase()
        )?;
        writeln!(w, "  uint32_t depth;")?;
        let rcap = self.region_cap();
        if rcap > 0 {
            // PK_RMASK bounds every index for the eBPF verifier; the
            // validator's depth consistency makes the clamps dead code.
            let mask = rcap.next_power_of_two() - 1;
            writeln!(w, "#define PK_RMASK {mask}u")?;
            writeln!(w, "  uint64_t pk_region_end[{}];", mask + 1)?;
            writeln!(w, "  uint32_t pk_rsp = 0;")?;
        }
        for md in &self.parser.metadata {
            writeln!(w, "  out->m_{} = {}ULL;", md.name, md.init)?;
        }
        writeln!(
            w,
            "  for (depth = 0; depth < {}u; depth++) {{",
            self.parser.max_depth
        )?;
        writeln!(w, "    switch (state) {{")?;
        for s in &self.parser.states {
            writeln!(w, "    case PK_S_{}: {{", s.name.to_uppercase())?;
            self.emit_state_body(&mut w, s)?;
            writeln!(w, "    }}")?;
        }
        writeln!(w, "    }}")?;
        writeln!(w, "  }}")?;
        writeln!(w, "  out->outcome = 1;")?;
        writeln!(w, "  out->reason = PK_R_MAX_DEPTH_EXCEEDED;")?;
        writeln!(w, "  out->consumed_bits = off;")?;
        writeln!(w, "  return 1;")?;
        writeln!(w, "}}")?;
        Ok(w)
    }

    /// Static sized-region capacity: total pushes across all states is
    /// a sound (if loose) bound on the nesting depth the validator
    /// enforces. 0 = the parser uses no regions (emit no locals).
    fn region_cap(&self) -> usize {
        self.parser
            .states
            .iter()
            .flat_map(|s| &s.region_ops)
            .filter(|op| matches!(op.kind, Some(pb::region_op::Kind::Push(_))))
            .count()
    }

    fn meta_bits(&self, name: &str) -> u32 {
        self.parser
            .metadata
            .iter()
            .find(|md| md.name == name)
            .map(|md| md.bits)
            .expect("validated IR: assign target declared")
    }

    fn emit_reject(&self, w: &mut String, indent: &str, reason: &str) -> Result<()> {
        writeln!(w, "{indent}out->outcome = 1;")?;
        writeln!(w, "{indent}out->reason = {};", reason_ident(reason))?;
        writeln!(w, "{indent}out->consumed_bits = off;")?;
        writeln!(w, "{indent}return 1;")?;
        Ok(())
    }

    fn emit_target(&self, w: &mut String, indent: &str, t: &pb::Target) -> Result<()> {
        match t.kind.as_ref() {
            Some(pb::target::Kind::State(name)) => {
                writeln!(w, "{indent}state = PK_S_{};", name.to_uppercase())?;
                writeln!(w, "{indent}continue;")?;
            }
            Some(pb::target::Kind::Accept(_)) => {
                writeln!(w, "{indent}out->outcome = 0;")?;
                writeln!(w, "{indent}out->reason = PK_R_NONE;")?;
                writeln!(w, "{indent}out->consumed_bits = off;")?;
                writeln!(w, "{indent}return 0;")?;
            }
            Some(pb::target::Kind::Reject(r)) => {
                self.emit_reject(w, indent, &r.reason)?;
            }
            None => bail!("empty target"),
        }
        Ok(())
    }

    fn emit_state_body(&self, w: &mut String, s: &pb::State) -> Result<()> {
        for ex in &s.extracts {
            let ht = self
                .parser
                .header_types
                .iter()
                .find(|h| h.name == ex.header_type)
                .ok_or_else(|| anyhow::anyhow!("unknown header type"))?;
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            writeln!(w, "      out->{inst}_present = 1;")?;
            let regions = self.region_cap() > 0;
            for f in &ht.fields {
                match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                    Some(pb::field_width::Width::Bits(n)) => {
                        // Region end first: crossing the innermost region
                        // is structural regardless of the buffer (the
                        // interp's avail-free reason rule).
                        if regions {
                            writeln!(
                                w,
                                "      if (pk_rsp && off + {n} > pk_region_end[(pk_rsp - 1u) & PK_RMASK]) {{"
                            )?;
                            self.emit_reject(w, "        ", "out of region bounds")?;
                            writeln!(w, "      }}")?;
                        }
                        writeln!(w, "      if (off + {n} > bit_len) {{")?;
                        self.emit_reject(w, "        ", "out of bounds")?;
                        writeln!(w, "      }}")?;
                        match self.byte_load_expr(s, inst, &f.name, *n) {
                            Some(load) => writeln!(
                                w,
                                "      out->{inst}.{} = ({})({load});",
                                f.name,
                                uint_type(*n)
                            )?,
                            None => writeln!(
                                w,
                                "      out->{inst}.{} = ({})pk_read_bits(buf, bit_len, off, {n});",
                                f.name,
                                uint_type(*n)
                            )?,
                        }
                        writeln!(w, "      off += {n};")?;
                    }
                    Some(pb::field_width::Width::ByteLen(expr)) => {
                        writeln!(w, "      {{")?;
                        writeln!(w, "        uint64_t vlen = {};", expr_c(expr)?)?;
                        // Division form: immune to u64 overflow on
                        // wrapped lengths; off <= bound holds here.
                        if regions {
                            writeln!(
                                w,
                                "        if (pk_rsp && vlen > (pk_region_end[(pk_rsp - 1u) & PK_RMASK] - off) / 8) {{"
                            )?;
                            self.emit_reject(w, "          ", "out of region bounds")?;
                            writeln!(w, "        }}")?;
                        }
                        writeln!(w, "        if (vlen > (bit_len - off) / 8) {{")?;
                        self.emit_reject(w, "          ", "out of bounds")?;
                        writeln!(w, "        }}")?;
                        writeln!(w, "        out->{inst}.{}_bit_off = off;", f.name)?;
                        writeln!(w, "        out->{inst}.{}_bit_len = vlen * 8;", f.name)?;
                        writeln!(w, "        off += vlen * 8;")?;
                        writeln!(w, "      }}")?;
                    }
                    None => bail!("field `{}` has no width", f.name),
                }
            }
        }
        for a in &s.assigns {
            let rhs = expr_c(a.value.as_ref().context("assign without value")?)?;
            let bits = self.meta_bits(&a.metadata);
            if bits >= 64 {
                writeln!(w, "      out->m_{} = {rhs};", a.metadata)?;
            } else {
                writeln!(
                    w,
                    "      out->m_{} = ({rhs}) & 0x{:x}ULL;",
                    a.metadata,
                    (1u64 << bits) - 1
                )?;
            }
        }
        for op in &s.region_ops {
            match op.kind.as_ref() {
                Some(pb::region_op::Kind::Push(e)) => {
                    writeln!(w, "      {{")?;
                    writeln!(w, "        uint64_t rlen = {};", expr_c(e)?)?;
                    // Structural check against the enclosing region only
                    // (division form, overflow-immune); at depth 0 just
                    // guard the end arithmetic itself.
                    writeln!(w, "        if (pk_rsp) {{")?;
                    writeln!(
                        w,
                        "          if (rlen > (pk_region_end[(pk_rsp - 1u) & PK_RMASK] - off) / 8) {{"
                    )?;
                    self.emit_reject(w, "            ", "region out of bounds")?;
                    writeln!(w, "          }}")?;
                    writeln!(
                        w,
                        "        }} else if (rlen > (0xffffffffffffffffULL - off) / 8) {{"
                    )?;
                    self.emit_reject(w, "          ", "region out of bounds")?;
                    writeln!(w, "        }}")?;
                    writeln!(w, "        if (pk_rsp > PK_RMASK) {{")?;
                    self.emit_reject(w, "          ", "region out of bounds")?;
                    writeln!(w, "        }}")?;
                    writeln!(
                        w,
                        "        pk_region_end[pk_rsp & PK_RMASK] = off + rlen * 8;"
                    )?;
                    writeln!(w, "        pk_rsp++;")?;
                    writeln!(w, "      }}")?;
                }
                Some(pb::region_op::Kind::Pop(_)) => {
                    // Balance is validator-enforced; the rsp guard is
                    // dead code that keeps the eBPF verifier happy.
                    writeln!(w, "      if (!pk_rsp) {{")?;
                    self.emit_reject(w, "        ", "region not exhausted")?;
                    writeln!(w, "      }}")?;
                    writeln!(w, "      pk_rsp--;")?;
                    writeln!(w, "      if (off < pk_region_end[pk_rsp & PK_RMASK]) {{")?;
                    self.emit_reject(w, "        ", "region not exhausted")?;
                    writeln!(w, "      }}")?;
                }
                None => bail!("empty region op"),
            }
        }
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => bail!("state `{}` has no transition", s.name),
            Some(pb::transition::Kind::Direct(t)) => self.emit_target(w, "      ", t)?,
            Some(pb::transition::Kind::Select(sel)) => {
                let keys: Vec<String> = sel.keys.iter().map(expr_c).collect::<Result<_>>()?;
                for (ki, k) in keys.iter().enumerate() {
                    writeln!(w, "      uint64_t key{ki} = {k};")?;
                }
                for (i, arm) in sel.arms.iter().enumerate() {
                    let cond: Vec<String> = arm
                        .entries
                        .iter()
                        .enumerate()
                        .map(|(ki, e)| entry_c(e, &format!("key{ki}")))
                        .collect();
                    let kw = if i == 0 { "if" } else { "} else if" };
                    writeln!(w, "      {kw} ({}) {{", cond.join(" && "))?;
                    self.emit_target(
                        w,
                        "        ",
                        arm.next
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("arm without target"))?,
                    )?;
                }
                if sel.arms.is_empty() {
                    match sel.default_target.as_ref() {
                        Some(t) => self.emit_target(w, "      ", t)?,
                        None => self.emit_reject(w, "      ", "no matching select arm")?,
                    }
                } else {
                    writeln!(w, "      }} else {{")?;
                    match sel.default_target.as_ref() {
                        Some(t) => self.emit_target(w, "        ", t)?,
                        None => self.emit_reject(w, "        ", "no matching select arm")?,
                    }
                    writeln!(w, "      }}")?;
                }
            }
        }
        Ok(())
    }

    fn source(&self) -> Result<String> {
        let mut w = String::new();
        let p = &self.prefix;
        writeln!(
            w,
            "/* Generated by pakeles from `{}`. Do not edit:",
            self.parser.name
        )?;
        writeln!(w, " * regenerate with `pakeles gen c`. */")?;
        writeln!(w, "#include \"parser.h\"")?;
        writeln!(w)?;
        w.push_str(&self.core("static")?);
        writeln!(w)?;
        writeln!(
            w,
            "int {p}_parse(const uint8_t *buf, uint64_t bit_len, {p}_result_t *out) {{"
        )?;
        writeln!(w, "  {p}_result_t zero = {{0}};")?;
        writeln!(w, "  *out = zero;")?;
        writeln!(w, "  return {p}_parse_core(buf, bit_len, out);")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "const char *{p}_reason_str(uint16_t reason) {{")?;
        writeln!(w, "  switch (reason) {{")?;
        for (reason, code) in &self.reasons {
            writeln!(w, "  case {code}: return \"{reason}\";")?;
        }
        writeln!(w, "  default: return \"\";")?;
        writeln!(w, "  }}")?;
        writeln!(w, "}}")?;
        Ok(w)
    }
}

pub fn generate_c(ir: &pb::Ir) -> Result<CArtifacts> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new(parser);
    Ok(CArtifacts {
        header: emit.header()?,
        source: emit.source()?,
    })
}

/// stdin/stdout conformance harness: one vector per line in, one
/// result line out. Test infrastructure, not a shipped artifact.
pub fn generate_c_harness(ir: &pb::Ir) -> Result<String> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new(parser);
    let p = &emit.prefix;
    let mut w = String::new();
    writeln!(
        w,
        "/* Generated conformance harness for `{}`. */",
        parser.name
    )?;
    writeln!(w, "#include \"parser.h\"")?;
    writeln!(w, "#include <stdio.h>")?;
    writeln!(w, "#include <string.h>")?;
    writeln!(w)?;
    writeln!(w, "static int hexval(int c) {{")?;
    writeln!(w, "  if (c >= '0' && c <= '9') return c - '0';")?;
    writeln!(w, "  if (c >= 'a' && c <= 'f') return c - 'a' + 10;")?;
    writeln!(w, "  return -1;")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    writeln!(w, "int main(void) {{")?;
    writeln!(w, "  static char line[300000];")?;
    writeln!(w, "  static uint8_t buf[150000];")?;
    writeln!(w, "  while (fgets(line, sizeof line, stdin)) {{")?;
    writeln!(w, "    unsigned long long bit_len = 0;")?;
    writeln!(w, "    char hex[280000];")?;
    writeln!(w, "    hex[0] = 0;")?;
    writeln!(
        w,
        "    if (sscanf(line, \"%llu %279999s\", &bit_len, hex) < 1) continue;"
    )?;
    writeln!(w, "    size_t nb = strlen(hex) / 2;")?;
    writeln!(w, "    if (hex[0] == '-') nb = 0;")?;
    writeln!(w, "    for (size_t i = 0; i < nb; i++)")?;
    writeln!(
        w,
        "      buf[i] = (uint8_t)((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1]));"
    )?;
    writeln!(w, "    {p}_result_t r;")?;
    writeln!(w, "    {p}_parse(buf, bit_len, &r);")?;
    writeln!(
        w,
        "    printf(\"%s|%s|%llu\", r.outcome == 0 ? \"accept\" : \"reject\", {p}_reason_str(r.reason), (unsigned long long)r.consumed_bits);"
    )?;
    for (inst, ht_name) in instances(parser) {
        let ht = parser
            .header_types
            .iter()
            .find(|h| h.name == ht_name)
            .unwrap();
        writeln!(w, "    if (r.{inst}_present) {{")?;
        for f in &ht.fields {
            match f.width.as_ref().and_then(|x| x.width.as_ref()) {
                Some(pb::field_width::Width::Bits(_)) => {
                    writeln!(
                        w,
                        "      printf(\"|{inst}.{}=%llu\", (unsigned long long)r.{inst}.{});",
                        f.name, f.name
                    )?;
                }
                Some(pb::field_width::Width::ByteLen(_)) => {
                    writeln!(w, "      printf(\"|{inst}.{}=\");", f.name)?;
                    writeln!(
                        w,
                        "      for (uint64_t i = 0; i < r.{inst}.{}_bit_len / 8; i++)",
                        f.name
                    )?;
                    writeln!(
                        w,
                        "        printf(\"%02x\", buf[r.{inst}.{}_bit_off / 8 + i]);",
                        f.name
                    )?;
                }
                None => {}
            }
        }
        writeln!(w, "    }}")?;
    }
    for md in &parser.metadata {
        writeln!(
            w,
            "    printf(\"|meta.{}=%llu\", (unsigned long long)r.m_{});",
            md.name, md.name
        )?;
    }
    writeln!(w, "    printf(\"\\n\");")?;
    writeln!(w, "    fflush(stdout);")?;
    writeln!(w, "  }}")?;
    writeln!(w, "  return 0;")?;
    writeln!(w, "}}")?;
    Ok(w)
}

/// Self-contained eBPF C: same core, no libc, packed-verdict entry.
/// Harness convention: mem = 8-byte LE bit_len, then packet bytes.
pub fn generate_bpf(ir: &pb::Ir) -> Result<String> {
    let parser = ir
        .parser
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ir has no parser"))?;
    let emit = Emit::new_bpf(parser);
    let p = &emit.prefix;
    let mut w = String::new();
    writeln!(
        w,
        "/* Generated by pakeles from `{}` (eBPF variant). Do not edit:",
        parser.name
    )?;
    writeln!(w, " * regenerate with `pakeles gen bpf`.")?;
    writeln!(w, " * Compile: clang -O2 -target bpf -c this_file.c")?;
    writeln!(
        w,
        " * Entry contract (rbpf raw VM): r1 = mem = 8-byte LE bit_len ++ packet;"
    )?;
    writeln!(
        w,
        " * the length prefix is the harness framing (rbpf passes no length)."
    )?;
    writeln!(
        w,
        " * Returns outcome(8b) << 56 | reason(8b) << 48 | consumed_bits(48b)."
    )?;
    writeln!(
        w,
        " * Note: the result struct lives on the (512-byte) BPF stack;"
    )?;
    writeln!(w, " * large parsers will need a redesign. */")?;
    writeln!(w)?;
    writeln!(w, "/* Freestanding: no libc for the bpf target. */")?;
    writeln!(w, "typedef __UINT8_TYPE__ uint8_t;")?;
    writeln!(w, "typedef __UINT16_TYPE__ uint16_t;")?;
    writeln!(w, "typedef __UINT32_TYPE__ uint32_t;")?;
    writeln!(w, "typedef __UINT64_TYPE__ uint64_t;")?;
    writeln!(w)?;
    w.push_str(&emit.structs()?);
    writeln!(w)?;
    writeln!(w, "typedef enum {{")?;
    writeln!(w, "  PK_R_NONE = 0,")?;
    for (reason, code) in &emit.reasons {
        writeln!(w, "  {} = {code},", reason_ident(reason))?;
    }
    writeln!(w, "}} {p}_reason_t;")?;
    writeln!(w)?;
    w.push_str(&emit.core("static __attribute__((always_inline))")?);
    writeln!(w)?;
    // rbpf's raw VM passes only the memory pointer (r1); the 8-byte
    // length prefix is the harness's framing, trusted by contract.
    writeln!(w, "uint64_t pk_entry(void *mem) {{")?;
    writeln!(w, "  const uint8_t *m = (const uint8_t *)mem;")?;
    writeln!(w, "  uint64_t bit_len = 0;")?;
    writeln!(w, "  uint32_t i;")?;
    writeln!(
        w,
        "  for (i = 0; i < 8; i++) bit_len |= (uint64_t)m[i] << (8 * i);"
    )?;
    writeln!(w, "  {p}_result_t out = {{0}};")?;
    writeln!(w, "  {p}_parse_core(m + 8, bit_len, &out);")?;
    writeln!(
        w,
        "  return ((uint64_t)out.outcome << 56) | ((uint64_t)out.reason << 48) | (out.consumed_bits & 0xFFFFFFFFFFFFULL);"
    )?;
    writeln!(w, "}}")?;
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::eth_ipvx_l4;

    #[test]
    fn metadata_c_emission_and_semantics() {
        let ir = crate::builder::meta_loop(); // shared test IR from Task 2
        let art = generate_c(&ir).unwrap();
        assert!(art.header.contains("uint64_t m_flag;"));
        assert!(art.header.contains("uint64_t m_acc;"));
        assert!(art.source.contains("out->m_acc = "));
        // and the zero-metadata guarantee:
        let plain = generate_c(&crate::fixtures::eth_ipvx_l4()).unwrap();
        assert!(!plain.header.contains("m_"));
    }

    fn cc_compiles(files: &[(&str, &str)], cmd: &[&str]) -> std::process::Output {
        let dir = std::env::temp_dir().join(format!("pakeles_c_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        std::process::Command::new(cmd[0])
            .args(&cmd[1..])
            .current_dir(&dir)
            .output()
            .unwrap()
    }

    #[test]
    fn generated_c_compiles_with_werror() {
        if std::process::Command::new("cc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: cc not available");
            return;
        }
        for ir in [eth_ipvx_l4(), crate::builder::meta_loop()] {
            let arts = generate_c(&ir).unwrap();
            let harness = generate_c_harness(&ir).unwrap();
            let out = cc_compiles(
                &[
                    ("parser.h", &arts.header),
                    ("parser.c", &arts.source),
                    ("main.c", &harness),
                ],
                &[
                    "cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2", "parser.c", "main.c",
                    "-o", "harness",
                ],
            );
            assert!(
                out.status.success(),
                "cc failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

//! Ergonomic authoring API — thin sugar over the pb types (the
//! `onnx.helper` analog). No semantics live here; `build()` validates.

use crate::ir::pb;
use crate::ir::validate::validate;
use crate::ir::IR_VERSION;

// ---- Expr helpers ----

pub fn c(v: u64) -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Constant(v)),
    }
}

pub fn f(header: &str, field: &str) -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Field(pb::FieldRef {
            header: header.into(),
            field: field.into(),
        })),
    }
}

/// Metadata reference expression.
pub fn m(name: &str) -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Metadata(pb::MetadataRef {
            name: name.into(),
        })),
    }
}

/// `remaining()`: bytes between the cursor and the innermost sized
/// region's end (packet end when no region is open).
pub fn remaining() -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Remaining(pb::Remaining {})),
    }
}

fn bin(op: pb::BinOpKind, lhs: pb::Expr, rhs: pb::Expr) -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Bin(Box::new(pb::BinOp {
            op: op as i32,
            lhs: Some(Box::new(lhs)),
            rhs: Some(Box::new(rhs)),
        }))),
    }
}

pub fn add(l: pb::Expr, r: pb::Expr) -> pb::Expr {
    bin(pb::BinOpKind::Add, l, r)
}
pub fn sub(l: pb::Expr, r: pb::Expr) -> pb::Expr {
    bin(pb::BinOpKind::Sub, l, r)
}
pub fn mul(l: pb::Expr, r: pb::Expr) -> pb::Expr {
    bin(pb::BinOpKind::Mul, l, r)
}
pub fn shl(l: pb::Expr, r: pb::Expr) -> pb::Expr {
    bin(pb::BinOpKind::Shl, l, r)
}

// ---- Target / arm / keyset helpers ----

pub fn to(state: &str) -> pb::Target {
    pb::Target {
        kind: Some(pb::target::Kind::State(state.into())),
    }
}

pub fn accept() -> pb::Target {
    pb::Target {
        kind: Some(pb::target::Kind::Accept(pb::Accept {})),
    }
}

pub fn reject(reason: &str) -> pb::Target {
    pb::Target {
        kind: Some(pb::target::Kind::Reject(pb::Reject {
            reason: reason.into(),
            ..Default::default()
        })),
    }
}

/// Payload-boundary reject (severity=info): "parsing ends here, the
/// rest is payload" — not malformedness.
pub fn reject_info(reason: &str) -> pb::Target {
    pb::Target {
        kind: Some(pb::target::Kind::Reject(pb::Reject {
            reason: reason.into(),
            annotations: [("severity".to_string(), "info".to_string())].into(),
        })),
    }
}

// ---- Display helpers ----

pub fn disp(name: &str, format: pb::DisplayFormat) -> pb::Display {
    pb::Display {
        name: name.into(),
        format: format as i32,
        ..Default::default()
    }
}

pub trait DisplayExt {
    fn labels(self, ls: &[(u64, &str)]) -> Self;
    fn doc(self, text: &str) -> Self;
}

impl DisplayExt for pb::Display {
    fn labels(mut self, ls: &[(u64, &str)]) -> Self {
        self.value_labels = ls
            .iter()
            .map(|(v, l)| pb::ValueLabel {
                value: *v,
                label: l.to_string(),
            })
            .collect();
        self
    }

    fn doc(mut self, text: &str) -> Self {
        self.doc = text.into();
        self
    }
}

pub fn v(value: u64) -> pb::KeysetEntry {
    pb::KeysetEntry {
        kind: Some(pb::keyset_entry::Kind::Value(value)),
    }
}

pub fn masked(value: u64, mask: u64) -> pb::KeysetEntry {
    pb::KeysetEntry {
        kind: Some(pb::keyset_entry::Kind::Masked(pb::Masked { value, mask })),
    }
}

pub fn range(lo: u64, hi: u64) -> pb::KeysetEntry {
    pb::KeysetEntry {
        kind: Some(pb::keyset_entry::Kind::Range(pb::Range { lo, hi })),
    }
}

pub fn arm(entries: Vec<pb::KeysetEntry>, next: pb::Target) -> pb::SelectArm {
    pb::SelectArm {
        entries,
        next: Some(next),
    }
}

// ---- HeaderTypeBuilder ----

pub struct HeaderTypeBuilder {
    ht: pb::HeaderType,
}

impl HeaderTypeBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            ht: pb::HeaderType {
                name: name.into(),
                ..Default::default()
            },
        }
    }

    pub fn bits(self, name: &str, n: u32) -> Self {
        self.field(name, pb::field_width::Width::Bits(n), None, &[])
    }

    /// Fixed-width field carrying annotations, e.g. `("tshark.key", "eth.type")`.
    pub fn bits_ann(self, name: &str, n: u32, anns: &[(&str, &str)]) -> Self {
        self.field(name, pb::field_width::Width::Bits(n), None, anns)
    }

    /// Fixed-width field with typed Display metadata and annotations.
    pub fn bits_full(
        self,
        name: &str,
        n: u32,
        display: pb::Display,
        anns: &[(&str, &str)],
    ) -> Self {
        self.field(name, pb::field_width::Width::Bits(n), Some(display), anns)
    }

    pub fn var_bytes(self, name: &str, byte_len: pb::Expr) -> Self {
        self.field(name, pb::field_width::Width::ByteLen(byte_len), None, &[])
    }

    fn field(
        mut self,
        name: &str,
        width: pb::field_width::Width,
        display: Option<pb::Display>,
        anns: &[(&str, &str)],
    ) -> Self {
        self.ht.fields.push(pb::Field {
            name: name.into(),
            width: Some(pb::FieldWidth { width: Some(width) }),
            display,
            annotations: anns
                .iter()
                .map(|(k, val)| (k.to_string(), val.to_string()))
                .collect(),
        });
        self
    }
}

// ---- StateBuilder ----

pub struct StateBuilder {
    state: pb::State,
}

impl StateBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            state: pb::State {
                name: name.into(),
                ..Default::default()
            },
        }
    }

    /// Extract a header; instance name defaults to the header type name.
    pub fn extract(mut self, header_type: &str) -> Self {
        self.state.extracts.push(pb::Extract {
            header_type: header_type.into(),
            instance: String::new(),
        });
        self
    }

    /// Append a metadata assignment, run after this state's extracts and
    /// before its transition.
    pub fn assign(mut self, name: &str, value: pb::Expr) -> Self {
        self.state.assigns.push(pb::Assign {
            metadata: name.into(),
            value: Some(value),
        });
        self
    }

    /// Open a sized region of `len` BYTES at the cursor (run after
    /// assigns, before the transition; ops keep their call order).
    pub fn push_region(mut self, len: pb::Expr) -> Self {
        self.state.region_ops.push(pb::RegionOp {
            kind: Some(pb::region_op::Kind::Push(len)),
        });
        self
    }

    /// Close the innermost sized region (exact-mode: the cursor must
    /// sit at the region end).
    pub fn pop_region(mut self) -> Self {
        self.state.region_ops.push(pb::RegionOp {
            kind: Some(pb::region_op::Kind::Pop(pb::Pop {})),
        });
        self
    }

    pub fn select(
        mut self,
        keys: Vec<pb::Expr>,
        arms: Vec<pb::SelectArm>,
        default_target: pb::Target,
    ) -> Self {
        self.state.transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Select(pb::Select {
                keys,
                arms,
                default_target: Some(default_target),
            })),
        });
        self
    }

    pub fn goto_(self, target: pb::Target) -> Self {
        self.direct(target)
    }

    pub fn accept(self) -> Self {
        self.direct(accept())
    }

    pub fn reject(self, reason: &str) -> Self {
        self.direct(reject(reason))
    }

    fn direct(mut self, target: pb::Target) -> Self {
        self.state.transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(target)),
        });
        self
    }
}

// ---- ParserBuilder ----

pub struct ParserBuilder {
    parser: pb::Parser,
}

impl ParserBuilder {
    pub fn new(name: &str, max_depth: u32) -> Self {
        Self {
            parser: pb::Parser {
                name: name.into(),
                max_depth,
                ..Default::default()
            },
        }
    }

    pub fn header(mut self, h: HeaderTypeBuilder) -> Self {
        self.parser.header_types.push(h.ht);
        self
    }

    /// Declare a metadata field: `bits`-wide, initialized to `init`.
    pub fn meta(mut self, name: &str, bits: u32, init: u64) -> Self {
        self.parser.metadata.push(pb::MetadataField {
            name: name.into(),
            bits,
            init,
            ..Default::default()
        });
        self
    }

    pub fn state(mut self, s: StateBuilder) -> Self {
        self.parser.states.push(s.state);
        self
    }

    pub fn start(mut self, state: &str) -> Self {
        self.parser.start_state = state.into();
        self
    }

    pub fn build(self) -> anyhow::Result<pb::Ir> {
        let ir = pb::Ir {
            ir_version: IR_VERSION.into(),
            parser: Some(self.parser),
        };
        validate(&ir).map_err(|errs| anyhow::anyhow!("invalid IR:\n  {}", errs.join("\n  ")))?;
        Ok(ir)
    }
}

/// Mid-size symex perf proxy: the rung-4a cost shape at a seconds scale.
/// A var-length options region ahead of each select puts every later
/// extract at a symbolic offset (`ExtractAt` chains), and the proto-4 arm
/// re-enters `parse_ip4` (an encap back edge, bounded by the testgen
/// loop-unroll cap), so feasibility checks deepen exactly like the tunnel
/// clusters. Perf-lever comparisons iterate here, not on the 4a IR.
pub fn encap_proxy() -> pb::Ir {
    ParserBuilder::new("encap_proxy", 6)
        .header(HeaderTypeBuilder::new("eth").bits("proto", 16))
        .header(
            HeaderTypeBuilder::new("ip4m")
                .bits("ver", 4)
                .bits("ihl", 4)
                .bits("proto", 8)
                .var_bytes("options", mul(f("ip4m", "ihl"), c(4))),
        )
        .header(
            HeaderTypeBuilder::new("ip6m")
                .bits("nh", 8)
                .bits("elen", 8)
                .var_bytes("exts", f("ip6m", "elen")),
        )
        .header(HeaderTypeBuilder::new("l4m").bits("sport", 16))
        .state(StateBuilder::new("parse_eth").extract("eth").select(
            vec![f("eth", "proto")],
            vec![
                arm(vec![v(0x0800)], to("parse_ip4")),
                arm(vec![v(0x86dd)], to("parse_ip6")),
            ],
            reject("unsupported ethertype"),
        ))
        .state(StateBuilder::new("parse_ip4").extract("ip4m").select(
            vec![f("ip4m", "proto")],
            vec![
                arm(vec![v(4)], to("parse_ip4")),
                arm(vec![v(41)], to("parse_ip6")),
                arm(vec![v(6)], to("parse_l4")),
            ],
            reject("unsupported proto"),
        ))
        .state(StateBuilder::new("parse_ip6").extract("ip6m").select(
            vec![f("ip6m", "nh")],
            vec![
                arm(vec![v(0)], to("parse_ip6")),
                arm(vec![v(4)], to("parse_ip4")),
                arm(vec![v(6)], to("parse_l4")),
            ],
            reject("unsupported next header"),
        ))
        .state(StateBuilder::new("parse_l4").extract("l4m").select(
            vec![f("l4m", "sport")],
            vec![arm(vec![v(80)], accept())],
            accept(),
        ))
        .start("parse_eth")
        .build()
        .unwrap()
}

/// Shared metadata test IR (see the Interfaces block of the metadata-v1
/// plan, Task 2): a count-prefixed accumulator loop with a constant write
/// and select-on-metadata exits. Used by interp/symex/codegen tests.
#[cfg(test)]
pub(crate) fn meta_loop() -> pb::Ir {
    ParserBuilder::new("meta_loop", 6)
        .meta("flag", 1, 0)
        .meta("acc", 8, 0)
        .header(HeaderTypeBuilder::new("h").bits("n", 8))
        .header(HeaderTypeBuilder::new("i").bits("v", 8))
        .state(
            StateBuilder::new("s0")
                .extract("h")
                .assign("acc", f("h", "n"))
                .assign("flag", c(1))
                .select(vec![m("acc")], vec![arm(vec![v(0)], accept())], to("s1")),
        )
        .state(
            StateBuilder::new("s1")
                .extract("i")
                .assign("acc", sub(m("acc"), c(1)))
                .select(vec![m("acc")], vec![arm(vec![v(0)], accept())], to("s1")),
        )
        .start("s0")
        .build()
        .unwrap()
}

/// Shared sized-region test IR (see the sized-region design doc's
/// micro-example): `h.total` bounds a region of TLV items
/// (t:u8, l:u8, val:bytes[l]); loop exits on remaining()==0 -> exact
/// pop -> accept. Used by interp/symex/codegen tests.
#[cfg(test)]
pub(crate) fn tlv_mini() -> pb::Ir {
    ParserBuilder::new("tlv_mini", 8)
        .header(HeaderTypeBuilder::new("h").bits("total", 8))
        .header(
            HeaderTypeBuilder::new("item")
                .bits("t", 8)
                .bits("l", 8)
                .var_bytes("val", f("item", "l")),
        )
        .state(
            StateBuilder::new("s0")
                .extract("h")
                .push_region(f("h", "total"))
                .goto_(to("tlv")),
        )
        .state(StateBuilder::new("tlv").select(
            vec![remaining()],
            vec![arm(vec![v(0)], to("done"))],
            to("item_s"),
        ))
        .state(StateBuilder::new("item_s").extract("item").goto_(to("tlv")))
        .state(StateBuilder::new("done").pop_region().accept())
        .start("s0")
        .build()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::test_support::tiny;

    #[test]
    fn builds_tiny_equivalent() {
        let built = ParserBuilder::new("tiny", 1)
            .state(StateBuilder::new("s").accept())
            .start("s")
            .build()
            .unwrap();
        assert_eq!(built, tiny());
    }

    #[test]
    fn built_ir_validates() {
        let ir = ParserBuilder::new("two", 2)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![v(1)], to("b"))],
                reject("nope"),
            ))
            .state(StateBuilder::new("b").accept())
            .start("a")
            .build()
            .unwrap();
        crate::ir::validate::validate(&ir).unwrap();
    }

    #[test]
    fn build_surfaces_validation_errors() {
        let err = ParserBuilder::new("bad", 1)
            .state(StateBuilder::new("s").goto_(to("ghost")))
            .start("s")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("unknown state `ghost`"));
    }

    #[test]
    fn builds_metadata_parser() {
        let ir = ParserBuilder::new("t", 3)
            .meta("flag", 1, 0)
            .meta("acc", 8, 5)
            .header(HeaderTypeBuilder::new("h").bits("x", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .assign("acc", sub(m("acc"), c(1)))
                    .assign("flag", c(1))
                    .select(vec![m("acc")], vec![arm(vec![v(0)], accept())], to("s0")),
            )
            .start("s0")
            .build()
            .unwrap();
        let p = ir.parser.as_ref().unwrap();
        assert_eq!(p.metadata.len(), 2);
        assert_eq!(p.states[0].assigns.len(), 2);
    }
}

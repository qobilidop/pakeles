//! Backend code generators: Wireshark Lua, portable C99, eBPF C, P4-16.

pub mod c;
pub mod lua;
pub mod p4;

/// True when any state carries sized-region ops. Backends that do not
/// (yet) lower regions must refuse such IR loudly — silently ignoring
/// region ops would miscompile.
pub(crate) fn has_region_ops(parser: &crate::ir::pb::Parser) -> bool {
    parser.states.iter().any(|s| !s.region_ops.is_empty())
}

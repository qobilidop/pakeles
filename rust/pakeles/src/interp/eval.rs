//! Expression evaluation and keyset matching over an environment of
//! already-extracted fixed-width field values.

use crate::ir::pb;
use std::collections::HashMap;

pub(crate) type Env = HashMap<(String, String), u64>;

/// Evaluate an operator tree. Arithmetic wraps (u64). Errors indicate a
/// malformed IR (unresolved ref, missing operand) — never packet content.
/// `remaining` is the value of `remaining()` at this use point, `None`
/// in positions where it is illegal (byte_len widths; validator-backed).
pub(crate) fn eval_expr(
    e: &pb::Expr,
    env: &Env,
    meta: &std::collections::HashMap<String, u64>,
    remaining: Option<u64>,
) -> anyhow::Result<u64> {
    match e.kind.as_ref() {
        Some(pb::expr::Kind::Constant(v)) => Ok(*v),
        Some(pb::expr::Kind::Remaining(_)) => {
            remaining.ok_or_else(|| anyhow::anyhow!("remaining() not allowed in this position"))
        }
        Some(pb::expr::Kind::Field(r)) => env
            .get(&(r.header.clone(), r.field.clone()))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unresolved field ref `{}.{}`", r.header, r.field)),
        Some(pb::expr::Kind::Bin(b)) => {
            let lhs = eval_expr(
                b.lhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing lhs"))?,
                env,
                meta,
                remaining,
            )?;
            let rhs = eval_expr(
                b.rhs
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("binop missing rhs"))?,
                env,
                meta,
                remaining,
            )?;
            let op = pb::BinOpKind::try_from(b.op)
                .map_err(|_| anyhow::anyhow!("unknown binop {}", b.op))?;
            Ok(match op {
                pb::BinOpKind::Add => lhs.wrapping_add(rhs),
                pb::BinOpKind::Sub => lhs.wrapping_sub(rhs),
                pb::BinOpKind::Mul => lhs.wrapping_mul(rhs),
                pb::BinOpKind::Shl => lhs.wrapping_shl(rhs as u32),
                pb::BinOpKind::Shr => lhs.wrapping_shr(rhs as u32),
                pb::BinOpKind::And => lhs & rhs,
                pb::BinOpKind::Or => lhs | rhs,
                pb::BinOpKind::Unspecified => {
                    anyhow::bail!("unspecified binop")
                }
            })
        }
        Some(pb::expr::Kind::Metadata(r)) => meta
            .get(&r.name)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unresolved metadata ref `{}`", r.name)),
        None => anyhow::bail!("empty expression"),
    }
}

pub(crate) fn eval_entry(entry: &pb::KeysetEntry, key: u64) -> bool {
    match entry.kind.as_ref() {
        Some(pb::keyset_entry::Kind::Value(v)) => key == *v,
        Some(pb::keyset_entry::Kind::Masked(m)) => key & m.mask == m.value & m.mask,
        Some(pb::keyset_entry::Kind::Range(r)) => (r.lo..=r.hi).contains(&key),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{c, f, masked as bmasked, mul, range as brange, sub, v};

    fn env() -> Env {
        let mut e = Env::new();
        e.insert(("ipv4".into(), "ihl".into()), 6);
        e
    }

    fn meta() -> std::collections::HashMap<String, u64> {
        std::collections::HashMap::new()
    }

    #[test]
    fn evals_ihl_options_len() {
        let expr = sub(mul(f("ipv4", "ihl"), c(4)), c(20));
        assert_eq!(eval_expr(&expr, &env(), &meta(), None).unwrap(), 4);
    }

    #[test]
    fn unresolved_ref_is_error() {
        assert!(eval_expr(&f("ghost", "x"), &env(), &meta(), None).is_err());
    }

    #[test]
    fn remaining_uses_context_and_errors_without_one() {
        let expr = crate::builder::remaining();
        assert_eq!(eval_expr(&expr, &env(), &meta(), Some(7)).unwrap(), 7);
        assert!(eval_expr(&expr, &env(), &meta(), None).is_err());
    }

    /// The spec takes a shift's right operand mod 64. Pinned here
    /// because no target language does this natively — C calls it
    /// undefined, P4 and SMT bitvectors answer 0, Lua computes a float
    /// — so every backend has to reproduce it, and this is the value
    /// they must reproduce.
    #[test]
    fn shift_amounts_wrap_at_64() {
        use crate::builder::{shl, shr};
        let at = |amount| eval_expr(&shl(c(1), c(amount)), &env(), &meta(), None).unwrap();
        assert_eq!(at(0), 1);
        assert_eq!(at(63), 1u64 << 63);
        assert_eq!(at(64), 1, "64 mod 64 == 0, not a zeroing shift");
        assert_eq!(at(65), 2);
        assert_eq!(
            eval_expr(&shr(c(0x8000_0000_0000_0000), c(64)), &env(), &meta(), None).unwrap(),
            0x8000_0000_0000_0000
        );
    }

    #[test]
    fn keyset_matching() {
        assert!(eval_entry(&v(6), 6));
        assert!(!eval_entry(&v(6), 17));
        assert!(eval_entry(&bmasked(0x0800, 0xFF00), 0x08FF));
        assert!(!eval_entry(&bmasked(0x0800, 0xFF00), 0x1800));
        assert!(eval_entry(&brange(5, 10), 5));
        assert!(eval_entry(&brange(5, 10), 10));
        assert!(!eval_entry(&brange(5, 10), 11));
    }
}

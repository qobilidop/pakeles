//! Well-formedness validation: everything protobuf cannot express.
//! Collects all violations (stable order) rather than failing fast.

use super::pb;

fn is_portable_ident(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && chars.all(|ch| matches!(ch, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9'))
}

fn is_backend_keyword(name: &str) -> bool {
    // Union of C99, Lua 5.2, and the P4-16 keywords that can occur in the
    // identifier positions emitted by Pakeles. Presentation names remain
    // unrestricted; these are semantic symbols shared by every backend.
    matches!(
        name,
        "_Bool"
            | "_Complex"
            | "_Imaginary"
            | "and"
            | "apply"
            | "asm"
            | "auto"
            | "bit"
            | "bool"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "control"
            | "default"
            | "do"
            | "double"
            | "else"
            | "end"
            | "enum"
            | "error"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "function"
            | "header"
            | "header_union"
            | "if"
            | "in"
            | "inline"
            | "int"
            | "key"
            | "local"
            | "long"
            | "not"
            | "or"
            | "out"
            | "parser"
            | "register"
            | "restrict"
            | "return"
            | "select"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "string"
            | "struct"
            | "switch"
            | "table"
            | "then"
            | "this"
            | "true"
            | "typedef"
            | "type"
            | "typeName"
            | "typeof"
            | "union"
            | "unsigned"
            | "varbit"
            | "void"
            | "volatile"
            | "while"
    )
}

fn validate_symbol(role: &str, name: &str, errs: &mut Vec<String>) {
    if name.is_empty() {
        errs.push(format!("{role} has empty name"));
    } else if !is_portable_ident(name) {
        errs.push(format!(
            "{role} `{name}` is not a portable identifier (expected [A-Za-z_][A-Za-z0-9_]*)"
        ));
    } else if is_backend_keyword(name) {
        errs.push(format!("{role} `{name}` is a reserved backend keyword"));
    }
}

fn c_reason_ident(reason: &str) -> String {
    let mut ident = String::from("PK_R_");
    for ch in reason.chars() {
        ident.push(if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    ident
}

fn validate_expr(e: &pb::Expr, ctx: &str, errs: &mut Vec<String>) {
    match &e.kind {
        None => errs.push(format!("{ctx}: empty expression")),
        Some(pb::expr::Kind::Field(r)) => {
            if r.header.is_empty() || r.field.is_empty() {
                errs.push(format!("{ctx}: field reference has an empty component"));
            }
        }
        Some(pb::expr::Kind::Metadata(r)) => {
            if r.name.is_empty() {
                errs.push(format!("{ctx}: metadata reference has an empty name"));
            }
        }
        Some(pb::expr::Kind::Bin(b)) => {
            match pb::BinOpKind::try_from(b.op) {
                Ok(pb::BinOpKind::Unspecified) => {
                    errs.push(format!("{ctx}: binary expression has unspecified operator"));
                }
                Err(_) => errs.push(format!(
                    "{ctx}: binary expression has unknown operator {}",
                    b.op
                )),
                Ok(_) => {}
            }
            match &b.lhs {
                Some(lhs) => validate_expr(lhs, ctx, errs),
                None => errs.push(format!("{ctx}: binary expression is missing lhs")),
            }
            match &b.rhs {
                Some(rhs) => validate_expr(rhs, ctx, errs),
                None => errs.push(format!("{ctx}: binary expression is missing rhs")),
            }
        }
        Some(pb::expr::Kind::Constant(_) | pb::expr::Kind::Remaining(_)) => {}
    }
}

pub fn validate(ir: &pb::Ir) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();

    // Version gate before anything else: length units changed at 0.2.0
    // (bytes -> bits), so interpreting a stale IR would be silently
    // wrong, not merely deprecated.
    if ir.ir_version != super::IR_VERSION {
        return Err(vec![format!(
            "ir_version `{}` is not the supported `{}` (pre-1.0: regenerate \
             the IR from its source description)",
            ir.ir_version,
            super::IR_VERSION
        )]);
    }

    let Some(parser) = &ir.parser else {
        return Err(vec!["ir has no parser".into()]);
    };

    validate_symbol("parser", &parser.name, &mut errs);

    if parser.max_depth == 0 {
        errs.push("max_depth must be >= 1".into());
    }

    // Header types: unique names, unique field names, sane widths.
    let mut header_types = std::collections::HashMap::new();
    for ht in &parser.header_types {
        validate_symbol("header type", &ht.name, &mut errs);
        if header_types.insert(ht.name.as_str(), ht).is_some() {
            errs.push(format!("duplicate header type `{}`", ht.name));
        }
        let mut fields = std::collections::HashSet::new();
        let mut c_members = std::collections::HashMap::<String, String>::new();
        for f in &ht.fields {
            validate_symbol(
                &format!("field of header type `{}`", ht.name),
                &f.name,
                &mut errs,
            );
            if !fields.insert(f.name.as_str()) {
                errs.push(format!("duplicate field `{}.{}`", ht.name, f.name));
            }
            match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                Some(pb::field_width::Width::Bits(b)) if !(1..=64).contains(b) => {
                    errs.push(format!(
                        "field `{}.{}` width {b} outside 1..=64",
                        ht.name, f.name
                    ));
                }
                Some(_) => {}
                None => errs.push(format!("field `{}.{}` has no width", ht.name, f.name)),
            }
            let emitted: Vec<String> = match f.width.as_ref().and_then(|w| w.width.as_ref()) {
                Some(pb::field_width::Width::BitLen(_)) => {
                    vec![format!("{}_bit_off", f.name), format!("{}_bit_len", f.name)]
                }
                _ => vec![f.name.clone()],
            };
            for member in emitted {
                if let Some(previous) = c_members.insert(member.clone(), f.name.clone()) {
                    errs.push(format!(
                        "header type `{}` fields `{previous}` and `{}` collide as generated C member `{member}`",
                        ht.name, f.name
                    ));
                }
            }
            if let Some(d) = &f.display {
                let mut label_vals = std::collections::HashSet::new();
                for vl in &d.value_labels {
                    if !label_vals.insert(vl.value) {
                        errs.push(format!(
                            "field `{}.{}` duplicate value label {}",
                            ht.name, f.name, vl.value
                        ));
                    }
                    if let Some(pb::field_width::Width::Bits(w)) =
                        f.width.as_ref().and_then(|x| x.width.as_ref())
                    {
                        let max = if *w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                        if vl.value > max {
                            errs.push(format!(
                                "field `{}.{}` value label {} exceeds {w}-bit width",
                                ht.name, f.name, vl.value
                            ));
                        }
                    }
                }
            }
        }
    }

    // Metadata declarations: unique non-empty names, width 1..=64, init fits.
    let mut meta_decls: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for m in &parser.metadata {
        validate_symbol("metadata field", &m.name, &mut errs);
        if !(1..=64).contains(&m.bits) {
            errs.push(format!(
                "metadata `{}` width {} outside 1..=64",
                m.name, m.bits
            ));
        } else if m.bits < 64 && m.init >= (1u64 << m.bits) {
            errs.push(format!(
                "metadata `{}` init {} does not fit in {} bits",
                m.name, m.init, m.bits
            ));
        }
        if meta_decls.insert(m.name.as_str(), m.bits).is_some() {
            errs.push(format!("duplicate metadata `{}`", m.name));
        }
    }

    // States: unique non-empty names.
    let mut states = std::collections::HashSet::new();
    let mut reason_idents = std::collections::HashMap::<String, String>::new();
    for reason in [
        "out of bounds",
        "max depth exceeded",
        "no matching select arm",
        "out of region bounds",
        "region out of bounds",
        "region not exhausted",
    ] {
        reason_idents.insert(c_reason_ident(reason), reason.into());
    }

    for s in &parser.states {
        validate_symbol("state", &s.name, &mut errs);
        if !states.insert(s.name.as_str()) {
            errs.push(format!("duplicate state `{}`", s.name));
        }
    }
    if !states.contains(parser.start_state.as_str()) {
        errs.push(format!("unknown start state `{}`", parser.start_state));
    }

    // Header instances: name -> header type (instance defaults to type name).
    let mut instances = std::collections::HashMap::new();
    for s in &parser.states {
        for e in &s.extracts {
            let inst = if e.instance.is_empty() {
                &e.header_type
            } else {
                &e.instance
            };
            validate_symbol("header instance", inst, &mut errs);
            if !header_types.contains_key(e.header_type.as_str()) {
                errs.push(format!(
                    "state `{}` extracts unknown header type `{}`",
                    s.name, e.header_type
                ));
            } else {
                match instances.entry(inst.as_str()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(e.header_type.as_str());
                    }
                    std::collections::hash_map::Entry::Occupied(entry)
                        if *entry.get() != e.header_type.as_str() =>
                    {
                        errs.push(format!(
                            "header instance `{inst}` is extracted as both `{}` and `{}`",
                            entry.get(),
                            e.header_type
                        ));
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {}
                }
                // W9: a peeked type is all-fixed-width (v1 — keeps
                // peeked layouts offset-computable per symbolic path).
                if e.lookahead {
                    let ht = header_types[e.header_type.as_str()];
                    for f in &ht.fields {
                        if matches!(
                            f.width.as_ref().and_then(|w| w.width.as_ref()),
                            Some(pb::field_width::Width::BitLen(_))
                        ) {
                            errs.push(format!(
                                "state `{}` lookahead of `{}`: field `{}.{}` is \
                                 variable-length (a peeked type must be all-fixed-width)",
                                s.name, e.header_type, ht.name, f.name
                            ));
                        }
                    }
                }
            }
        }
    }

    // The portable C result struct puts instances and metadata beside its
    // built-in observables. Check lowered member names once, during
    // validation, instead of letting a backend emit an invalid struct.
    let mut result_members: std::collections::HashMap<String, String> = [
        ("outcome".into(), "built-in outcome".into()),
        ("reason".into(), "built-in reason".into()),
        ("consumed_bits".into(), "built-in consumed_bits".into()),
    ]
    .into_iter()
    .collect();
    let mut seen_instances = std::collections::HashSet::new();
    for s in &parser.states {
        for e in &s.extracts {
            let inst = if e.instance.is_empty() {
                &e.header_type
            } else {
                &e.instance
            };
            if !seen_instances.insert(inst.as_str()) {
                continue;
            }
            for member in [inst.clone(), format!("{inst}_present")] {
                if let Some(previous) =
                    result_members.insert(member.clone(), format!("instance `{inst}`"))
                {
                    errs.push(format!(
                        "instance `{inst}` collides with {previous} as generated C member `{member}`"
                    ));
                }
            }
            if inst == "verdict" {
                errs.push("header instance `verdict` is reserved by the P4 backend".into());
            }
        }
    }
    for m in &parser.metadata {
        let member = format!("m_{}", m.name);
        if let Some(previous) =
            result_members.insert(member.clone(), format!("metadata `{}`", m.name))
        {
            errs.push(format!(
                "metadata `{}` collides with {previous} as generated C member `{member}`",
                m.name
            ));
        }
    }

    let check_ref = |r: &pb::FieldRef, ctx: &str, errs: &mut Vec<String>| match instances
        .get(r.header.as_str())
    {
        None => errs.push(format!("{ctx}: unknown header instance `{}`", r.header)),
        Some(ht_name) => {
            let ht = header_types[ht_name];
            if !ht.fields.iter().any(|f| f.name == r.field) {
                errs.push(format!(
                    "{ctx}: header `{}` has no field `{}`",
                    r.header, r.field
                ));
            }
        }
    };

    let check_meta_ref = |r: &pb::MetadataRef, ctx: &str, errs: &mut Vec<String>| {
        if !meta_decls.contains_key(r.name.as_str()) {
            errs.push(format!("{ctx}: unknown metadata `{}`", r.name));
        }
    };

    fn walk_refs<'a>(e: &'a pb::Expr, out: &mut Vec<&'a pb::FieldRef>) {
        match &e.kind {
            Some(pb::expr::Kind::Field(r)) => out.push(r),
            Some(pb::expr::Kind::Bin(b)) => {
                if let Some(l) = &b.lhs {
                    walk_refs(l, out);
                }
                if let Some(r) = &b.rhs {
                    walk_refs(r, out);
                }
            }
            Some(pb::expr::Kind::Metadata(_)) => {}
            _ => {}
        }
    }

    fn walk_meta_refs<'a>(e: &'a pb::Expr, out: &mut Vec<&'a pb::MetadataRef>) {
        match &e.kind {
            Some(pb::expr::Kind::Metadata(r)) => out.push(r),
            Some(pb::expr::Kind::Bin(b)) => {
                if let Some(l) = &b.lhs {
                    walk_meta_refs(l, out);
                }
                if let Some(r) = &b.rhs {
                    walk_meta_refs(r, out);
                }
            }
            _ => {}
        }
    }

    // Field refs inside variable-length widths. `bit_len` must not
    // reference metadata (v1 restriction: metadata may not affect a
    // header's extracted size, which would undermine pathid soundness)
    // and must not use `remaining()` (v1: widths stay region-blind).
    for ht in &parser.header_types {
        for f in &ht.fields {
            if let Some(pb::field_width::Width::BitLen(e)) =
                f.width.as_ref().and_then(|w| w.width.as_ref())
            {
                let width_ctx = format!("width of `{}.{}`", ht.name, f.name);
                validate_expr(e, &width_ctx, &mut errs);
                let mut refs = Vec::new();
                walk_refs(e, &mut refs);
                for r in refs {
                    check_ref(r, &format!("width of `{}.{}`", ht.name, f.name), &mut errs);
                }
                let mut meta_refs = Vec::new();
                walk_meta_refs(e, &mut meta_refs);
                if !meta_refs.is_empty() {
                    errs.push(format!(
                        "field `{}.{}`: bit_len must not reference metadata",
                        ht.name, f.name
                    ));
                }
                if contains_remaining(e) {
                    errs.push(format!(
                        "field `{}.{}`: bit_len must not use remaining()",
                        ht.name, f.name
                    ));
                }
            }
        }
    }

    // Transitions: targets resolve, select arity matches, refs resolve,
    // keyset entries fit the key's width when the key is a plain field ref
    // or a metadata ref.
    let key_width = |e: &pb::Expr| -> Option<u32> {
        match &e.kind {
            Some(pb::expr::Kind::Field(r)) => {
                let ht = header_types.get(*instances.get(r.header.as_str())?)?;
                let f = ht.fields.iter().find(|f| f.name == r.field)?;
                if let Some(pb::field_width::Width::Bits(b)) =
                    f.width.as_ref().and_then(|w| w.width.as_ref())
                {
                    return Some(*b);
                }
                None
            }
            Some(pb::expr::Kind::Metadata(r)) => meta_decls.get(r.name.as_str()).copied(),
            _ => None,
        }
    };

    for s in &parser.states {
        let ctx = format!("state `{}`", s.name);

        for (i, op) in s.region_ops.iter().enumerate() {
            match &op.kind {
                Some(pb::region_op::Kind::Push(e)) => {
                    let push_ctx = format!("state `{}` region push #{i}", s.name);
                    validate_expr(e, &push_ctx, &mut errs);
                    let mut refs = Vec::new();
                    walk_refs(e, &mut refs);
                    for r in refs {
                        check_ref(r, &push_ctx, &mut errs);
                    }
                    let mut meta_refs = Vec::new();
                    walk_meta_refs(e, &mut meta_refs);
                    if !meta_refs.is_empty() {
                        errs.push(format!(
                            "{push_ctx}: push length must not reference metadata"
                        ));
                    }
                    if contains_remaining(e) {
                        // v1: keeps pathid's push-length replay a plain
                        // env evaluation (no remaining() context).
                        errs.push(format!("{push_ctx}: push length must not use remaining()"));
                    }
                }
                Some(pb::region_op::Kind::Pop(_)) => {}
                None => errs.push(format!("{ctx}: empty region op #{i}")),
            }
        }

        for a in &s.assigns {
            if !meta_decls.contains_key(a.metadata.as_str()) {
                errs.push(format!("{ctx}: unknown metadata `{}`", a.metadata));
            }
            if let Some(value) = &a.value {
                let assign_ctx = format!("state `{}` assign `{}`", s.name, a.metadata);
                validate_expr(value, &assign_ctx, &mut errs);
                let mut refs = Vec::new();
                walk_refs(value, &mut refs);
                for r in refs {
                    check_ref(r, &assign_ctx, &mut errs);
                }
                let mut meta_refs = Vec::new();
                walk_meta_refs(value, &mut meta_refs);
                for r in meta_refs {
                    check_meta_ref(r, &assign_ctx, &mut errs);
                }
            } else {
                errs.push(format!("{ctx}: assign `{}` has no value", a.metadata));
            }
        }

        let mut check_target = |t: &pb::Target, errs: &mut Vec<String>| match &t.kind {
            Some(pb::target::Kind::State(name)) => {
                if !states.contains(name.as_str()) {
                    errs.push(format!("{ctx}: unknown state `{name}`"));
                }
            }
            Some(pb::target::Kind::Reject(r)) => {
                if r.reason.is_empty() {
                    errs.push(format!("{ctx}: reject has empty reason"));
                }
                if let Some(sev) = r.annotations.get("severity") {
                    if sev != "error" && sev != "info" {
                        errs.push(format!(
                            "{ctx}: reject severity `{sev}` (must be `error` or `info`)"
                        ));
                    }
                }
                let ident = c_reason_ident(&r.reason);
                if let Some(previous) = reason_idents.insert(ident.clone(), r.reason.clone()) {
                    if previous != r.reason {
                        errs.push(format!(
                            "reject reasons `{previous}` and `{}` collide as generated C identifier `{ident}`",
                            r.reason
                        ));
                    }
                }
            }
            None => errs.push(format!("{ctx}: empty target")),
            Some(pb::target::Kind::Accept(_)) => {}
        };
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            None => errs.push(format!("{ctx}: no transition")),
            Some(pb::transition::Kind::Direct(t)) => check_target(t, &mut errs),
            Some(pb::transition::Kind::Select(sel)) => {
                if sel.keys.is_empty() {
                    errs.push(format!("{ctx}: select has no keys"));
                }
                for k in &sel.keys {
                    validate_expr(k, &format!("{ctx} select key"), &mut errs);
                    let mut refs = Vec::new();
                    walk_refs(k, &mut refs);
                    for r in refs {
                        check_ref(r, &ctx, &mut errs);
                    }
                    let mut meta_refs = Vec::new();
                    walk_meta_refs(k, &mut meta_refs);
                    for r in meta_refs {
                        check_meta_ref(r, &ctx, &mut errs);
                    }
                }
                for arm in &sel.arms {
                    if arm.entries.len() != sel.keys.len() {
                        errs.push(format!(
                            "{ctx}: arm has {} entries for {} keys",
                            arm.entries.len(),
                            sel.keys.len()
                        ));
                    }
                    for (entry, key) in arm.entries.iter().zip(&sel.keys) {
                        match entry.kind.as_ref() {
                            None => errs.push(format!("{ctx}: empty keyset entry")),
                            Some(pb::keyset_entry::Kind::Range(r)) if r.lo > r.hi => {
                                errs.push(format!(
                                    "{ctx}: invalid keyset range {}..={} (lo exceeds hi)",
                                    r.lo, r.hi
                                ))
                            }
                            Some(_) => {}
                        }
                        if let (Some(w), Some(kind)) = (key_width(key), entry.kind.as_ref()) {
                            let max = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                            let vals: &[u64] = match kind {
                                pb::keyset_entry::Kind::Value(v) => &[*v],
                                pb::keyset_entry::Kind::Masked(m) => &[m.value, m.mask],
                                pb::keyset_entry::Kind::Range(r) => &[r.lo, r.hi],
                            };
                            if vals.iter().any(|v| *v > max) {
                                errs.push(format!("{ctx}: keyset entry exceeds {w}-bit key width"));
                            }
                        }
                    }
                    if let Some(t) = &arm.next {
                        check_target(t, &mut errs);
                    } else {
                        errs.push(format!("{ctx}: select arm has no target"));
                    }
                }
                if let Some(t) = &sel.default_target {
                    check_target(t, &mut errs);
                } else {
                    errs.push(format!("{ctx}: select has no default target"));
                }
            }
        }
    }

    // Path-sensitive def-use: an expression may only reference header
    // instances *definitely* extracted on every path to its use point.
    // Must-analysis fixpoint: in(s) = ∩ over predecessors p of
    // (in(p) ∪ extracted(p)); in(start) = ∅.
    if errs.is_empty() {
        definite_extraction_errors(parser, &header_types, &mut errs);
    }

    if errs.is_empty() {
        region_depth_errors(parser, &mut errs);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Every reachable state must be entered at ONE region-stack depth:
/// propagate depths from the start state and flag pops on an empty
/// stack and depth mismatches. Consistency subsumes boundedness — a
/// net-positive cycle would revisit a state at a different depth.
/// Also enforces that `remaining()` is only used with a region open
/// (assigns: entry depth; push #i: depth before that op; select keys:
/// post-ops depth) — it is structural, undefined outside a region.
fn region_depth_errors(parser: &pb::Parser, errs: &mut Vec<String>) {
    use std::collections::HashMap;

    let states: HashMap<&str, &pb::State> =
        parser.states.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut depth: HashMap<&str, i64> = HashMap::new();
    depth.insert(parser.start_state.as_str(), 0);
    let mut work = vec![parser.start_state.as_str()];
    while let Some(name) = work.pop() {
        let s = states[name];
        let mut cur = depth[name];
        if cur == 0 {
            for a in &s.assigns {
                if a.value.as_ref().is_some_and(contains_remaining) {
                    errs.push(format!(
                        "state `{name}` assign `{}`: remaining() with no open region",
                        a.metadata
                    ));
                    return;
                }
            }
        }
        for (i, op) in s.region_ops.iter().enumerate() {
            match &op.kind {
                Some(pb::region_op::Kind::Push(e)) => {
                    if cur == 0 && contains_remaining(e) {
                        errs.push(format!(
                            "state `{name}` region push #{i}: remaining() with no open region"
                        ));
                        return;
                    }
                    cur += 1;
                }
                Some(pb::region_op::Kind::Pop(_)) => {
                    cur -= 1;
                    if cur < 0 {
                        errs.push(format!(
                            "state `{name}`: region pop #{i} with no open region"
                        ));
                        return;
                    }
                }
                None => {}
            }
        }
        if cur == 0 {
            if let Some(pb::transition::Kind::Select(sel)) =
                s.transition.as_ref().and_then(|t| t.kind.as_ref())
            {
                if sel.keys.iter().any(contains_remaining) {
                    errs.push(format!(
                        "state `{name}` select key: remaining() with no open region"
                    ));
                    return;
                }
            }
        }
        let mut visit = |t: &pb::Target| {
            if let Some(pb::target::Kind::State(succ)) = &t.kind {
                match depth.get(succ.as_str()) {
                    None => {
                        if let Some((k, _)) = states.get_key_value(succ.as_str()) {
                            depth.insert(k, cur);
                            work.push(k);
                        }
                    }
                    Some(d) if *d != cur => {
                        errs.push(format!(
                            "state `{succ}` is entered at region depth {cur} and {d} \
                             (every state must have one depth)"
                        ));
                    }
                    Some(_) => {}
                }
            }
        };
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => visit(t),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = &arm.next {
                        visit(t);
                    }
                }
                if let Some(t) = &sel.default_target {
                    visit(t);
                }
            }
            None => {}
        }
        if !errs.is_empty() {
            return;
        }
    }
}

fn contains_remaining(e: &pb::Expr) -> bool {
    match &e.kind {
        Some(pb::expr::Kind::Remaining(_)) => true,
        Some(pb::expr::Kind::Bin(b)) => {
            b.lhs.as_deref().is_some_and(contains_remaining)
                || b.rhs.as_deref().is_some_and(contains_remaining)
        }
        _ => false,
    }
}

fn state_instances(s: &pb::State) -> Vec<String> {
    s.extracts
        .iter()
        .map(|e| {
            if e.instance.is_empty() {
                e.header_type.clone()
            } else {
                e.instance.clone()
            }
        })
        .collect()
}

fn definite_extraction_errors(
    parser: &pb::Parser,
    header_types: &std::collections::HashMap<&str, &pb::HeaderType>,
    errs: &mut Vec<String>,
) {
    use std::collections::{HashMap, HashSet};

    let succs = |s: &pb::State| -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |t: &pb::Target| {
            if let Some(pb::target::Kind::State(n)) = &t.kind {
                out.push(n.clone());
            }
        };
        match s.transition.as_ref().and_then(|t| t.kind.as_ref()) {
            Some(pb::transition::Kind::Direct(t)) => push(t),
            Some(pb::transition::Kind::Select(sel)) => {
                for arm in &sel.arms {
                    if let Some(t) = &arm.next {
                        push(t);
                    }
                }
                if let Some(t) = &sel.default_target {
                    push(t);
                }
            }
            None => {}
        }
        out
    };

    // Fixpoint over must-extracted sets at state entry.
    let all: HashSet<String> = parser.states.iter().flat_map(state_instances).collect();
    let mut inset: HashMap<&str, HashSet<String>> = parser
        .states
        .iter()
        .map(|s| {
            let init = if s.name == parser.start_state {
                HashSet::new()
            } else {
                all.clone()
            };
            (s.name.as_str(), init)
        })
        .collect();
    loop {
        let mut changed = false;
        for s in &parser.states {
            let out: HashSet<String> = inset[s.name.as_str()]
                .iter()
                .cloned()
                .chain(state_instances(s))
                .collect();
            for succ in succs(s) {
                if let Some(cur) = inset.get_mut(succ.as_str()) {
                    let narrowed: HashSet<String> = cur.intersection(&out).cloned().collect();
                    if narrowed.len() != cur.len() {
                        *cur = narrowed;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Check every expression use point against the available set.
    let mut check_expr = |e: &pb::Expr, avail: &HashSet<String>, ctx: &str| {
        let mut refs = Vec::new();
        collect_refs(e, &mut refs);
        for r in refs {
            if !avail.contains(&r.header) {
                errs.push(format!(
                    "{ctx}: `{}.{}` is not definitely extracted on every path to this point",
                    r.header, r.field
                ));
            }
        }
    };
    for s in &parser.states {
        let mut avail = inset[s.name.as_str()].clone();
        for ex in &s.extracts {
            let inst = if ex.instance.is_empty() {
                &ex.header_type
            } else {
                &ex.instance
            };
            // Var-length exprs inside this header may use earlier
            // fields of the same instance: add before checking widths.
            avail.insert(inst.clone());
            if let Some(ht) = header_types.get(ex.header_type.as_str()) {
                for f in &ht.fields {
                    if let Some(pb::field_width::Width::BitLen(e)) =
                        f.width.as_ref().and_then(|w| w.width.as_ref())
                    {
                        check_expr(
                            e,
                            &avail,
                            &format!("state `{}` width of `{inst}.{}`", s.name, f.name),
                        );
                    }
                }
            }
        }
        // Assigns run after this state's extracts (and before its
        // transition), so a field extracted in this state is legal here —
        // same treatment as select keys, below.
        for a in &s.assigns {
            if let Some(value) = &a.value {
                check_expr(
                    value,
                    &avail,
                    &format!("state `{}` assign `{}`", s.name, a.metadata),
                );
            }
        }
        if let Some(pb::transition::Kind::Select(sel)) =
            s.transition.as_ref().and_then(|t| t.kind.as_ref())
        {
            for k in &sel.keys {
                check_expr(k, &avail, &format!("state `{}` select key", s.name));
            }
        }
    }
}

fn collect_refs<'a>(e: &'a pb::Expr, out: &mut Vec<&'a pb::FieldRef>) {
    match &e.kind {
        Some(pb::expr::Kind::Field(r)) => out.push(r),
        Some(pb::expr::Kind::Bin(b)) => {
            if let Some(l) = &b.lhs {
                collect_refs(l, out);
            }
            if let Some(r) = &b.rhs {
                collect_refs(r, out);
            }
        }
        Some(pb::expr::Kind::Metadata(_)) => {}
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::pb;
    use super::super::test_support::tiny;
    use super::validate;

    fn parser(ir: &mut pb::Ir) -> &mut pb::Parser {
        ir.parser.as_mut().unwrap()
    }

    fn set_direct_target(ir: &mut pb::Ir, state: &str) {
        parser(ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::State(state.into())),
            })),
        });
    }

    fn assert_err_contains(ir: &pb::Ir, needle: &str) {
        let errs = validate(ir).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "expected an error containing {needle:?}, got {errs:?}"
        );
    }

    #[test]
    fn accepts_tiny() {
        validate(&tiny()).unwrap();
    }

    #[test]
    fn rejects_missing_parser() {
        let ir = pb::Ir {
            ir_version: crate::ir::IR_VERSION.into(),
            parser: None,
        };
        assert_err_contains(&ir, "no parser");
    }

    #[test]
    fn rejects_stale_ir_version() {
        let mut ir = tiny();
        ir.ir_version = "0.1.0".into();
        assert_err_contains(&ir, "ir_version `0.1.0`");
    }

    #[test]
    fn rejects_zero_max_depth() {
        let mut ir = tiny();
        parser(&mut ir).max_depth = 0;
        assert_err_contains(&ir, "max_depth");
    }

    #[test]
    fn rejects_dup_state() {
        let mut ir = tiny();
        let dup = parser(&mut ir).states[0].clone();
        parser(&mut ir).states.push(dup);
        assert_err_contains(&ir, "duplicate state `s`");
    }

    #[test]
    fn rejects_unresolved_start() {
        let mut ir = tiny();
        parser(&mut ir).start_state = "nope".into();
        assert_err_contains(&ir, "unknown start state `nope`");
    }

    #[test]
    fn rejects_unresolved_target() {
        let mut ir = tiny();
        set_direct_target(&mut ir, "nope");
        assert_err_contains(&ir, "unknown state `nope`");
    }

    #[test]
    fn rejects_bad_width() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(65)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_err_contains(&ir, "width 65 outside 1..=64");
    }

    #[test]
    fn rejects_conflicting_header_instance_types() {
        let mut ir = tiny();
        let p = parser(&mut ir);
        p.header_types = ["a", "b"]
            .into_iter()
            .map(|name| pb::HeaderType {
                name: name.into(),
                fields: vec![pb::Field {
                    name: "value".into(),
                    width: Some(pb::FieldWidth {
                        width: Some(pb::field_width::Width::Bits(8)),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .collect();
        p.states[0].extracts = vec![
            pb::Extract {
                header_type: "a".into(),
                instance: "same".into(),
                lookahead: false,
            },
            pb::Extract {
                header_type: "b".into(),
                instance: "same".into(),
                lookahead: false,
            },
        ];
        assert_err_contains(&ir, "instance `same` is extracted as both `a` and `b`");
    }

    #[test]
    fn rejects_nonportable_symbols_and_lowering_collisions() {
        let mut ir = tiny();
        parser(&mut ir).name = "bad-name".into();
        assert_err_contains(&ir, "not a portable identifier");

        let mut ir = tiny();
        parser(&mut ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::Reject(pb::Reject {
                    reason: "out-of-bounds".into(),
                    ..Default::default()
                })),
            })),
        });
        assert_err_contains(&ir, "collide as generated C identifier");
    }

    #[test]
    fn rejects_incomplete_expression_and_select_structure() {
        let mut ir = tiny();
        parser(&mut ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Select(pb::Select {
                keys: vec![pb::Expr { kind: None }],
                arms: vec![pb::SelectArm {
                    entries: vec![pb::KeysetEntry { kind: None }],
                    next: None,
                }],
                default_target: None,
            })),
        });
        let errs = validate(&ir).unwrap_err();
        for needle in [
            "empty expression",
            "empty keyset entry",
            "select arm has no target",
            "select has no default target",
        ] {
            assert!(
                errs.iter().any(|e| e.contains(needle)),
                "missing {needle:?} in {errs:?}"
            );
        }
    }

    fn field_ref(header: &str, field: &str) -> pb::Expr {
        pb::Expr {
            kind: Some(pb::expr::Kind::Field(pb::FieldRef {
                header: header.into(),
                field: field.into(),
            })),
        }
    }

    fn with_select(ir: &mut pb::Ir, keys: Vec<pb::Expr>, arms: Vec<pb::SelectArm>) {
        parser(ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Select(pb::Select {
                keys,
                arms,
                default_target: Some(pb::Target {
                    kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                }),
            })),
        });
    }

    #[test]
    fn rejects_arity_mismatch() {
        let mut ir = tiny();
        with_select(
            &mut ir,
            vec![field_ref("x", "y")],
            vec![pb::SelectArm {
                entries: vec![],
                next: None,
            }],
        );
        assert_err_contains(&ir, "0 entries for 1 keys");
    }

    #[test]
    fn rejects_unknown_field_ref() {
        let mut ir = tiny();
        with_select(&mut ir, vec![field_ref("ghost", "f")], vec![]);
        assert_err_contains(&ir, "unknown header instance `ghost`");
    }

    #[test]
    fn rejects_unknown_metadata_select_key() {
        let mut ir = tiny();
        with_select(
            &mut ir,
            vec![pb::Expr {
                kind: Some(pb::expr::Kind::Metadata(pb::MetadataRef {
                    name: "ghost".into(),
                })),
            }],
            vec![],
        );
        assert_err_contains(&ir, "unknown metadata `ghost`");
    }

    #[test]
    fn rejects_bad_severity() {
        let mut ir = tiny();
        parser(&mut ir).states[0].transition = Some(pb::Transition {
            kind: Some(pb::transition::Kind::Direct(pb::Target {
                kind: Some(pb::target::Kind::Reject(pb::Reject {
                    reason: "r".into(),
                    annotations: [("severity".to_string(), "fatal".to_string())].into(),
                })),
            })),
        });
        assert_err_contains(&ir, "reject severity `fatal`");
    }

    #[test]
    fn rejects_bad_value_labels() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(4)),
                }),
                display: Some(pb::Display {
                    name: "F".into(),
                    value_labels: vec![
                        pb::ValueLabel {
                            value: 3,
                            label: "a".into(),
                        },
                        pb::ValueLabel {
                            value: 3,
                            label: "b".into(),
                        },
                        pb::ValueLabel {
                            value: 99,
                            label: "c".into(),
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_err_contains(&ir, "duplicate value label 3");
        assert_err_contains(&ir, "value label 99 exceeds 4-bit width");
    }

    #[test]
    fn rejects_branch_dependent_ref() {
        use crate::builder::*;
        let err = ParserBuilder::new("branchy", 3)
            .header(HeaderTypeBuilder::new("h").bits("f", 8))
            .header(HeaderTypeBuilder::new("g").bits("x", 8))
            .state(StateBuilder::new("a").extract("h").select(
                vec![f("h", "f")],
                vec![arm(vec![v(1)], to("b"))],
                to("c"),
            ))
            .state(StateBuilder::new("b").extract("g").goto_(to("c")))
            .state(StateBuilder::new("c").select(
                vec![f("g", "x")],
                vec![arm(vec![v(1)], accept())],
                reject("no"),
            ))
            .start("a")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("not definitely extracted"));
    }

    #[test]
    fn rejects_oversized_keyset_value() {
        let mut ir = tiny();
        parser(&mut ir).header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "f".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::Bits(8)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        parser(&mut ir).states[0].extracts.push(pb::Extract {
            header_type: "h".into(),
            instance: String::new(),
            lookahead: false,
        });
        with_select(
            &mut ir,
            vec![field_ref("h", "f")],
            vec![pb::SelectArm {
                entries: vec![pb::KeysetEntry {
                    kind: Some(pb::keyset_entry::Kind::Value(256)),
                }],
                next: Some(pb::Target {
                    kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                }),
            }],
        );
        assert_err_contains(&ir, "exceeds 8-bit key width");
    }

    #[test]
    fn rejects_oversized_metadata_keyset_value() {
        let mut ir = tiny();
        let p = ir.parser.as_mut().unwrap();
        p.metadata.push(pb::MetadataField {
            name: "m".into(),
            bits: 8,
            init: 0,
            ..Default::default()
        });
        with_select(
            &mut ir,
            vec![pb::Expr {
                kind: Some(pb::expr::Kind::Metadata(pb::MetadataRef {
                    name: "m".into(),
                })),
            }],
            vec![pb::SelectArm {
                entries: vec![pb::KeysetEntry {
                    kind: Some(pb::keyset_entry::Kind::Value(256)),
                }],
                next: Some(pb::Target {
                    kind: Some(pb::target::Kind::Accept(pb::Accept {})),
                }),
            }],
        );
        assert_err_contains(&ir, "exceeds 8-bit key width");
    }

    #[test]
    fn rejects_bad_metadata_decls() {
        let mut ir = tiny();
        let p = ir.parser.as_mut().unwrap();
        p.metadata.push(pb::MetadataField {
            name: "".into(),
            bits: 0,
            init: 0,
            ..Default::default()
        });
        p.metadata.push(pb::MetadataField {
            name: "m".into(),
            bits: 65,
            init: 0,
            ..Default::default()
        });
        p.metadata.push(pb::MetadataField {
            name: "m".into(),
            bits: 4,
            init: 16,
            ..Default::default()
        });
        assert_err_contains(&ir, "metadata field has empty name");
        assert_err_contains(&ir, "metadata `m` width 65 outside 1..=64");
        assert_err_contains(&ir, "duplicate metadata `m`");
        assert_err_contains(&ir, "metadata `m` init 16 does not fit in 4 bits");
    }

    #[test]
    fn rejects_undeclared_metadata_refs() {
        let mut ir = tiny();
        let p = ir.parser.as_mut().unwrap();
        // assign to undeclared target, RHS referencing undeclared metadata
        p.states[0].assigns.push(pb::Assign {
            metadata: "ghost".into(),
            value: Some(pb::Expr {
                kind: Some(pb::expr::Kind::Metadata(pb::MetadataRef {
                    name: "ghost2".into(),
                })),
            }),
        });
        assert_err_contains(&ir, "unknown metadata `ghost`");
        assert_err_contains(&ir, "unknown metadata `ghost2`");
    }

    #[test]
    fn rejects_var_length_under_lookahead() {
        use crate::builder::*;
        let err = ParserBuilder::new("peek_var", 2)
            .header(
                HeaderTypeBuilder::new("h")
                    .bits("n", 8)
                    .var_bytes("body", f("h", "n")),
            )
            .state(StateBuilder::new("s").lookahead("h").accept())
            .start("s")
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("all-fixed-width"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_pop_with_no_open_region() {
        use crate::builder::*;
        let err = ParserBuilder::new("bad_pop", 2)
            .state(StateBuilder::new("s").pop_region().accept())
            .start("s")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("no open region"));
    }

    #[test]
    fn rejects_inconsistent_region_depth() {
        use crate::builder::*;
        // `c` is reachable inside the region (via a) and outside (via b).
        let err = ParserBuilder::new("two_depths", 4)
            .header(HeaderTypeBuilder::new("h").bits("x", 8))
            .state(
                StateBuilder::new("s0")
                    .extract("h")
                    .push_region(f("h", "x"))
                    .select(vec![f("h", "x")], vec![arm(vec![v(1)], to("a"))], to("b")),
            )
            .state(StateBuilder::new("a").goto_(to("c")))
            .state(StateBuilder::new("b").pop_region().goto_(to("c")))
            .state(StateBuilder::new("c").accept())
            .start("s0")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("region depth"));
    }

    #[test]
    fn rejects_remaining_in_bit_len() {
        use crate::builder::*;
        let err = ParserBuilder::new("rem_width", 2)
            .header(HeaderTypeBuilder::new("h").var_bytes("rest", remaining()))
            .state(StateBuilder::new("s").extract("h").accept())
            .start("s")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("bit_len must not use remaining()"));
    }

    #[test]
    fn rejects_remaining_with_no_open_region() {
        use crate::builder::*;
        let err = ParserBuilder::new("rootless_rem", 2)
            .header(HeaderTypeBuilder::new("h").bits("x", 8))
            .state(StateBuilder::new("s").extract("h").select(
                vec![remaining()],
                vec![arm(vec![v(0)], accept())],
                reject("r"),
            ))
            .start("s")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("remaining() with no open region"));
    }

    #[test]
    fn rejects_metadata_in_region_push() {
        use crate::builder::*;
        let err = ParserBuilder::new("meta_push", 2)
            .meta("n", 8, 0)
            .state(StateBuilder::new("s").push_region(m("n")).accept())
            .start("s")
            .build()
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("push length must not reference metadata"));
    }

    #[test]
    fn rejects_metadata_in_bit_len() {
        // v1 restriction: bit_len must not reference metadata (pathid soundness).
        let mut ir = tiny();
        let p = ir.parser.as_mut().unwrap();
        p.metadata.push(pb::MetadataField {
            name: "n".into(),
            bits: 8,
            init: 0,
            ..Default::default()
        });
        p.header_types.push(pb::HeaderType {
            name: "h".into(),
            fields: vec![pb::Field {
                name: "body".into(),
                width: Some(pb::FieldWidth {
                    width: Some(pb::field_width::Width::BitLen(pb::Expr {
                        kind: Some(pb::expr::Kind::Metadata(pb::MetadataRef {
                            name: "n".into(),
                        })),
                    })),
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_err_contains(&ir, "bit_len must not reference metadata");
    }
}

"""Assemble a validated-enough `ir_pb2.Ir` from headers + states.

`Assembly` is the internal built artifact behind the `Parser` base
class's `to_pb()`/`to_json()`/`save()`. Fast-fail checks only
(unknown state names, oversized select keys); the Rust CLI
(`pakeles lint`) remains the validation authority.
"""

from __future__ import annotations

from google.protobuf import json_format

from pakeles._header import Header
from pakeles._metadata import Metadata, MetadataFieldSpec
from pakeles._pb import ir_pb2
from pakeles._states import Accept, Masked, Reject, SelectSpec, State, Target

IR_VERSION = "0.1.0"


class Assembly:
    def __init__(
        self,
        name: str,
        *,
        max_depth: int,
        start: str,
        states: dict[str, State],
        metadata: type[Metadata] | None = None,
        doc: str | None = None,
    ) -> None:
        self._name = name
        self._max_depth = max_depth
        self._start = start
        self._states = dict(states)
        self._metadata = metadata
        self._doc = doc
        self._check()

    def _check_metadata_field(
        self, sname: str, what: str, field: MetadataFieldSpec
    ) -> None:
        if self._metadata is None:
            raise ValueError(
                f"state {sname!r}: {what} {field.name!r} used but parser() has "
                f"no metadata= declared"
            )
        fields: list[MetadataFieldSpec] = self._metadata._fields  # type: ignore[attr-defined]
        if not any(field is f for f in fields):
            raise ValueError(
                f"state {sname!r}: {what} {field.name!r} does not belong to "
                f"the declared metadata class {self._metadata.__name__!r}"
            )

    def _check(self) -> None:
        if self._start not in self._states:
            raise ValueError(f"start state {self._start!r} is not in states")
        for sname, chain in self._states.items():
            if chain.transition is None:
                raise ValueError(f"state {sname!r} has no transition")
            for target, _value in chain.assigns:
                self._check_metadata_field(sname, "assign target", target)
            targets: list[Target] = []
            if isinstance(chain.transition, SelectSpec):
                sel = chain.transition
                targets.extend(sel.arms.values())
                targets.append(sel.default)
                for key_spec in sel.keys:
                    if key_spec.width_bits is None:
                        raise ValueError(
                            f"state {sname!r}: select key "
                            f"{key_spec.header}.{key_spec.name} is not a fixed field"
                        )
                    if isinstance(key_spec, MetadataFieldSpec):
                        self._check_metadata_field(sname, "select key", key_spec)
                for arm_key in sel.arms:
                    values = arm_key if isinstance(arm_key, tuple) else (arm_key,)
                    if len(values) != len(sel.keys):
                        raise ValueError(
                            f"state {sname!r}: arm {arm_key!r} has "
                            f"{len(values)} values for {len(sel.keys)} keys"
                        )
                    for value, key_spec in zip(values, sel.keys):
                        assert key_spec.width_bits is not None
                        bound = value.mask if isinstance(value, Masked) else value
                        if bound >= 1 << key_spec.width_bits:
                            raise ValueError(
                                f"state {sname!r}: arm value {bound:#x} does not "
                                f"fit {key_spec.header}.{key_spec.name} "
                                f"({key_spec.width_bits} bits)"
                            )
            else:
                targets.append(chain.transition)
            for t in targets:
                if isinstance(t, str):
                    if t not in self._states:
                        raise ValueError(
                            f"state {sname!r} references unknown state {t!r}"
                        )
                elif not isinstance(t, (Accept, Reject)):
                    raise TypeError(
                        f"state {sname!r} holds an unresolved state-method "
                        f"reference {t!r}; states assemble via the "
                        f"Parser base class"
                    )

    def _header_types(self) -> list[type[Header]]:
        seen: dict[str, type[Header]] = {}
        for chain in self._states.values():
            for header, _ in chain.extracts:
                seen.setdefault(header.ir_name(), header)
        return list(seen.values())

    def _var_width_instance(self) -> dict[str, str]:
        """For each header type carrying a variable-length field, the
        single instance name it is extracted under. Var-width lengths are
        instance-relative (sibling refs name the enclosing header; refs to
        *other* headers, e.g. GRE flag bits sizing GREOpt, already carry
        their own instance), and every consumer keys field refs by
        instance; in the default case the instance equals the type name,
        so this only matters for custom-named instances
        (e.g. `IPv6ExtOpt["ext_opt"]`).
        A var-width header extracted under >1 distinct instance would need
        per-instance header types, which the IR does not model."""
        out: dict[str, str] = {}
        for chain in self._states.values():
            for header, instance in chain.extracts:
                if not any(
                    f.byte_len_expr is not None
                    for f in header._fields  # type: ignore[attr-defined]
                ):
                    continue
                name = header.ir_name()
                inst = instance if instance is not None else name
                prev = out.setdefault(name, inst)
                if prev != inst:
                    raise ValueError(
                        f"header type {name!r} has a variable-length field "
                        f"but is extracted under multiple instance names "
                        f"({prev!r}, {inst!r}); this is not supported"
                    )
        return out

    def to_pb(self) -> ir_pb2.Ir:
        ir = ir_pb2.Ir(ir_version=IR_VERSION)
        p = ir.parser
        p.name = self._name
        p.max_depth = self._max_depth
        p.start_state = self._start
        if self._doc:
            p.annotations["doc"] = self._doc
        if self._metadata is not None:
            for mf in self._metadata._fields:  # type: ignore[attr-defined]
                pm = p.metadata.add()
                pm.name = mf.name
                pm.bits = mf.width_bits
                if mf.init:
                    pm.init = mf.init
                if mf.display_name or mf.format or mf.doc:
                    pm.display.name = mf.display_name
                    pm.display.format = mf.format
                    pm.display.doc = mf.doc
        var_inst = self._var_width_instance()
        for header in self._header_types():
            ht = header.to_pb()
            inst = var_inst.get(header.ir_name())
            if inst is not None and inst != header.ir_name():
                for f in ht.fields:
                    if f.width.WhichOneof("width") == "byte_len":
                        _rebind_expr_header(f.width.byte_len, header.ir_name(), inst)
            p.header_types.append(ht)
        for sname, chain in self._states.items():
            st = p.states.add()
            st.name = sname
            if chain.doc:
                st.annotations["doc"] = chain.doc
            for header, instance in chain.extracts:
                ex = st.extracts.add()
                ex.header_type = header.ir_name()
                if instance is not None:
                    ex.instance = instance
            for target, value in chain.assigns:
                a = st.assigns.add()
                a.metadata = target.name
                a.value.CopyFrom(value.to_pb())
            for kind, rlen in chain.region_ops:
                op = st.region_ops.add()
                if kind == "push":
                    assert rlen is not None
                    op.push.CopyFrom(rlen.to_pb())
                else:
                    op.pop.SetInParent()
            tr = chain.transition
            assert tr is not None
            if isinstance(tr, SelectSpec):
                sel = st.transition.select
                for key_spec in sel_keys(tr):
                    sel.keys.append(key_spec)
                for arm_key, target in tr.arms.items():
                    arm = sel.arms.add()
                    values = arm_key if isinstance(arm_key, tuple) else (arm_key,)
                    for value in values:
                        entry = arm.entries.add()
                        if isinstance(value, Masked):
                            entry.masked.value = value.value
                            entry.masked.mask = value.mask
                        else:
                            entry.value = value
                    _fill_target(arm.next, target)
                _fill_target(sel.default_target, tr.default)
            else:
                _fill_target(st.transition.direct, tr)
        return ir

    def to_json(self) -> str:
        return json_format.MessageToJson(self.to_pb(), sort_keys=True)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
            f.write("\n")


def _rebind_expr_header(expr: ir_pb2.Expr, type_name: str, instance: str) -> None:
    """Rewrite sibling field refs in `expr` (those naming the owning header
    type `type_name`) to name the extraction instance `instance`.
    Cross-header refs (a var-width length reading another header's fields,
    e.g. GRE flag bits sizing the GREOpt region) already carry the right
    instance name and must not be touched."""
    kind = expr.WhichOneof("kind")
    if kind == "field":
        if expr.field.header == type_name:
            expr.field.header = instance
    elif kind == "bin":
        _rebind_expr_header(expr.bin.lhs, type_name, instance)
        _rebind_expr_header(expr.bin.rhs, type_name, instance)


def sel_keys(sel: SelectSpec) -> list[ir_pb2.Expr]:
    return [k.as_expr().to_pb() for k in sel.keys]


def _fill_target(pb_target: ir_pb2.Target, target: Target) -> None:
    if isinstance(target, str):
        pb_target.state = target
    elif isinstance(target, Accept):
        pb_target.accept.SetInParent()
    elif isinstance(target, Reject):
        pb_target.reject.reason = target.reason
        if target.info:
            pb_target.reject.annotations["severity"] = "info"
    else:  # unresolved StateRef; _check rejects these first
        raise TypeError(f"unresolved state reference {target!r}")



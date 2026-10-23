"""Virtual callers for the exception path (bncpp-66): a function reached only through a vtable slot has no direct
callers, so cpp/eh_path.py ended its walk there (the frontier). Its virtual call sites are the indirect calls that
load its slot through an X::VTable member (cpp/rtti_types.py: the class structs and 'X* this'), for every X whose
vtable can hold the function there:
  - each primary vtable with the function at slot k: the class's X::VTable member k and that of every class on its
    primary-base chain that has slot k (a call through Base::VTable may dispatch to the override);
  - each secondary vtable (the class's vtable for a base B at +off): B's member k and B's primary bases'.
Calls through a sibling's or an unrelated class's VTable cannot reach it and are not listed. BN's type field
references find the slot loads (bv.get_code_refs_for_type_field), so only receivers BN knows as 'X*' count -- the
calls through 'this' and typed fields (bn_class_types.py / bn_class_fields.py): one-sided, never a false path.
Lambdas in std::function (cpp/rtti_closures.py) are classes too: their invoke slot is reached through the family
base's VTable (an anchored base, bncpp-31) once a receiver has that type.
"""
from . import rtti_fields
from .rtti_names import _primary_base


def slot_members(types, labels):
    """{function: {(X::VTable name, byte offset)}}: the VTable members a virtual call to the function goes through"""
    out = {}

    def chain(cls, k, fn):
        seen = set()
        while cls is not None and cls in types and cls not in seen:
            seen.add(cls)
            prim = [v for v in types[cls].vtables if v.offset_to_top == 0 and v.construction_for is None]
            if prim and k >= len(prim[0].slots):
                break
            # also a base without a vtable of its own: an anchored one has its X::VTable (bncpp-31); a member that
            # does not exist has no references
            out.setdefault(fn, set()).add((labels[cls] + "::VTable", k * 8))
            cls = _primary_base(types[cls])

    for a, t in types.items():
        for vt in t.vtables:
            if vt.construction_for is not None:
                continue
            if vt.offset_to_top == 0:
                start = a
            else:  # the vtable for the base subobject at -offset_to_top
                start = next((b for b, off in rtti_fields.base_offsets(t, types) if off == -vt.offset_to_top), None)
            for k, s in enumerate(vt.slots):
                if isinstance(s, int) and start is not None:
                    chain(start, k, s)
    return out


class VirtualCallers:
    """vcallers(fn) -> [(call address, caller function start, tail?)] from BN's type field references"""

    def __init__(self, bv, types, labels):
        self.bv = bv
        self.members = slot_members(types, labels)
        self.memo = {}

    def calls_at(self, func, addr):
        """the indirect calls a slot load at addr belongs to: the call itself, or the calls of the loaded variable"""
        from binaryninja import MediumLevelILOperation as Op
        calls = (Op.MLIL_CALL_SSA, Op.MLIL_TAILCALL_SSA)
        m = func.mlil
        if m is None:
            return []
        ssa, out = m.ssa_form, []
        i = m.get_instruction_start(addr)
        while i is not None and i < len(m) and m[i].address == addr:
            s = m[i].ssa_form
            if s.operation in calls:
                out.append(s)
            elif s.operation == Op.MLIL_SET_VAR_SSA:
                out += [u for u in ssa.get_ssa_var_uses(s.dest) if u.operation in calls and
                        u.dest.operation == Op.MLIL_VAR_SSA and u.dest.src == s.dest]
            i += 1
        return [(c.address, func.start, c.operation == Op.MLIL_TAILCALL_SSA) for c in out
                if c.dest.operation not in (Op.MLIL_CONST_PTR, Op.MLIL_IMPORT)]

    def member_calls(self, key):
        if key not in self.memo:
            from binaryninja import QualifiedName
            out = []
            try:
                refs = list(self.bv.get_code_refs_for_type_field(QualifiedName([key[0]]), key[1]))
            except Exception:
                refs = []
            for r in refs:
                if r.func is not None:
                    out += [c for c in self.calls_at(r.func, r.address) if c not in out]
            self.memo[key] = out
        return self.memo[key]

    def __call__(self, fn):
        out = []
        for key in sorted(self.members.get(fn, ())):
            out += [c for c in self.member_calls(key) if c not in out]
        return out

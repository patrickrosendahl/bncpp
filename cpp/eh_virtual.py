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
The result of a dynamic_cast<T*> is a T* whatever BN typed it (bncpp-95): ___dynamic_cast(p, src typeinfo, T's
typeinfo, hint) -- a call (*(*r + k))(r, ...) on that result goes through T::VTable member k, so it counts like a
typed receiver (cast_calls, from the IL of ___dynamic_cast's callers; cached).
"""
from . import rtti_fields
from .rtti_names import _primary_base

DYNAMIC_CAST = ("___dynamic_cast", "__dynamic_cast")
_CASTS_VERSION = 5


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


def _root(e, Op):
    """the SSA variable an expression copies (through plain copies), else None"""
    while e.operation == Op.MLIL_VAR_SSA:
        d = e.function.get_ssa_var_definition(e.src)
        if d is None or d.operation != Op.MLIL_SET_VAR_SSA or d.src.operation != Op.MLIL_VAR_SSA:
            return e.src
        e = d.src
    return None


def _load(e, Op):
    """[a + k] (a through copies) -> (a, k), else None"""
    while e.operation == Op.MLIL_VAR_SSA:
        d = e.function.get_ssa_var_definition(e.src)
        if d is None or d.operation != Op.MLIL_SET_VAR_SSA:
            break
        e = d.src
    if e.operation != Op.MLIL_LOAD_SSA:
        return None
    a = e.src
    while a.operation == Op.MLIL_VAR_SSA:
        d = a.function.get_ssa_var_definition(a.src)
        if d is None or d.operation != Op.MLIL_SET_VAR_SSA or d.src.operation not in (Op.MLIL_VAR_SSA, Op.MLIL_ADD):
            break
        a = d.src
    if a.operation == Op.MLIL_ADD and a.right.operation == Op.MLIL_CONST:
        return a.left, a.right.constant
    return a, 0


def cast_callers(bv):
    """{caller start: (function, {addresses of its ___dynamic_cast calls})}"""
    targets = set(s.address for n in DYNAMIC_CAST for s in bv.get_symbols_by_name(n))
    funcs = {}
    for t in targets:
        for r in bv.get_code_refs(t):
            if r.function is not None:
                funcs.setdefault(r.function.start, (r.function, set()))[1].add(r.address)
    return funcs


def cast_calls(bv, types, funcs=None):
    """[(T typeinfo, byte offset, call address, caller start, tail?)]: the virtual calls on dynamic_cast<T*> results,
    T a class of the scan; the result followed along its SSA uses through copies and phis whose inputs are such
    results of the same T or a null pointer (O0: 'p = t ? cast(t, ...) : nullptr'). funcs: a part of cast_callers'
    result (default: all; ~350 ms per caller whose IL BN has not built yet)"""
    from binaryninja import MediumLevelILOperation as Op
    calls = (Op.MLIL_CALL_SSA, Op.MLIL_TAILCALL_SSA)
    out = []
    for f, addrs in (cast_callers(bv) if funcs is None else funcs).values():
        m = f.mlil
        if m is None:
            continue
        ssa = m.ssa_form
        cls, work = {}, []  # SSA var -> T
        for a in sorted(addrs):
            i = m.get_instruction_start(a)
            ins = m[i].ssa_form if i is not None and i < len(m) else None
            if ins is not None and ins.operation == Op.MLIL_CALL_SSA and len(ins.params) >= 3 \
                    and len(ins.output) == 1 and ins.params[2].operation in (Op.MLIL_CONST_PTR, Op.MLIL_CONST) \
                    and ins.params[2].constant in types:
                cls[ins.output[0]] = ins.params[2].constant
                work.append(ins.output[0])

        def null(v):
            d = ssa.get_ssa_var_definition(v)
            return d is not None and d.operation == Op.MLIL_SET_VAR_SSA and \
                d.src.operation in (Op.MLIL_CONST, Op.MLIL_CONST_PTR) and d.src.constant == 0

        sites, phis = {}, {}
        while work:
            v = work.pop()
            for u in ssa.get_ssa_var_uses(v):
                if u.operation == Op.MLIL_SET_VAR_SSA and u.src.operation == Op.MLIL_VAR_SSA:
                    new = [u.dest]
                elif u.operation == Op.MLIL_VAR_PHI:
                    phis[u.dest] = u
                    new = [d for d, p in phis.items() if d not in cls and
                           len(set(cls.get(x) for x in p.src if not null(x))) == 1 and
                           all(x in cls or null(x) for x in p.src)]
                else:
                    if u.operation in calls:
                        sites[u.address] = u
                    new = []
                for d in new:
                    if d not in cls:
                        cls[d] = next(cls[x] for x in (phis[d].src if d in phis else [v]) if x in cls)
                        work.append(d)
        for ins in sites.values():
            if not ins.params or ins.params[0].operation != Op.MLIL_VAR_SSA:
                continue
            slot = _load(ins.dest, Op)
            vptr = _load(slot[0], Op) if slot is not None else None
            if vptr is None or vptr[1] != 0:
                continue
            r = _root(vptr[0], Op) if vptr[0].operation == Op.MLIL_VAR_SSA else None
            if r is not None and r in cls and _root(ins.params[0], Op) == r:
                out.append((cls[r], slot[1], ins.address, f.start, ins.operation == Op.MLIL_TAILCALL_SSA))
    return out


class VirtualCallers:
    """vcallers(fn) -> [(call address, caller function start, tail?)] from BN's type field references"""

    def __init__(self, bv, types, labels, cache=None, budget=None):
        """cache: a shared.bncache.Cache for the dynamic_cast calls, per caller (None: computed each time); budget:
        seconds for the callers not in the cache yet (None: all of them; the rest waits for the next run)"""
        self.bv, self.types, self.labels, self.cache, self.budget = bv, types, labels, cache, budget
        self.members = slot_members(types, labels)
        self.memo = {}
        self._casts = None
        self.cast_progress = None  # (callers done, callers)

    def casts(self):
        """{(T::VTable name, byte offset): [(call address, caller start, tail?)]} of the dynamic_cast results"""
        if self._casts is None:
            import time
            got = self.cache.get("dyncasts", _CASTS_VERSION) if self.cache is not None else None
            done = {int(k, 0): [tuple(x) for x in v] for k, v in got["funcs"].items()} if got is not None else {}
            todo = {a: v for a, v in cast_callers(self.bv).items() if a not in done}
            t0 = time.time()
            for a in sorted(todo):
                if self.budget is not None and time.time() - t0 > self.budget:
                    break
                done[a] = cast_calls(self.bv, self.types, {a: todo[a]})
            if self.cache is not None and len(done) > (len(got["funcs"]) if got is not None else -1):
                self.cache.put("dyncasts", _CASTS_VERSION, {"funcs": {"%#x" % k: v for k, v in sorted(done.items())}})
            self.cast_progress = (len(done), len(done) + sum(1 for a in todo if a not in done))
            self._casts = {}
            for rows in done.values():
                for t, off, call, func, tail in rows:
                    if t in self.labels:
                        self._casts.setdefault((self.labels[t] + "::VTable", off), []).append((call, func, bool(tail)))
        return self._casts

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
            out += [c for c in self.casts().get(key, ()) if c not in out]
            self.memo[key] = out
        return self.memo[key]

    def __call__(self, fn):
        out = []
        for key in sorted(self.members.get(fn, ())):
            out += [c for c in self.member_calls(key) if c not in out]
        return out

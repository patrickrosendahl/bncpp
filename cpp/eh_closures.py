"""Closure callers for the exception path (bncpp-109): a lambda in a std::function is a class of its own
(cpp/rtti_closures.py), its operator() sits in slot 6 of std::function's __base<Sig> and is called through the
std::function's __f_ pointer -- (*(*f + 0x30))(f, args), inlined from __value_func::operator() or in an out-of-line
instance. No receiver there is typed, so cpp/eh_virtual.py's type field references don't reach it, and matching
the slot offset alone would make every std::function call a caller of every closure of every signature.

Instead the closure is followed from where it is made to where it is called (one-sided, as the virtual hops: a
call site is listed only where the std::function may hold this very closure):
  - object: where the closure lives -- the vptr store of its class (a constructor that stores into its 'this'
    goes up to its callers' arguments: the -O0 shape of __func / __value_func constructors); passing the object
    to a direct callee makes it the callee's parameter (an out-of-line invoke helper);
  - holder: a std::function holding it -- where the object's address is stored into __f_ (holder + 0x20 / 0x18); a
    holder passed by address to a direct callee is that callee's parameter; __f_ stored into another place makes
    that place a holder (std::function's move: a task object, a member); a holder in a typed field X.f makes
    every read of X.f + 0x20 that BN lists as a type field reference a holder too (an object invoked later, e.g.
    a queue's worker);
  - call site: (*(*f + 0x30))(f, ...) where f is the holder's __f_ (or the object's address).
Values are abstract and set-valued, from MLIL SSA: the address of a place (a stack slot, a parameter + offset, a
call's result + offset), the 8 bytes loaded from one, a constant; a phi is the union of its inputs ('may hold':
the inline and the heap branch of a move merge). libc++ layout: __value_func = __buf_ (3 pointers, aligned to
max_align_t), then __f_: +0x20 on x86_64 (16-byte alignment), +0x18 on arm64 (Darwin: 8).
"""
import re

_MAX_UP = 6      # constructor levels followed up to the callers' arguments
_MAX_DOWN = 8    # calls followed down from where the std::function lives
_MAX_VIAS = 4    # chains kept per place
_STD_FUNCTION = re.compile(r"std::(__1::)?(function<|__function::)")
_NONE = frozenset()


def func_ptr_offset(arch):
    """libc++ __value_func::__f_ for a BN architecture name"""
    return 0x18 if arch.startswith(("aarch64", "arm64")) else 0x20


class _Fn:
    """one function's MLIL SSA, read once"""

    def __init__(self, bv, f):
        from binaryninja import MediumLevelILOperation as Op
        self.Op, self.bv, self.f = Op, bv, f
        self.memo = {}
        self.calls, self.stores, self.invokes = [], [], []  # (ins, target, tail) / (ins, src, dest value, field)
        self.at = {}  # address -> SSA instructions
        m = f.mlil
        self.ssa = m.ssa_form if m is not None else None
        if self.ssa is None:
            return
        self.params = list(f.parameter_vars)
        try:  # a register BN does not list as a parameter (entry_rsi: a struct passed by value) -> its index
            self.arg_regs = list(f.calling_convention.int_arg_regs)
        except Exception:
            self.arg_regs = []
        for ins in self.ssa.instructions:
            self.at.setdefault(ins.address, []).append(ins)
            op = ins.operation
            if op in (Op.MLIL_CALL_SSA, Op.MLIL_TAILCALL_SSA, Op.MLIL_JUMP):
                tail = op != Op.MLIL_CALL_SSA
                if op != Op.MLIL_JUMP and self.const(ins.dest) is not None:
                    self.calls.append((ins, self.const(ins.dest), tail))
                else:
                    recv = self.vtable_call(ins.dest)
                    if recv is not None:
                        self.invokes.append((ins, recv, tail))
            elif op in (Op.MLIL_STORE_SSA, Op.MLIL_STORE_STRUCT_SSA):
                k = ins.offset if op == Op.MLIL_STORE_STRUCT_SSA else 0
                for d in self.value(ins.dest):
                    if d[0] == "addr":
                        d = ("addr", d[1], d[2] + k)
                        self.stores.append((ins, ins.src, d, self.struct_field(ins.dest, d)))
            elif op in (Op.MLIL_SET_VAR_SSA, Op.MLIL_SET_VAR_ALIASED) and self.stack(ins.dest.var):
                self.stores.append((ins, ins.src, ("addr", ("stack",), ins.dest.var.storage), None))

    def stack(self, v):
        return v.source_type.name == "StackVariableSourceType"

    def const(self, e):
        return e.constant if e.operation in (self.Op.MLIL_CONST, self.Op.MLIL_CONST_PTR) else None

    def follow(self, e):
        """through SSA copies"""
        Op = self.Op
        for _ in range(32):
            if e.operation != Op.MLIL_VAR_SSA:
                return e
            d = self.ssa.get_ssa_var_definition(e.src)
            if d is None or d.operation != Op.MLIL_SET_VAR_SSA:
                return e
            e = d.src
        return e

    def value(self, e):
        """the set of abstract values: ('addr', base, off), ('load', base, off), ('const', c); base ('stack',),
        ('param', k) or ('call', address) -- a call's result, e.g. operator new"""
        Op = self.Op
        op = e.operation
        c = self.const(e)
        if c is not None:
            return frozenset([("const", c)])
        if op == Op.MLIL_ADDRESS_OF and self.stack(e.src):
            return frozenset([("addr", ("stack",), e.src.storage)])
        if op == Op.MLIL_ADDRESS_OF_FIELD and self.stack(e.src):
            return frozenset([("addr", ("stack",), e.src.storage + e.offset)])
        if op == Op.MLIL_VAR_SSA:
            return self.var_value(e.src)
        if op == Op.MLIL_VAR_ALIASED:  # an address-taken variable: only what is in its slot
            return frozenset([("load", ("stack",), e.src.var.storage)]) if self.stack(e.src.var) else _NONE
        if op == Op.MLIL_ADD and self.const(e.right) is not None:
            k = self.const(e.right)
            return frozenset(("addr", v[1], v[2] + k) for v in self.value(e.left) if v[0] == "addr")
        if op in (Op.MLIL_LOAD_SSA, Op.MLIL_LOAD_STRUCT_SSA):
            k = e.offset if op == Op.MLIL_LOAD_STRUCT_SSA else 0
            return frozenset(("load", v[1], v[2] + k) for v in self.value(e.src) if v[0] == "addr")
        return _NONE

    def var_value(self, sv):
        if sv in self.memo:
            return self.memo[sv]
        Op = self.Op
        self.memo[sv] = _NONE  # a phi cycle
        v, out = sv.var, set()
        if self.stack(v):
            out.add(("load", ("stack",), v.storage))
        d = self.ssa.get_ssa_var_definition(sv)
        if d is None:
            if v in self.params:
                out.add(("addr", ("param", self.params.index(v)), 0))
            elif v.source_type.name == "RegisterVariableSourceType":
                r = self.f.arch.get_reg_name(v.storage)
                if r in self.arg_regs:
                    out.add(("addr", ("param", self.arg_regs.index(r)), 0))
        elif d.operation == Op.MLIL_SET_VAR_SSA:
            out |= self.value(d.src)
        elif d.operation == Op.MLIL_VAR_PHI:
            for s in d.src:
                out |= self.var_value(s)
        elif d.operation in (Op.MLIL_CALL_SSA, Op.MLIL_CALL_UNTYPED_SSA):
            out.add(("addr", ("call", d.address), 0))
        self.memo[sv] = frozenset(out)
        return self.memo[sv]

    def arg(self, p, ptype=None):
        """a call argument's values; a struct passed by value (a demangled std::function parameter: ptype, the
        callee's parameter type) is passed by address (Itanium: not trivially copyable)"""
        vs = self.value(p)
        if ptype is not None and ptype.type_class.name in ("StructureTypeClass", "NamedTypeReferenceClass"):
            vs = vs | frozenset(("addr", v[1], v[2]) for v in vs if v[0] == "load" and v[1] == ("stack",))
        return vs

    def vtable_call(self, dest):
        """dest = [[f] + k] -> (k, values of f), else None"""
        Op = self.Op
        d = self.follow(dest)
        if d.operation == Op.MLIL_LOAD_SSA:
            a, k = self.follow(d.src), 0
            if a.operation == Op.MLIL_ADD and self.const(a.right) is not None:
                a, k = self.follow(a.left), self.const(a.right)
        elif d.operation == Op.MLIL_LOAD_STRUCT_SSA:
            a, k = self.follow(d.src), d.offset
        else:
            return None
        if a.operation not in (Op.MLIL_LOAD_SSA, Op.MLIL_LOAD_STRUCT_SSA) or \
                (a.operation == Op.MLIL_LOAD_STRUCT_SSA and a.offset != 0):
            return None
        f = self.value(a.src)
        return (k, f) if f else None

    def struct_field(self, dest, d):
        """(X, offset in X) of a store to d whose address dest has a base variable typed X* (through copies)"""
        Op = self.Op
        e = self.follow(dest)
        while e.operation == Op.MLIL_ADD and self.const(e.right) is not None:
            e = self.follow(e.left)
        if e.operation != Op.MLIL_VAR_SSA:
            return None
        t = e.src.var.type
        if t is None or t.type_class.name != "PointerTypeClass" or t.target.type_class.name != "NamedTypeReferenceClass":
            return None
        for b in self.value(e):
            if b[0] == "addr" and b[1] == d[1]:
                return str(t.target.name), d[2] - b[2]
        return None


class ClosureCallers:
    """callers(invoke function) -> [(call address, caller start, tail?, via)]: where std::functions holding a
    closure whose operator() is that function call it. via: the direct call sites back up to the function where
    that std::function lives, innermost first ((call address, caller start, tail?), ...) -- an out-of-line
    std::function<Sig>::operator() is shared by every function of that signature, so the exception goes on only
    through the calls that passed this one down (cpp/eh_path.py), not to all of the helper's callers"""

    def __init__(self, bv, types):
        self.bv = bv
        self.by_invoke = {}
        for a, t in types.items():
            c = t.closure
            if c is not None and c.layout == "std::function" and isinstance(c.invoke, int) and t.vtables:
                self.by_invoke.setdefault(c.invoke, []).append((t, c.invoke_index * 8))
        self.fns, self.memo, self.visited = {}, {}, set()
        self.fp = func_ptr_offset(bv.arch.name)

    def fn(self, start):
        if start not in self.fns:
            f = self.bv.get_function_at(start)
            g = _Fn(self.bv, f) if f is not None else None
            self.fns[start] = g if g is not None and g.ssa is not None else None
        return self.fns[start]

    def param_types(self, start):
        f = self.bv.get_function_at(start)
        try:
            return [p.type for p in f.type.parameters] if f is not None else []
        except Exception:
            return []

    def callers_of(self, start):
        """[(caller _Fn, call instruction)] of the direct calls to start"""
        out = []
        for caller in sorted(set(r.function.start for r in self.bv.get_code_refs(start) if r.function is not None)):
            g = self.fn(caller)
            out += [(g, ins) for ins, target, _t in (g.calls if g is not None else ()) if target == start]
        return out

    def field_reads(self, struct, off):
        """[(_Fn, holder value)] for the reads of struct.off that BN lists as type field references -- a member of a
        class, not std::function's own __f_ (its helpers' typed 'this': every std::function of the signature)"""
        from binaryninja import QualifiedName
        out = []
        if _STD_FUNCTION.match(struct):
            return out
        try:
            refs = list(self.bv.get_code_refs_for_type_field(QualifiedName([struct]), off))
        except Exception:
            return out
        for r in refs:
            g = self.fn(r.func.start) if r.func is not None else None
            for ins in (g.at.get(r.address, ()) if g is not None else ()):
                if ins.operation == g.Op.MLIL_SET_VAR_SSA:
                    out += [(g, (v[1], v[2] - self.fp)) for v in g.value(ins.src) if v[0] == "load"]
        return out

    def lift(self, k, off, via):
        """parameter k + off of the function called at via[0], in the callers up the chain: [(caller start, base,
        offset, (X, offset in X) or None, the rest of via)]"""
        site, caller, _tail = via[0]
        c = self.fn(caller)
        out = []
        for ins, target, _t in (c.calls if c is not None else ()):
            if ins.address != site or k >= len(ins.params):
                continue
            types = self.param_types(target)
            for a in c.arg(ins.params[k], types[k] if k < len(types) else None):
                if a[0] != "addr":
                    continue
                d = ("addr", a[1], a[2] + off)
                out.append((caller, a[1], a[2] + off, c.struct_field(ins.params[k], d), via[1:]))
                if a[1][0] == "param" and len(via) > 1:
                    out += self.lift(a[1][1], a[2] + off, via[1:])
        return out

    def __call__(self, fn):
        if fn not in self.memo:
            out = []
            for t, inv in self.by_invoke.get(fn, ()):
                out += [c for c in self.trace(t, inv) if c not in out]
            self.memo[fn] = out
        return self.memo[fn]

    def trace(self, t, inv):
        """the call sites of closure class t's operator() (slot offset inv) through std::functions holding it"""
        vt = t.vtables[0]
        own = set(s for v in t.vtables for s in v.slots if isinstance(s, int))
        work, seen, sites, vias = [], set(), [], {}
        for start in sorted(set(r.function.start for r in self.bv.get_code_refs(vt.addr) if r.function is not None)):
            g = self.fn(start) if start not in own else None
            for _ins, src, d, _f in (g.stores if g is not None else ()):
                if ("const", vt.addr) in g.value(src):  # the vptr store (x86: not at the lea's address)
                    work.append(("object", start, d[1], d[2], _MAX_UP, ()))
        while work:
            item = work.pop()
            if item in seen:
                continue
            if item[0] != "field":  # a place reached through many chains (-O0 libc++ helpers): the first few
                n = vias.get(item[:5], 0)
                if n >= _MAX_VIAS:
                    continue
                vias[item[:5]] = n + 1
            seen.add(item)
            if item[0] == "field":
                for g, place in self.field_reads(item[1], item[2] + self.fp):
                    work.append(("holder", g.f.start, place[0], place[1], 0, ()))
                continue
            kind, start, base, off, up, via = item
            g = self.fn(start)
            if g is None:
                continue
            # the closure's address / the holder's __f_
            ptr = ("addr", base, off) if kind == "object" else ("load", base, off + self.fp)
            for ins, (k, recv), tail in g.invokes:
                if k == inv and ptr in recv:
                    sites.append((ins.address, start, tail, via))
            for _ins, src, d, field in g.stores:
                if ptr in g.value(src):
                    # stored into __f_: the place fp below holds a std::function with the closure
                    work.append(("holder", start, d[1], d[2] - self.fp, up if d[1][0] == "param" else 0, via))
                    if field is not None:
                        work.append(("field", field[0], field[1] - self.fp))
                    if d[1][0] == "param" and via:  # moved into what a caller passed (-O0: function::operator=)
                        for caller, cbase, coff, cfield, rest in self.lift(d[1][1], d[2], via):
                            work.append(("holder", caller, cbase, coff - self.fp, 0, rest))
                            if cfield is not None:
                                work.append(("field", cfield[0], cfield[1] - self.fp))
            for ins, target, tail in g.calls:
                if len(via) >= _MAX_DOWN:
                    break
                types = self.param_types(target)
                down = ((ins.address, start, tail),) + via
                for k, p in enumerate(ins.params):
                    vs = g.arg(p, types[k] if k < len(types) else None)
                    if ptr in vs:  # the closure itself, e.g. to an out-of-line __value_func::operator() helper
                        work.append(("object", target, ("param", k), 0, 0, down))
                    if kind == "holder" and ("addr", base, off) in vs:  # the std::function by address
                        work.append(("holder", target, ("param", k), 0, 0, down))
            if base[0] == "param" and up > 0 and not via:
                # made inside a constructor: the place is the callers' argument
                types = self.param_types(start)
                for c, ins in self.callers_of(start):
                    if base[1] < len(ins.params):
                        for a in c.arg(ins.params[base[1]], types[base[1]] if base[1] < len(types) else None):
                            if a[0] == "addr":
                                work.append((kind, c.f.start, a[1], a[2] + off, up - 1, ()))
        self.visited = seen  # for a look at the walk
        out = []
        for s in sites:
            if s not in out:
                out.append(s)
        return out

# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py and the class names / types
# (tests/bn_class_apply.py, tests/bn_class_types.py):
#   bnrun --bndb DB --timeout 1800 tests/bn_class_fields.py                     # dry run: plan + review file
#   bnrun --bndb DB --timeout 1800 --env APPLY=1 tests/bn_class_fields.py       # apply (in RAM), then save PATH
#   (APPLY refuses while classes have no type from bn_class_types.py; tests/bn_class_pipeline.py runs all three)
#   options: --env BASELINE=F (as bn_class_types.py), --env NAMES=F (field names: lines 'label offset name [type]'),
#            (a type BN cannot parse keeps the name untyped, a bad offset skips the line: review 'note:' lines),
#            --env LIMIT=N (timing: only the first N functions in step 1 and N classes in step 3; dry run only),
#            --env NOCACHE=1 (step 1 always anew, no cache file: the suite, tests/bn_dump.py),
#            --env ROUNDS=N (APPLY: at most N passes of steps 3+4 until the structs stop changing; default 4;
#            stopped at N: the line 'not settled after N rounds: X(0x..) ...'),
#            --env TRACE=L1,L2 (print these structs' shape every round: a struct that does not settle, bncpp-58)
# Step 1 (building the MLIL of ~7,000 functions: ~4-9 min on SynthV) is cached per binary (shared/bncache.py: next to
# the database, <x>.bndb.bncpp-cache.json), section "ctors" with _CTORS_VERSION (bump it when step 1 changes).
# bncpp-22: constructors / destructors get 'X* this', then the class structs get their size, base subobjects and
# fields (cpp/rtti_fields.py). A dry run plans with the accesses BN sees now (constructors still untyped, so
# fewer fields); APPLY types the constructors first, re-analyses, then reads the accesses. Never over a user type,
# a user-named member or a struct that is not ours (anything but vptr / field_* / NAMES members).
# bncpp-34: fields that hold an object pointer get 'Y*' from what is stored into them (step 2b, cached as section
# "ptrstores" with _PTRS_VERSION; the stores are resolved against the current types on each pass, to a fixpoint).
# Stores through a variable that only gets a typed source after an APPLY are not in the cache: NOCACHE=1 rescans.
# bncpp-28: a parameter the stores come from ('this->field_40 = arg2') gets its class from the arguments at its
# direct call sites (step 2c, cached as section "paramargs"; not for functions also in a vtable); APPLY types it too
# (never over a user type), the review has 'param' lines.
# bncpp-28: a function whose result the stores or call-site arguments use ('this->eng = make_engine()') gets its
# return class from its own return statements (step 2d, cached as section "retdescs"; same rules); APPLY types it
# 'X* f(...)', the review has 'ret' lines.
# Review: .scratch/classes/<binary>.fields.review ('pointer' lines: outcome, class, evidence per class stored)
import importlib, json, os, re, time
import binaryninja as _bn
from binaryninja import (BaseStructure, FunctionParameter, MediumLevelILOperation as Op, NamedTypeReferenceClass,
                         QualifiedName, StructureBuilder, Type, TypeClass)

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_names = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_names")
_fields = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_fields")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_bncache = importlib.import_module(_dev["pkgname"] + ".shared.bncache")
_env = globals().get("env") or {}
_apply = (_env.get("APPLY") or os.environ.get("APPLY")) == "1"
_limit = int(_env.get("LIMIT") or 0) or None
if _apply and _limit:
    raise RuntimeError("LIMIT is for timing dry runs only")
_t0 = time.time()
_baseline = None
if _env.get("BASELINE"):
    with open(_env["BASELINE"], encoding="utf-8") as _fh:
        _baseline = json.load(_fh)
_overrides, _override_lines, _names_notes = {}, {}, []
if _env.get("NAMES"):
    with open(_env["NAMES"], encoding="utf-8") as _fh:
        for _lno, _line in enumerate(_fh, 1):
            _p = _line.split("#")[0].split(None, 3)
            if len(_p) < 3:
                continue
            try:
                _k = (_p[0], int(_p[1], 0))
            except ValueError:
                _names_notes.append("note: names line %d: offset %r not a number, skipped: %s" % (
                    _lno, _p[1], _line.strip()))
                continue
            _overrides[_k] = (_p[2], _p[3].strip() if len(_p) > 3 else None)
            _override_lines[_k] = (_lno, _line.strip())
_CTORS_VERSION = 4
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_OPERATOR_NEW = ("__Znwm", "__Znam", "__ZnwmRKSt9nothrow_t", "__ZnamRKSt9nothrow_t")
_counts, _review = {}, []


def _count(key, n=1):
    _counts[key] = _counts.get(key, 0) + n


_last = [time.time()]


def _lap(step):
    now = time.time()
    _counts["s " + step] = int(now - _last[0])
    _last[0] = now


_OURS = re.compile(r"struct [^,()]*::VTable\*\*")  # BN infers X::VTable** from the vptr store once X::VTable exists


_typed_here = set()  # functions this run typed: unprotected before, so still ours
_OUR_PARAM = re.compile(r"struct ([^,()*]+)\* \w+")


def _protected(f):
    """a type someone set; with BASELINE, one that differs from BN's fresh inference -- after mapping back what
    BN inferred from our own types (X::VTable** -> void***) and with our own parameters ('X* this' from step 2, a
    parameter typed from its callers) matching anything"""
    if not f.has_user_type or f.start in _typed_here:
        return False
    base = _baseline.get("%#x" % f.start) if _baseline is not None else None
    if _baseline is None or base is None:
        return True
    cur = _OURS.sub("void***", str(f.type))
    if cur == base:
        return False
    pat = re.escape(_OUR_PARAM.sub(lambda m: "\0" if m.group(1) in _label_set else m.group(0), cur))
    return re.fullmatch(pat.replace("\0", r"[^,()]+"), base) is None


def _ref(name):
    return Type.named_type_reference(NamedTypeReferenceClass.StructNamedTypeClass, QualifiedName([name]))


_img = _bnimage.BNImage(bv)
_types = _rtti.scan(_img)
_labels = _names.labels(_types, _img.demangle, _names.label_overrides(_types, _img.symbol_at))
_label_set = set(_labels.values())
_points = {vt.addr: (a, vt.offset_to_top) for a, t in _types.items() for vt in t.vtables if vt.construction_for is None}
_new_addrs = set(s.address for n in _OPERATOR_NEW for s in bv.get_symbols_by_name(n))
_no_vptr = set(a for a, slots in _fields.anchored_bases(_types).items() if slots is None)  # bncpp-31: a field at 0
# bncpp-55: the class structs come from bn_class_types.py; without them APPLY would type nothing but still give
# other structs bases on types that do not exist -- refuse before changing anything
_untyped = sorted(_labels[a] for a in set(a for a, t in _types.items() if any(vt.primary for vt in t.vtables))
                  | set(_fields.anchored_bases(_types)) if bv.get_type_by_name(QualifiedName([_labels[a]])) is None)
if _untyped:
    _count("classes: no type yet (run bn_class_types.py)", len(_untyped))
    if _apply:
        raise RuntimeError("APPLY refused: %d classes have no type yet (%s%s); run tests/bn_class_types.py first "
                           "(or tests/bn_class_pipeline.py)" % (len(_untyped), ", ".join(_untyped[:5]),
                                                                ", ..." if len(_untyped) > 5 else ""))
_lap("0 scan")


# Step 1 starts at the code refs (BN puts one on the MLIL store / call itself) and follows the vars through their
# definitions / uses: reading every instruction of the referencing functions from Python costs ~50 us each (minutes
# on SynthV's big functions).
def _mlil_at(m, addr):
    """the MLIL instructions at an address"""
    out, i = [], m.get_instruction_start(addr)
    while i is not None and i < len(m) and m[i].address == addr:
        out.append(m[i])
        i += 1
    return out


def _is_this(m, p0, var, seen):
    """var is the first parameter or a copy of it"""
    if var == p0:
        return True
    if var in seen:
        return False
    seen.add(var)
    return any(d.operation == Op.MLIL_SET_VAR and d.src.operation == Op.MLIL_VAR and _is_this(m, p0, d.src.src, seen)
               for d in m.get_var_definitions(var))


def _store_site(mi):
    """(base var, offset, address point) of a vptr store '[base + off] = point', else None; once the base has a
    struct type (bn_class_types.py, or BN's own) the store is 'base->member = point' (MLIL_STORE_STRUCT)"""
    if mi.operation not in (Op.MLIL_STORE, Op.MLIL_STORE_STRUCT) \
            or mi.src.operation not in (Op.MLIL_CONST, Op.MLIL_CONST_PTR) or mi.src.constant not in _points:
        return None
    d, off = mi.dest, mi.offset if mi.operation == Op.MLIL_STORE_STRUCT else 0
    if d.operation == Op.MLIL_ADD and d.right.operation == Op.MLIL_CONST:
        off, d = off + d.right.constant, d.left
    return (d.src, off, mi.src.constant) if d.operation == Op.MLIL_VAR else None


def _new_uses(ssa, var, size, call, sites, seen):
    """the object operator new returned in SSA variable var: its vptr store at 0, or the constructor it goes to as
    'this'. SSA, so that a factory whose branches merge the results of several new calls into one variable
    ('case 1: return new A; case 2: return new B') gives each call only its own class"""
    if var in seen:
        return
    seen.add(var)
    for u in ssa.get_ssa_var_uses(var):
        o = u.operation
        if o == Op.MLIL_SET_VAR_SSA and u.src.operation == Op.MLIL_VAR_SSA and u.src.src == var:
            _new_uses(ssa, u.dest, size, call, sites, seen)
        elif o in (Op.MLIL_STORE_SSA, Op.MLIL_STORE_STRUCT_SSA):
            d = u.dest.left if u.dest.operation == Op.MLIL_ADD else u.dest
            st = _store_site(u.non_ssa_form)
            if st is not None and st[1] == 0 and d.operation == Op.MLIL_VAR_SSA and d.src == var:
                c, ott = _points[st[2]]
                if ott == 0:
                    sites.append((c, None, size, call))
        elif o == Op.MLIL_CALL_SSA and u.dest.operation == Op.MLIL_CONST_PTR \
                and u.params and u.params[0].operation == Op.MLIL_VAR_SSA and u.params[0].src == var:
            sites.append((None, u.dest.constant, size, call))


# 1. constructors / destructors (vptr stores on this) and sizes (operator new sites), per function: BN keeps the IL
# of only analysis.limits.cacheSize (256) functions, so jumping between functions rebuilds it again and again
_nocache = _env.get("NOCACHE") == "1"
_cache_file = None if _nocache else _bncache.Cache(bv)
_cache = _cache_file.get("ctors", _CTORS_VERSION) if _limit is None and not _nocache else None
if _cache is not None:
    _stores = {int(k, 0): [tuple(x) for x in v] for k, v in _cache["stores"].items()}
    _sites = [tuple(x) for x in _cache["sites"]]
    _count("step 1 from cache")
    _lap("1 cache")
else:
    _stores, _sites, _by_func = {}, [], {}
    for _a in list(_points) + list(_new_addrs):
        for _r in bv.get_code_refs(_a):
            _by_func.setdefault(_r.function.start, (_r.function, set()))[1].add(_r.address)
    _lap("1a code refs")
    for _f, _addrs in list(_by_func.values())[:_limit]:
        _m = _f.mlil  # once per function: built anew on each call once evicted
        if _m is None:
            continue
        _p0 = _f.parameter_vars[0] if len(_f.parameter_vars) else None
        for _addr in sorted(_addrs):
            for _mi in _mlil_at(_m, _addr):
                _st = _store_site(_mi)
                if _st is not None and _p0 is not None and _is_this(_m, _p0, _st[0], set()):
                    _c, _ott = _points[_st[2]]
                    _stores.setdefault(_f.start, []).append((_st[1], _c, _ott))
                elif _mi.operation == Op.MLIL_CALL and _mi.dest.operation in (Op.MLIL_CONST_PTR, Op.MLIL_IMPORT) \
                        and _mi.dest.constant in _new_addrs and _mi.output and _mi.params \
                        and _mi.params[0].operation == Op.MLIL_CONST:
                    _new_uses(_m.ssa_form, _mi.ssa_form.output[0], _mi.params[0].constant, _mi.address, _sites, set())
    _lap("1b il")
    _count("functions scanned", len(_by_func))
    if _limit is None and not _nocache:
        _cache_file.put("ctors", _CTORS_VERSION, {"sites": _sites,
                                                  "stores": {"%#x" % k: v for k, v in sorted(_stores.items())}})
_ctors = _fields.ctor_classes(_types, _stores)


def _forwards_to(a):
    """the function a tiny function a only passes its 'this' on to (C1 -> C2 constructors: 'return C2(this, ...)'),
    else None; size-checked before its IL is built"""
    f = bv.get_function_at(a)
    if f is None or f.total_bytes > 48 or not len(f.parameter_vars):
        return None
    m = f.mlil
    if m is None or len(m) > 6:  # O0 spills this first: var_10 = this; rdi = var_10; C2(rdi)
        return None
    p0 = f.parameter_vars[0]
    for ins in m.instructions:
        if ins.operation in (Op.MLIL_CALL, Op.MLIL_TAILCALL) and ins.dest.operation == Op.MLIL_CONST_PTR \
                and ins.params and ins.params[0].operation == Op.MLIL_VAR and _is_this(m, p0, ins.params[0].src, set()):
            return ins.dest.constant
    return None


# constructors that only forward to one (no vptr store of their own): reached from operator new sites
for _ctor in sorted(set(c for _cls, c, _n, _call in _sites if c is not None and c not in _ctors)):
    _to = _forwards_to(_ctor)
    if _to in _ctors:
        _ctors[_ctor] = _ctors[_to]
        _count("ctors forwarding")
_lap("1c forwarding ctors")
_sizes = _fields.class_sizes(_sites, _ctors, _types)
_virtual = set(s for t in _types.values() for vt in t.vtables for s in vt.slots if isinstance(s, int))
_count("ctors/dtors", len(_ctors))
_count("classes sized", len(_sizes))

# 2. 'X* this' on the constructors / destructors that are not virtual (those have it from bn_class_types.py)
for _fa, _c in sorted(_ctors.items()):
    _f, _label = bv.get_function_at(_fa), _labels[_c]
    if _fa in _virtual or _f is None:
        continue
    _old = _f.type
    if _old.parameters and str(_old.parameters[0].type) == "struct %s*" % _label:
        _count("ctor already typed")
        continue
    if _protected(_f):
        _count("ctor type kept (user)")
        _review.append("keep  ctor %#x %s   [now: %s]" % (_fa, _f.name, _old))
        continue
    if bv.get_type_by_name(QualifiedName([_label])) is None:
        _count("ctor skipped (no class type)")
        continue
    _count("ctor typed")
    _review.append("apply ctor %#x %s: this = %s*   [now: %s]" % (_fa, _f.name, _label, _old))
    if _apply:
        _typed_here.add(_fa)
        _f.type = Type.function(_old.return_value, [FunctionParameter(Type.pointer(bv.arch, _ref(_label)), "this")]
                                + list(_old.parameters[1:]), calling_convention=_f.calling_convention,
                                variable_arguments=_old.has_variable_arguments)
if _apply:
    bv.update_analysis_and_wait()
_lap("2 ctor types")

# 2b. stores of object pointers into class objects (bncpp-34), recorded with where the object and the value come
# from (descriptors, resolved against the current types in _plan): the stores into an object from operator new or
# one that gets a vptr stored in the function, and the stores through a typed field (BN's type field references
# of the 8-byte members, only store instructions). Cached (section "ptrstores"): the types they resolve against
# change, the stores do not.
_PTRS_VERSION = 2


def _root(ssa, v, seen):
    """the SSA variable a value was copied from (through plain copies)"""
    while v not in seen:
        seen.add(v)
        d = ssa.get_ssa_var_definition(v)
        if d is None or d.operation != Op.MLIL_SET_VAR_SSA or d.src.operation != Op.MLIL_VAR_SSA:
            return v
        v = d.src.src
    return v


def _copies(ssa, v):
    """v and the SSA variables copied from it"""
    out, k = [v], 0
    while k < len(out):
        for u in ssa.get_ssa_var_uses(out[k]):
            if u.operation == Op.MLIL_SET_VAR_SSA and u.src.operation == Op.MLIL_VAR_SSA and u.dest not in out:
                out.append(u.dest)
        k += 1
    return out


def _base_off(e):
    """(SSA var, offset) of an address 'var' / 'var + c', else None"""
    off = 0
    if e.operation == Op.MLIL_ADD and e.right.operation == Op.MLIL_CONST:
        e, off = e.left, e.right.constant
    return (e.src, off) if e.operation == Op.MLIL_VAR_SSA else None


def _stores_into(ssa, v, of=False):
    """[(store, offset)]: the stores into the object v points to (and its copies); of: the stores of v elsewhere
    ('p->field = v') too"""
    cs, out = set(_copies(ssa, v)), []
    for c in cs:
        for u in ssa.get_ssa_var_uses(c):
            if u.operation in (Op.MLIL_STORE_SSA, Op.MLIL_STORE_STRUCT_SSA):
                bo = _base_off(u.dest)
                if bo is not None and (bo[0] in cs or (of and u.src.operation == Op.MLIL_VAR_SSA and u.src.src in cs)):
                    out.append((u, bo[1] + (u.offset if u.operation == Op.MLIL_STORE_STRUCT_SSA else 0)))
    return out


def _consts(ssa, e, depth=0):
    """the constants a value can be: a constant, or a variable set to one or to a phi of them (O2 picks the vptr of
    one of two classes in branches and stores it once); else an empty set"""
    if e.operation in (Op.MLIL_CONST, Op.MLIL_CONST_PTR):
        return {e.constant}
    if e.operation != Op.MLIL_VAR_SSA or depth > 4:
        return set()
    d = ssa.get_ssa_var_definition(e.src)
    if d is not None and d.operation == Op.MLIL_SET_VAR_SSA:
        return _consts(ssa, d.src, depth + 1)
    if d is not None and d.operation == Op.MLIL_VAR_PHI:
        out = set()
        for s in d.src:
            dd = ssa.get_ssa_var_definition(s)
            c = _consts(ssa, dd.src, depth + 1) if dd is not None and dd.operation == Op.MLIL_SET_VAR_SSA else set()
            if not c:
                return set()
            out |= c
        return out
    return set()


def _desc(f, ssa, v, memo, depth=0):
    """where the object an SSA variable points to comes from, as JSON: ['vptr', class] (a primary vptr stored at 0
    in this function: exact), ['new', call], ['param', function, index], ['ret', callee], ['load', desc, offset],
    ['phi', [desc]], ['or', [desc]] (the first that resolves); None if nothing"""
    v = _root(ssa, v, set())
    if v in memo:
        return memo[v]
    memo[v] = None  # a cycle through phis
    cls = set()
    for s, off in _stores_into(ssa, v):
        if off == 0:
            for k in _consts(ssa, s.src):
                c, ott = _points.get(k, (None, None))
                if ott == 0:
                    cls.add(c)
    leaf = [c for c in cls if all(o == c or o in _fields.ancestors(_types, c) for o in cls)]
    if cls and len(leaf) != 1:  # one object of either class (branches; O2 merges the new calls): their common base
        c = _fields.pointer_class(_types, sorted(cls))
        leaf = [c] if c is not None else []
    d, out = ssa.get_ssa_var_definition(v), None
    if d is None:
        pv = list(f.parameter_vars)
        out = ["param", f.start, pv.index(v.var)] if v.version == 0 and v.var in pv else None
    elif d.operation == Op.MLIL_CALL_SSA and d.dest.operation in (Op.MLIL_CONST_PTR, Op.MLIL_IMPORT):
        out = ["new", d.address] if d.dest.constant in _new_addrs else ["ret", d.dest.constant]
    elif d.operation == Op.MLIL_SET_VAR_SSA and depth < 4 and d.src.operation in (Op.MLIL_LOAD_SSA,
                                                                                  Op.MLIL_LOAD_STRUCT_SSA):
        bo = _base_off(d.src.src)
        if bo is not None:
            b = _desc(f, ssa, bo[0], memo, depth + 1)
            off = bo[1] + (d.src.offset if d.src.operation == Op.MLIL_LOAD_STRUCT_SSA else 0)
            out = ["load", b, off] if b is not None else None
    elif d.operation == Op.MLIL_VAR_PHI and depth < 4:
        srcs = [_desc(f, ssa, s, memo, depth + 1) for s in d.src]
        out = ["phi", srcs] if srcs and all(x is not None for x in srcs) else None
    if len(leaf) == 1:
        out = ["vptr", leaf[0]] if out is None else ["or", [["vptr", leaf[0]], out]]
    memo[v] = out
    return out


def _is_store_insn(addr):
    """a prefilter before the IL is built: the instruction writes memory (x86 'mov [..], ..'; arm64 'st*')"""
    toks = bv.arch.get_instruction_text(bv.read(addr, 16), addr)
    text = "".join(t.text for t in toks[0]) if toks and toks[0] else ""
    mn, _sp, ops = text.strip().partition(" ")
    return mn.startswith("st") or (mn.startswith("mov") and "[" in ops.split(",")[0])


_pcache = _cache_file.get("ptrstores", _PTRS_VERSION) if _limit is None and not _nocache else None
if _pcache is not None:
    _ptr_stores = _pcache["stores"]
    _count("step 2b from cache")
else:
    _ptr_stores, _pfuncs = [], {}
    for _a in list(_types)[:_limit]:
        _qn = QualifiedName([_labels[_a]])
        _t = bv.get_type_by_name(_qn)
        if _t is None or not hasattr(_t, "members"):
            continue
        _offs = set(_mb.offset for _mb in _t.members if _mb.type.width == 8)
        try:  # the offsets BN saw accessed: a fresh struct has only its vptr yet
            _offs |= set(_mb.offset for _mb in bv.create_structure_from_offset_access(_qn).members
                         if _mb.type.width == 8)
        except Exception:
            pass
        for _o in sorted(_offs - {0}):
            if True:
                for _r in bv.get_code_refs_for_type_field(_labels[_a], _o):
                    if _r.func is not None and _r.address not in _pfuncs.get(_r.func.start, (0, ()))[1] \
                            and _is_store_insn(_r.address):
                        _pfuncs.setdefault(_r.func.start, (_r.func, set()))[1].add(_r.address)
    _seeds = {}  # function -> addresses of the vptr stores / new calls: objects built here
    for _a in list(_points) + list(_new_addrs):
        for _r in bv.get_code_refs(_a):
            _seeds.setdefault(_r.function.start, (_r.function, set()))[1].add(_r.address)
    _lap("2b refs")
    for _fs in list(set(_pfuncs) | set(_seeds))[:_limit]:
        _f = (_pfuncs.get(_fs) or _seeds.get(_fs))[0]
        _m = _f.mlil
        if _m is None:
            continue
        _ssa, _memo, _todo = _m.ssa_form, {}, {}
        for _addr in sorted(_pfuncs.get(_fs, (0, set()))[1]):
            for _mi in _mlil_at(_m, _addr):
                _s = _mi.ssa_form
                if _s.operation in (Op.MLIL_STORE_SSA, Op.MLIL_STORE_STRUCT_SSA):
                    _bo = _base_off(_s.dest)
                    if _bo is not None:
                        _off = _bo[1] + (_s.offset if _s.operation == Op.MLIL_STORE_STRUCT_SSA else 0)
                        _todo[_s.instr_index] = (_s, _bo[0], _off)
        for _addr in sorted(_seeds.get(_fs, (0, set()))[1]):
            for _mi in _mlil_at(_m, _addr):
                _s = _mi.ssa_form
                _obj = None
                if _s.operation == Op.MLIL_CALL_SSA and _s.output and _s.dest.operation in (
                        Op.MLIL_CONST_PTR, Op.MLIL_IMPORT) and _s.dest.constant in _new_addrs:
                    _obj = _s.output[0]
                elif _s.operation in (Op.MLIL_STORE_SSA, Op.MLIL_STORE_STRUCT_SSA):
                    _bo = _base_off(_s.dest)
                    _obj = _bo[0] if _bo is not None else None
                if _obj is not None:
                    for _st, _off in _stores_into(_ssa, _root(_ssa, _obj, set()), of=True):
                        _todo.setdefault(_st.instr_index, (_st, None, _off))
        for _st, _bv, _off in _todo.values():
            if _off == 0 or _off % 8 or _st.src.operation != Op.MLIL_VAR_SSA:
                continue
            if _bv is None:
                _bv = _base_off(_st.dest)[0]
            _dd = _desc(_f, _ssa, _bv, _memo)
            _sd = _desc(_f, _ssa, _st.src.src, _memo) if _dd is not None else None
            if _sd is not None:
                _ptr_stores.append([_st.address, _off, _dd, _sd])
    _lap("2b il")
    _count("ptr store functions scanned", len(set(_pfuncs) | set(_seeds)))
    if _limit is None and not _nocache:
        _cache_file.put("ptrstores", _PTRS_VERSION, {"stores": _ptr_stores})
_count("ptr stores", len(_ptr_stores))


# 2c. the arguments at the direct call sites of the parameters the stores come from (bncpp-28): a constructor that
# stores its parameter ('this->field_40 = arg2') gets the parameter's class from its callers. Recorded as
# descriptors too, following parameters that come from a parameter of the caller; cached (section "paramargs").
_ARGS_VERSION = 1


def _params_in(d, out):
    """the (function, index) of the 'param' descriptors in d"""
    if d is None:
        return out
    if d[0] == "param":
        out.add((d[1], d[2]))
    elif d[0] == "load":
        _params_in(d[1], out)
    elif d[0] in ("phi", "or"):
        for x in d[1]:
            _params_in(x, out)
    return out


_acache = _cache_file.get("paramargs", _ARGS_VERSION) if _limit is None and not _nocache and _pcache is not None \
    else None
if _acache is not None:
    _param_args = {tuple(int(x, 0) for x in k.split(":")): v for k, v in _acache["args"].items()}
    _count("step 2c from cache")
else:
    _param_args = {}  # (function, index) -> [descriptor at a direct call site]
    _todo = sorted(set().union(*[_params_in(sd, set()) for _a, _o, _dd, sd in _ptr_stores]) if _ptr_stores else ())
    _sites_of = {}  # caller -> {(call address, callee)}
    _done = set()
    while _todo:
        _need = {}  # callee -> indexes not scanned yet
        for _fi in _todo:
            if _fi not in _done:
                _done.add(_fi)
                _need.setdefault(_fi[0], set()).add(_fi[1])
        _todo, _by_caller = [], {}
        for _fa in _need:
            if _fa in _virtual:
                continue  # also reached through the vtable: callers with other classes are not seen
            for _r in bv.get_code_refs(_fa):
                if _r.function is not None:
                    _by_caller.setdefault(_r.function.start, (_r.function, set()))[1].add((_r.address, _fa))
        for _f, _calls in _by_caller.values():
            _m = _f.mlil
            if _m is None:
                continue
            _ssa, _memo = _m.ssa_form, {}
            for _addr, _fa in sorted(_calls):
                for _mi in _mlil_at(_m, _addr):
                    _s = _mi.ssa_form
                    if _s.operation not in (Op.MLIL_CALL_SSA, Op.MLIL_TAILCALL_SSA) \
                            or _s.dest.operation != Op.MLIL_CONST_PTR or _s.dest.constant != _fa:
                        continue
                    for _i in _need[_fa]:
                        _p = _s.params[_i] if _i < len(_s.params) else None
                        _d = _desc(_f, _ssa, _p.src, _memo) if _p is not None and _p.operation == Op.MLIL_VAR_SSA \
                            else None
                        _param_args.setdefault((_fa, _i), []).append(_d)
                        _todo += sorted(_params_in(_d, set()) - _done)
        _todo = sorted(set(_todo))
    _lap("2c callers")
    if _limit is None and not _nocache:
        _cache_file.put("paramargs", _ARGS_VERSION, {"args": {"%#x:%d" % k: v for k, v in
                                                              sorted(_param_args.items())}})
_count("params with direct callers", len(_param_args))


# 2d. the return statements of the callees whose result is used as an object (bncpp-28): ['ret', callee] in the
# stores and the call-site arguments; followed through callees returning another callee's result. Cached (section
# "retdescs", valid with the two above).
_RETS_VERSION = 1


def _rets_in(d, out):
    """the callees of the 'ret' descriptors in d"""
    if d is None:
        return out
    if d[0] == "ret":
        out.add(d[1])
    elif d[0] == "load":
        _rets_in(d[1], out)
    elif d[0] in ("phi", "or"):
        for x in d[1]:
            _rets_in(x, out)
    return out


_rcache = _cache_file.get("retdescs", _RETS_VERSION) if _limit is None and not _nocache and _acache is not None \
    else None
if _rcache is not None:
    _ret_descs = {int(k, 0): v for k, v in _rcache["rets"].items()}
    _count("step 2d from cache")
else:
    _ret_descs = {}  # callee -> [descriptor of each returned value]
    _todo = set()
    for _a, _o, _dd, _sd in _ptr_stores:
        _rets_in(_sd, _todo)
    for _args in _param_args.values():
        for _d in _args:
            _rets_in(_d, _todo)
    while _todo:
        _fa = _todo.pop()
        if _fa in _ret_descs:
            continue
        _f = bv.get_function_at(_fa)
        _m = _f.mlil if _f is not None else None
        if _m is None:
            continue
        _ssa, _memo, _out = _m.ssa_form, {}, []
        for _mi in _ssa.instructions:
            if _mi.operation == Op.MLIL_TAILCALL_SSA and _mi.dest.operation in (Op.MLIL_CONST_PTR, Op.MLIL_IMPORT):
                _d = ["ret", _mi.dest.constant]  # 'return g()' as a jump: g's result is ours
            elif _mi.operation == Op.MLIL_RET and _mi.src:
                _v = _mi.src[0]
                _d = _desc(_f, _ssa, _v.src, _memo) if _v.operation == Op.MLIL_VAR_SSA else None
            else:
                continue
            _out.append(_d)
            _todo |= _rets_in(_d, set()) - set(_ret_descs)
        _ret_descs[_fa] = _out
    _lap("2d returns")
    if _limit is None and not _nocache:
        _cache_file.put("retdescs", _RETS_VERSION, {"rets": {"%#x" % k: v for k, v in sorted(_ret_descs.items())}})
_count("returns used as objects", len(_ret_descs))
_new_class = {call: c for (call, _size), c in _fields.new_classes(_sites, _ctors, _types).items()}
_by_label = {l: a for a, l in _labels.items()}


def _class_of(t):
    """the class a type 'X*' points to, else None"""
    if t is None or t.type_class != TypeClass.PointerTypeClass:
        return None
    tg = t.target
    if tg.type_class == TypeClass.NamedTypeReferenceClass:
        return _by_label.get(str(tg.name))
    if tg.type_class == TypeClass.StructureTypeClass and tg.registered_name is not None:
        return _by_label.get(str(tg.registered_name.name))
    return None


def _member_class(lays, c, off, depth=0):
    """the class the member at (class, offset) points to in the layouts, looking into the base subobjects"""
    lay = lays.get(c)
    if lay is None or depth > 8:
        return None
    for m in lay.members:
        if m.offset == off:
            return _class_of(m.type)
    for b, boff in lay.bases:
        if b in lays and boff <= off < boff + lays[b].width:
            return _member_class(lays, b, off - boff, depth + 1)
    return None


_fclasses = {}  # function -> (return class, [parameter class]) or None; cleared per plan (APPLY changes types)


def _func_classes(fa):
    """the classes a function's return type and parameters point to now (a BN call per function, not per use)"""
    if fa not in _fclasses:
        f = bv.get_function_at(fa)
        _fclasses[fa] = None if f is None else (_class_of(f.return_type),
                                                [_class_of(p.type) for p in f.type.parameters])
    return _fclasses[fa]


def _resolve(d, lays):
    """(class, kind) a descriptor resolves to now, else None"""
    k = d[0]
    if k == "vptr":
        return d[1], "vptr"
    if k == "new":
        c = _new_class.get(d[1])
        return (c, "new") if c is not None else None
    if k in ("param", "ret"):
        fc = _func_classes(d[1])
        if fc is None:
            return None
        if k == "ret":
            c = fc[0]
            if c is None:
                c = _ret_plan.get(d[1], (None,))[0]
                return (c, "callee") if c is not None else None
        else:
            c = fc[1][d[2]] if d[2] < len(fc[1]) else None
            if c is None:
                c = _param_plan.get((d[1], d[2]), (None,))[0]
                return (c, "caller") if c is not None else None
        return (c, k) if c is not None else None
    if k == "load":
        b = _resolve(d[1], lays)
        c = _member_class(lays, b[0], d[2]) if b is not None else None
        return (c, "field") if c is not None else None
    if k == "phi":
        rs = [_resolve(x, lays) for x in d[1]]
        cs = set(r[0] for r in rs if r is not None)
        return (cs.pop(), "phi") if None not in rs and len(cs) == 1 else None
    if k == "or":
        return next((r for r in (_resolve(x, lays) for x in d[1]) if r is not None), None)
    return None


_param_review = {}  # (function, index) -> (review line, outcome): over all rounds (an applied one is typed after)
_param_plan = {}  # (function, index) -> (class or None, {class: [kind]}): the last _evidence pass's
_ret_plan = {}  # function -> (class or None, {class: [kind]}): from its return statements, the same pass


def _param_classes(lays):
    """_param_plan for the untyped parameters, from the arguments at their direct call sites (bncpp-28): one class,
    or their common base at offset 0; unrelated classes: a contradiction (None). Arguments that resolve to nothing
    are left out, as the stores are. A fixpoint over all of them at once (an argument can be the caller's own
    parameter), so the result does not depend on where a chain is entered. _ret_plan the same way, from the
    return statements (a parameter can come from a callee's result and a result from a parameter)"""
    _param_plan.clear()
    _ret_plan.clear()

    def plan_of(items):
        new = {}
        for key, descs in items:
            ev = {}
            for d in descs:
                r = _resolve(d, lays) if d is not None else None
                if r is not None:
                    ev.setdefault(r[0], []).append(r[1])
            if ev:
                new[key] = (_fields.pointer_class(_types, sorted(ev)), ev)
        return new
    for _i in range(10):
        new_p, new_r = plan_of(_param_args.items()), plan_of(_ret_descs.items())
        if new_p == _param_plan and new_r == _ret_plan:
            return
        _param_plan.clear()
        _param_plan.update(new_p)
        _ret_plan.clear()
        _ret_plan.update(new_r)
    _count("params from callers: no fixpoint")


def _evidence(lays):
    """{(class, offset): {class stored: [kind]}} from the pointer stores, against the layouts"""
    ev = {}
    _param_classes(lays)
    for _addr, off, dd, sd in _ptr_stores:
        dst = _resolve(dd, lays)
        src = _resolve(sd, lays) if dst is not None else None
        if src is not None:
            ev.setdefault((dst[0], off), {}).setdefault(src[0], []).append(src[1])
    return ev


# bncpp-35: a type BN cannot parse ('uint8', a class with no struct) keeps the name as an untyped override
_parsed = {}
for _k, (_n, _ts) in _overrides.items():
    _ty = None
    if _ts:
        try:
            _ty = bv.parse_type_string(_ts)[0]
        except Exception as _e:
            _names_notes.append("note: names line %d: type %r not parsed (%s), name kept untyped: %s" % (
                _override_lines[_k][0], _ts, str(_e).strip().replace("\n", " "), _override_lines[_k][1]))
            _count("names: type not parsed")
    _parsed[_k] = (_n, _ty)
for _n in _names_notes:
    if "not a number" in _n:
        _count("names: line skipped")
_override_names = set(n for n, _t in _overrides.values())


def _plan():
    """steps 3 and 4 once: the layouts from the accesses BN sees now, the review lines and the struct definitions"""
    # 3. accesses and the current members, per class struct that exists
    accesses, existing, widths = {}, {}, {}
    for a in list(_types)[:_limit]:
        qn = QualifiedName([_labels[a]])
        t = bv.get_type_by_name(qn)
        if t is None or not hasattr(t, "members"):
            continue
        widths[a] = t.width
        existing[a] = [(m.offset, m.name, m.type, m.type.width,
                        not (m.name == "vptr" or m.name.startswith("field_") or m.name in _override_names))
                       for m in t.members]
        try:
            s = bv.create_structure_from_offset_access(qn)
        except Exception:
            continue
        accesses[a] = {m.offset: (m.type.width, m.type) for m in s.members if m.offset != 0 or a in _no_vptr}
    # pointer fields to a fixpoint: a field typed 'Y*' types the loads from it, whose stores are evidence in turn
    _fclasses.clear()
    t_ptr = time.time()
    lays, typed = None, None
    for _i in range(8):
        ev = _evidence(lays) if lays is not None else None
        lays = _fields.layouts(_types, _labels, _sizes, accesses, existing, _parsed,
                               lambda label: Type.pointer(bv.arch, _ref(label + "::VTable")),
                               lambda n: Type.int(n, False), widths, ev,
                               lambda label: Type.pointer(bv.arch, Type.void() if label is None else _ref(label)))
        now = set((a, p[0], p[1]) for a, lay in lays.items() for p in lay.pointers if p[3] == "typed")
        if ev is not None and now == typed:
            break
        typed = now
    _count("s 3 pointer fixpoint", int(time.time() - t_ptr))
    # 4. the structs; the parameters typed from their callers (bncpp-28)
    counts, review, defs, shape = {}, [], [], []
    params = []
    for fa, i in sorted(_param_args):
        f = bv.get_function_at(fa)
        ps = f.type.parameters if f is not None else []
        if i >= len(ps) or _class_of(ps[i].type) is not None:
            continue
        c, ev = _param_plan.get((fa, i), (None, {}))
        if not ev:
            continue
        unknown = sum(1 for d in _param_args[(fa, i)] if d is None or _resolve(d, lays) is None)
        what = "contradiction" if c is None else "no struct" if c not in lays or c not in existing \
            else "kept (user)" if _protected(f) else "typed"
        _param_review[(fa, i)] = ("%s param %#x %s %s: %s  (%s; %d call sites unresolved)   [now: %s]" % (
            "apply" if what == "typed" else "keep ", fa, f.name, ps[i].name, lays[c].name if c in lays else "-",
            ", ".join("%s %s" % (lays[k].name if k in lays else "%#x" % k, "/".join(sorted(set(v))))
                      for k, v in sorted(ev.items())), unknown, ps[i].type), what)
        if what == "typed":
            params.append((f, i, lays[c].name))
    # the return types from the return statements (bncpp-28): (f, None, label) in params
    for fa in sorted(_ret_descs):
        f = bv.get_function_at(fa)
        if f is None or _class_of(f.return_type) is not None or f.return_type.width != bv.arch.address_size:
            continue
        c, ev = _ret_plan.get(fa, (None, {}))
        if not ev:
            continue
        unknown = sum(1 for d in _ret_descs[fa] if d is None or _resolve(d, lays) is None)
        what = "contradiction" if c is None else "no struct" if c not in lays or c not in existing \
            else "kept (user)" if _protected(f) else "typed"
        _param_review[("ret", fa)] = ("%s ret   %#x %s: %s  (%s; %d returns unresolved)   [now: %s]" % (
            "apply" if what == "typed" else "keep ", fa, f.name, lays[c].name if c in lays else "-",
            ", ".join("%s %s" % (lays[k].name if k in lays else "%#x" % k, "/".join(sorted(set(v))))
                      for k, v in sorted(ev.items())), unknown, f.return_type), what)
        if what == "typed":
            params.append((f, None, lays[c].name))
    for a, lay in sorted(lays.items()):
        if a not in existing:  # no struct of ours (bn_class_types.py makes them)
            counts["structs: no type yet (run bn_class_types.py)"] = \
                counts.get("structs: no type yet (run bn_class_types.py)", 0) + 1
            continue
        bases = [(b, off) for b, off in lay.bases if b in existing]  # never a base on a type that does not exist
        if len(bases) < len(lay.bases):
            counts["bases dropped: no type yet"] = counts.get("bases dropped: no type yet", 0) + len(lay.bases) - len(bases)
        s = StructureBuilder.create()
        s.width = lay.width
        s.base_structures = [BaseStructure(_ref(lays[b].name), off, lays[b].width) for b, off in bases]
        for m in lay.members:
            s.add_member_at_offset(m.name, m.type, m.offset, overwrite_existing=False)
        for key, n in (("structs", 1), ("fields", sum(1 for m in lay.members if m.source != "vptr")),
                       ("fields named (override)", sum(1 for m in lay.members if m.source == "override")),
                       ("pointer fields typed", sum(1 for p in lay.pointers if p[3] == "typed")),
                       ("pointer fields: contradiction", sum(1 for p in lay.pointers if p[3] == "contradiction")),
                       ("pointer fields kept", sum(1 for p in lay.pointers if p[3].startswith("kept"))),
                       ("structs with a base", 1 if bases else 0)):
            counts[key] = counts.get(key, 0) + n
        review.append("apply struct %s %#x (%s)%s: %s" % (
            lay.name, lay.width, lay.width_from, "".join(" base %s@%#x" % (lays[b].name, o) for b, o in bases),
            ", ".join("%#x %s" % (m.offset, m.name) for m in lay.members)))
        defs.append((QualifiedName([lay.name]), s))
        shape.append((lay.name, lay.width, tuple(bases), tuple((m.offset, m.name, str(m.type))
                                                                    for m in lay.members)))
    return lays, counts, review, defs, shape, params


# APPLY repeats 3 and 4 until the layouts no longer change: BN reports more accesses once a struct is wider (and
# the derived ones as its bases'), so one pass is not a fixpoint and a second APPLY would still change structs
_rounds, _prev = int(_env.get("ROUNDS") or 4), None
_trace = set(x for x in (_env.get("TRACE") or "").split(",") if x)
for _round in range(1, (_rounds if _apply else 1) + 1):
    _lays, _round_counts, _round_review, _defs, _shape, _params = _plan()
    _diff = [] if _prev is None else [x for x, y in zip(_shape, _prev) if x != y]
    _changed = None if _prev is None else len(_diff) + abs(len(_shape) - len(_prev))
    print("round %d: %s%s" % (_round, ", ".join("%s %d" % kv for kv in sorted(_round_counts.items())),
                              "" if _changed is None else ", structs changed %d %s" % (
                                  _changed, " ".join("%s(%#x)" % (x[0], x[1]) for x in _diff[:10]))))
    for _t in _shape:
        if _t[0] in _trace:
            print("  trace %s %#x bases %s: %s" % (_t[0], _t[1], _t[2], " ".join("%#x %s %s" % m for m in _t[3])))
    _lap("3+4 round %d" % _round)
    if _changed == 0 and not _params:
        break
    _prev = _shape
    _final_review, _final_counts = _round_review, _round_counts
    if _apply and _defs:
        bv.define_user_types([(n, s.immutable_copy()) for n, s in _defs], None)
    if _apply:
        for _f, _i, _label in _params:
            _old = _f.type
            _ps = list(_old.parameters)
            _typed_here.add(_f.start)
            _ret = _old.return_value
            if _i is None:  # the return type
                _ret = Type.pointer(bv.arch, _ref(_label))
            else:
                _ps[_i] = FunctionParameter(Type.pointer(bv.arch, _ref(_label)), _ps[_i].name)
            _f.type = Type.function(_ret, _ps, calling_convention=_f.calling_convention,
                                    variable_arguments=_old.has_variable_arguments)
    if _apply and (_defs or _params):
        bv.update_analysis_and_wait()
_count("rounds", _round)
_count("stable", 1 if _changed == 0 or not _apply else 0)
# bncpp-60: an APPLY that stopped at the round limit says so (tests/bn_dump.py writes it into .fields, suite.py check
# gates on it): the structs that still changed in the last round
_unsettled = None
if _apply and _changed != 0:
    _unsettled = "not settled after %d rounds: %s" % (_round, " ".join("%s(%#x)" % (x[0], x[1]) for x in _diff) or (
        "structs changed %d" % _changed if _changed else "only one round"))
for _k, _v in _final_counts.items():
    _count(_k, _v)
for _key, (_line, _what) in _param_review.items():
    _count(("returns: " if _key[0] == "ret" else "params from callers: ") + _what)


def _why(d):
    """the innermost reason a call-site argument resolves to no class (bncpp-28: which evidence source is next)"""
    if d is None:
        return "no variable (constant / expression)"
    k = d[0]
    if k == "new":
        return "new: no class of that size"
    if k == "ret":
        return "ret: callee returns no class"
    if k == "param":
        return "param of a vtable-slot function" if d[1] in _virtual else "param: no caller evidence"
    if k == "load":
        return "load: " + (_why(d[1]) if _resolve(d[1], _lays) is None else "field has no class")
    if k == "phi":
        return "phi: " + ("several classes" if all(_resolve(x, _lays) is not None for x in d[1])
                          else next(_why(x) for x in d[1] if _resolve(x, _lays) is None))
    if k == "or":
        return next(_why(x) for x in d[1] if _resolve(x, _lays) is None)
    return k


# why: per parameter with direct callers (already a class / evidence / none) and per unresolved argument the reason
if not _apply:
    _why_params, _why_args = {}, {}
    for (_fa, _i), _args in _param_args.items():
        _fc = _func_classes(_fa)
        if _fc is not None and _i < len(_fc[1]) and _fc[1][_i] is not None:
            _what = "already a class"
        elif _param_plan.get((_fa, _i), (None, {}))[1]:
            _what = "evidence"
        else:
            _what = "no evidence"
        _why_params[_what] = _why_params.get(_what, 0) + 1
        if _what == "already a class":
            continue
        for _d in _args:
            if _d is None or _resolve(_d, _lays) is None:
                _r = _why(_d)
                _why_args[_r] = _why_args.get(_r, 0) + 1
    _why_rets, _why_rvals = {}, {}
    for _fa, _descs in _ret_descs.items():
        _fc = _func_classes(_fa)
        _what = "no function" if _fc is None else "already a class" if _fc[0] is not None else \
            "evidence" if _ret_plan.get(_fa, (None, {}))[1] else "no returns" if not _descs else "no evidence"
        _why_rets[_what] = _why_rets.get(_what, 0) + 1
        if _what in ("no evidence", "evidence"):
            for _d in _descs:
                if _d is None or _resolve(_d, _lays) is None:
                    _r = _why(_d)
                    _why_rvals[_r] = _why_rvals.get(_r, 0) + 1
    print("why returns: " + ", ".join("%s %d" % kv for kv in sorted(_why_rets.items(), key=lambda kv: -kv[1])))
    print("why returned values unresolved: " + ", ".join("%s %d" % kv for kv in sorted(_why_rvals.items(),
                                                                                       key=lambda kv: -kv[1])))
    print("why params: " + ", ".join("%s %d" % kv for kv in sorted(_why_params.items(), key=lambda kv: -kv[1])))
    print("why args unresolved: " + ", ".join("%s %d" % kv for kv in sorted(_why_args.items(), key=lambda kv: -kv[1])))
_review += sorted(_names_notes, key=lambda n: int(n.split()[3].rstrip(':'))) + _final_review + [line for line, _what in sorted(_param_review.values())]
_rv = os.path.join(REPO, ".scratch/classes/%s.fields.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_review) + "\n\n" + "\n".join(_fields.format_layouts(_lays)) + "\n")
print("review -> %s" % _rv)
if _unsettled:
    print(_unsettled)
print("%s: %s (%.1f s)" % ("applied" if _apply else "dry run", ", ".join(
    "%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

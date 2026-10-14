# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py and the class names / types
# (tests/bn_class_apply.py, tests/bn_class_types.py):
#   bnrun --bndb DB --timeout 1800 tests/bn_class_fields.py                     # dry run: plan + review file
#   bnrun --bndb DB --timeout 1800 --env APPLY=1 tests/bn_class_fields.py       # apply (in RAM), then save PATH
#   options: --env BASELINE=F (as bn_class_types.py), --env NAMES=F (field names: lines 'label offset name [type]'),
#            --env LIMIT=N (timing: only the first N functions in step 1 and N classes in step 3; dry run only),
#            --env NOCACHE=1 (step 1 always anew, no cache file: the suite, tests/bn_dump.py),
#            --env ROUNDS=N (APPLY: at most N passes of steps 3+4 until the structs stop changing; default 4)
# Step 1 (building the MLIL of ~7,000 functions: ~4-9 min on SynthV) is cached per binary (shared/bncache.py: next to
# the database, <x>.bndb.bncpp-cache.json), section "ctors" with _CTORS_VERSION (bump it when step 1 changes).
# bncpp-22: constructors / destructors get 'X* this', then the class structs get their size, base subobjects and
# fields (cpp/rtti_fields.py). A dry run plans with the accesses BN sees now (constructors still untyped, so
# fewer fields); APPLY types the constructors first, re-analyses, then reads the accesses. Never over a user type,
# a user-named member or a struct that is not ours (anything but vptr / field_* / NAMES members).
# Review: .scratch/classes/<binary>.fields.review
import importlib, json, os, re, time
import binaryninja as _bn
from binaryninja import (BaseStructure, FunctionParameter, MediumLevelILOperation as Op, NamedTypeReferenceClass,
                         QualifiedName, StructureBuilder, Type)

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
    with open(_env["BASELINE"]) as _fh:
        _baseline = json.load(_fh)
_overrides = {}
if _env.get("NAMES"):
    with open(_env["NAMES"]) as _fh:
        for _line in _fh:
            _p = _line.split("#")[0].split(None, 3)
            if len(_p) >= 3:
                _overrides[(_p[0], int(_p[1], 0))] = (_p[2], _p[3].strip() if len(_p) > 3 else None)
_CTORS_VERSION = 2
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


def _protected(f):
    """a type someone set; with BASELINE, one that differs from BN's fresh inference -- after mapping back what
    BN inferred from our own types (X::VTable** -> void***)"""
    if not f.has_user_type:
        return False
    base = _baseline.get("%#x" % f.start) if _baseline is not None else None
    return _baseline is None or base is None or _OURS.sub("void***", str(f.type)) != base


def _ref(name):
    return Type.named_type_reference(NamedTypeReferenceClass.StructNamedTypeClass, QualifiedName([name]))


_img = _bnimage.BNImage(bv)
_types = _rtti.scan(_img)
_labels = _names.labels(_types, _img.demangle, _names.label_overrides(_types, _img.symbol_at))
_points = {vt.addr: (a, vt.offset_to_top) for a, t in _types.items() for vt in t.vtables if vt.construction_for is None}
_new_addrs = set(s.address for n in _OPERATOR_NEW for s in bv.get_symbols_by_name(n))
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


def _new_uses(m, var, size, sites, seen):
    """the object operator new returned in var: its vptr store at 0, or the constructor it goes to as 'this'"""
    if var in seen:
        return
    seen.add(var)
    for u in m.get_var_uses(var):
        o = u.operation
        if o == Op.MLIL_SET_VAR and u.src.operation == Op.MLIL_VAR and u.src.src == var:
            _new_uses(m, u.dest, size, sites, seen)
        elif o in (Op.MLIL_STORE, Op.MLIL_STORE_STRUCT):
            st = _store_site(u)
            if st is not None and st[0] == var and st[1] == 0:
                c, ott = _points[st[2]]
                if ott == 0:
                    sites.append((c, None, size))
        elif o == Op.MLIL_CALL and u.dest.operation == Op.MLIL_CONST_PTR and u.params \
                and u.params[0].operation == Op.MLIL_VAR and u.params[0].src == var:
            sites.append((None, u.dest.constant, size))


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
                    _new_uses(_m, _mi.output[0], _mi.params[0].constant, _sites, set())
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
for _ctor in sorted(set(c for _cls, c, _n in _sites if c is not None and c not in _ctors)):
    _to = _forwards_to(_ctor)
    if _to in _ctors:
        _ctors[_ctor] = _ctors[_to]
        _count("ctors forwarding")
_lap("1c forwarding ctors")
_sizes = _fields.class_sizes(_sites, _ctors)
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
        _f.type = Type.function(_old.return_value, [FunctionParameter(Type.pointer(bv.arch, _ref(_label)), "this")]
                                + list(_old.parameters[1:]), calling_convention=_f.calling_convention,
                                variable_arguments=_old.has_variable_arguments)
if _apply:
    bv.update_analysis_and_wait()
_lap("2 ctor types")

_parsed = {}
for _k, (_n, _ts) in _overrides.items():
    _parsed[_k] = (_n, bv.parse_type_string(_ts)[0] if _ts else None)
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
        accesses[a] = {m.offset: (m.type.width, m.type) for m in s.members if m.offset != 0}
    lays = _fields.layouts(_types, _labels, _sizes, accesses, existing, _parsed,
                           lambda label: Type.pointer(bv.arch, _ref(label + "::VTable")),
                           lambda n: Type.int(n, False), widths)
    # 4. the structs
    counts, review, defs, shape = {}, [], [], []
    for a, lay in sorted(lays.items()):
        if a not in existing:
            continue  # no struct of ours (bn_class_types.py makes them)
        s = StructureBuilder.create()
        s.width = lay.width
        s.base_structures = [BaseStructure(_ref(lays[b].name), off, lays[b].width) for b, off in lay.bases]
        for m in lay.members:
            s.add_member_at_offset(m.name, m.type, m.offset, overwrite_existing=False)
        for key, n in (("structs", 1), ("fields", sum(1 for m in lay.members if m.source != "vptr")),
                       ("fields named (override)", sum(1 for m in lay.members if m.source == "override")),
                       ("structs with a base", 1 if lay.bases else 0)):
            counts[key] = counts.get(key, 0) + n
        review.append("apply struct %s %#x (%s)%s: %s" % (
            lay.name, lay.width, lay.width_from, "".join(" base %s@%#x" % (lays[b].name, o) for b, o in lay.bases),
            ", ".join("%#x %s" % (m.offset, m.name) for m in lay.members)))
        defs.append((QualifiedName([lay.name]), s))
        shape.append((lay.name, lay.width, tuple(lay.bases), tuple((m.offset, m.name, str(m.type))
                                                                    for m in lay.members)))
    return lays, counts, review, defs, shape


# APPLY repeats 3 and 4 until the layouts no longer change: BN reports more accesses once a struct is wider (and
# the derived ones as its bases'), so one pass is not a fixpoint and a second APPLY would still change structs
_rounds, _prev = int(_env.get("ROUNDS") or 4), None
for _round in range(1, (_rounds if _apply else 1) + 1):
    _lays, _round_counts, _round_review, _defs, _shape = _plan()
    _diff = [] if _prev is None else [x for x, y in zip(_shape, _prev) if x != y]
    _changed = None if _prev is None else len(_diff) + abs(len(_shape) - len(_prev))
    print("round %d: %s%s" % (_round, ", ".join("%s %d" % kv for kv in sorted(_round_counts.items())),
                              "" if _changed is None else ", structs changed %d %s" % (
                                  _changed, " ".join("%s(%#x)" % (x[0], x[1]) for x in _diff[:10]))))
    _lap("3+4 round %d" % _round)
    if _changed == 0:
        break
    _prev = _shape
    _final_review, _final_counts = _round_review, _round_counts
    if _apply and _defs:
        bv.define_user_types([(n, s.immutable_copy()) for n, s in _defs], None)
        bv.update_analysis_and_wait()
_count("rounds", _round)
_count("stable", 1 if _changed == 0 or not _apply else 0)
for _k, _v in _final_counts.items():
    _count(_k, _v)
_review += _final_review
_rv = os.path.join(REPO, ".scratch/classes/%s.fields.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w") as _fh:
    _fh.write("\n".join(_review) + "\n\n" + "\n".join(_fields.format_layouts(_lays)) + "\n")
print("review -> %s" % _rv)
print("%s: %s (%.1f s)" % ("applied" if _apply else "dry run", ", ".join(
    "%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

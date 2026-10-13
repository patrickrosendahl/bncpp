# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 1800 tests/bn_class_types.py                     # dry run: counts
#   bnrun --bndb DB --timeout 1800 --env APPLY=1 tests/bn_class_types.py       # apply (in RAM), wait for analysis
#   bnrun --bndb-save DB                                                        # then persist, path-scoped
# bncpp-27: the class scan (cpp/rtti.py) as types (cpp/rtti_types.py) -- struct X { X::VTable* vptr; }, X::VTable
# with a function pointer per slot, 'X* this' as the first parameter of X's primary-vtable functions, and the
# vtable struct on the vtable's address point. Never over what someone set: an existing type of the same name,
# a function with a user type, a user data variable -- each skip is counted. Where a database marks every
# function's type as user-set, give BN's own inference as the baseline (only types that differ are protected):
#   bnrun --bndb RAW_BINARY --timeout 120 --env DUMP_TYPES=F tests/bn_class_types.py   (a fresh view)
#   bnrun --bndb DB ... --env BASELINE=F tests/bn_class_types.py
import importlib, os, time
import binaryninja as _bn
from binaryninja import FunctionParameter, NamedTypeReferenceClass, QualifiedName, StructureBuilder, Type

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_types_mod = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_types")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_env = globals().get("env") or {}
_apply = (_env.get("APPLY") or os.environ.get("APPLY")) == "1"
_t0 = time.time()
if _env.get("DUMP_TYPES"):
    # baseline for BASELINE: every function's type as BN infers it (run this on a fresh view of the binary)
    import json
    with open(_env["DUMP_TYPES"], "w") as _fh:
        json.dump({"%#x" % f.start: str(f.type) for f in bv.functions}, _fh)
    raise SystemExit("dumped %d function types into %s" % (len(bv.functions), _env["DUMP_TYPES"]))
_baseline = None
if _env.get("BASELINE"):
    import json
    with open(_env["BASELINE"]) as _fh:
        _baseline = json.load(_fh)


def _protected(f):
    """a type someone set: a user type -- with BASELINE, only one that differs from BN's own inference (a
    database where every function carries a user type, e.g. after a bulk export, protects nothing by itself)"""
    if not f.has_user_type:
        return False
    if _baseline is None:
        return True
    base = _baseline.get("%#x" % f.start)
    return base is None or base != str(f.type)


def _demangle(mangled):
    try:
        _ty, parts = _bn.demangle_gnu3(bv.arch, mangled)
    except Exception:
        return None
    return str(QualifiedName(parts)) if parts else None


def _call_targets(addr):
    f = bv.get_function_at(addr)
    if f is None:
        return None
    out = []
    for site in f.call_sites:
        for t in bv.get_callees(site.address, f, site.arch):
            s = bv.get_symbol_at(t)
            out.append(s.raw_name if s is not None and s.type in _bnimage._IMPORTS else t)
    return out


_classes, _functions = _types_mod.plan(_rtti.scan(_bnimage.BNImage(bv)), _demangle, _call_targets)
_counts = {}


def _count(key, n=1):
    _counts[key] = _counts.get(key, 0) + n


def _ref(name):
    return Type.named_type_reference(NamedTypeReferenceClass.StructNamedTypeClass, QualifiedName([name]))


_arch = bv.arch
_mine = set()  # class names whose types this run defines (an existing type of that name is someone else's)
_new_types = []
for _c in _classes:
    if bv.get_type_by_name(QualifiedName([_c.name])) is not None:
        _count("class type kept (exists)")
        continue
    _mine.add(_c.name)
    _s = StructureBuilder.create()
    _s.add_member_at_offset("vptr", Type.pointer(_arch, _ref(_c.vtable_name)), 0)
    _new_types.append((QualifiedName([_c.name]), _s))
_count("class types", len(_new_types))
if _apply and _new_types:
    bv.define_user_types([(n, t.immutable_copy()) for n, t in _new_types], None)

# 'this' on the owners' functions
for _f_addr, (_label, _role) in sorted(_functions.items()):
    _f = bv.get_function_at(_f_addr)
    if _f is None:
        _count("function missing")
        continue
    if _protected(_f):
        _count("function type kept (user)")
        continue
    if _label not in _mine:
        _count("function skipped (class type not ours)")
        continue
    _old = _f.type
    _params = [FunctionParameter(Type.pointer(_arch, _ref(_label)), "this")] + list(_old.parameters[1:])
    _ret = Type.void() if _role in ("dtor", "deleting") else _old.return_value
    _count("function typed")
    if _apply:
        _f.type = Type.function(_ret, _params, calling_convention=_f.calling_convention,
                                variable_arguments=_old.has_variable_arguments)
if _apply:
    bv.update_analysis_and_wait()

# vtable structs (after the functions, so their members carry the new function types), on the address points
_vt_types = []
for _c in _classes:
    if _c.name not in _mine:
        continue
    _s = StructureBuilder.create()
    for _i, (_m, _slot) in enumerate(_c.members):
        _f = bv.get_function_at(_slot) if isinstance(_slot, int) else None
        _target = _f.type if _f is not None else Type.function(Type.void(), [])
        _s.add_member_at_offset(_m, Type.pointer(_arch, _target), 8 * _i)
    _vt_types.append((QualifiedName([_c.vtable_name]), _s))
_count("vtable types", len(_vt_types))
if _apply and _vt_types:
    bv.define_user_types([(n, t.immutable_copy()) for n, t in _vt_types], None)
for _c in _classes:
    if _c.name not in _mine:
        continue
    _dv = bv.get_data_var_at(_c.vtable_addr)
    if _dv is not None and not _dv.auto_discovered:
        _count("vtable data kept (user)")
        continue
    _count("vtable data typed")
    if _apply:
        bv.define_user_data_var(_c.vtable_addr, _ref(_c.vtable_name))
if _apply:
    bv.update_analysis_and_wait()
print("%s: %d classes, %d functions planned; %s (%.1f s)" % (
    "applied" if _apply else "dry run", len(_classes), len(_functions),
    ", ".join("%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

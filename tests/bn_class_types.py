# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 1800 tests/bn_class_types.py                     # dry run: counts
#   bnrun --bndb DB --timeout 1800 --env APPLY=1 tests/bn_class_types.py       # apply (in RAM), wait for analysis
#   bnrun --bndb-save DB                                                        # then persist, path-scoped
# bncpp-27: the class scan (cpp/rtti.py) as types (cpp/rtti_types.py) -- struct X { X::VTable* vptr; }, X::VTable
# with a function pointer per slot, 'X* this' as the first parameter of X's primary-vtable functions, and the
# vtable struct on the vtable's address point. bncpp-31: a base anchored by the RTTI base list whose vtable is
# not in the image gets a struct too (a vptr + X::VTable from the derived classes' slots, no data variable;
# no virtual functions: no vptr, a placeholder width the fields step sizes). Never over what someone set: an
# existing type of the same name,
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
    with open(_env["DUMP_TYPES"], "w", encoding="utf-8") as _fh:
        json.dump({"%#x" % f.start: str(f.type) for f in bv.functions}, _fh)
    raise SystemExit("dumped %d function types into %s" % (len(bv.functions), _env["DUMP_TYPES"]))
_baseline = None
if _env.get("BASELINE"):
    import json
    with open(_env["BASELINE"], encoding="utf-8") as _fh:
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


def _user_name(addr):
    f = bv.get_function_at(addr)
    return f.name if f is not None and not f.symbol.auto else None


_img = _bnimage.BNImage(bv)
_scan = _rtti.scan(_img)
_names_mod = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_names")
_classes, _functions = _types_mod.plan(_scan, _img.demangle, _img.call_targets,
                                       _names_mod.label_overrides(_scan, _img.symbol_at), _user_name)
_counts = {}
_review = []  # what the run would do (or did), for the review file


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
        _review.append("keep  type %s (exists)" % _c.name)
        continue
    _mine.add(_c.name)
    _s = StructureBuilder.create()
    if _c.polymorphic:
        _review.append("apply type %s { %s::VTable* vptr; }   %s" % (
            _c.name, _c.name, "vtable %#x: %s" % (_c.vtable_addr, ", ".join(m for m, _s in _c.members))
            if _c.vtable_addr is not None else
            "[anchored base; vtable from the derived classes' slots: %s]" % ", ".join(m for m, _s in _c.members)))
        _s.add_member_at_offset("vptr", Type.pointer(_arch, _ref(_c.vtable_name)), 0)
    else:  # an anchored base with no virtual functions (bncpp-31): no vptr, the fields step sizes it
        _count("class type anchored (no vptr)")
        _review.append("apply type %s (anchored base, no virtual functions)   [width from the fields step]"
                      % _c.name)
        _s.width = 8  # a placeholder: BN needs a usable width; bn_class_fields.py sets the real one
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
        _review.append("keep  %#x %s   [now: %s]" % (_f_addr, _f.name, _f.type))
        continue
    if _label not in _mine:
        _count("function skipped (class type not ours)")
        _review.append("skip  %#x %s   [class type %s exists]" % (_f_addr, _f.name, _label))
        continue
    _old = _f.type
    _params = [FunctionParameter(Type.pointer(_arch, _ref(_label)), "this")] + list(_old.parameters[1:])
    _ret = Type.void() if _role in ("dtor", "deleting") else _old.return_value
    _count("function typed")
    _review.append("apply %#x %s: this = %s*%s   [now: %s]" % (
        _f_addr, _f.name, _label, ", returns void" if _role in ("dtor", "deleting") else "", _old))
    if _apply:
        _f.type = Type.function(_ret, _params, calling_convention=_f.calling_convention,
                                variable_arguments=_old.has_variable_arguments)
        # bncpp-28: ours for the later passes of this session (bn_class_fields.py types more of its parameters)
        bv.session_data.setdefault("bncpp_typed", set()).add(_f_addr)
if _apply:
    bv.update_analysis_and_wait()

# vtable structs (after the functions, so their members carry the new function types), on the address points;
# an anchored base with no virtual functions has no vtable struct (no slots; its subobject has no vptr)
_vt_types = []
for _c in _classes:
    if _c.name not in _mine or not _c.members:
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
    if _c.name not in _mine or _c.vtable_addr is None:
        continue  # an anchored base: no vtable of its own in the image (bncpp-31)
    _dv = bv.get_data_var_at(_c.vtable_addr)
    if _dv is not None and not _dv.auto_discovered:
        _count("vtable data kept (user)")
        continue
    _count("vtable data typed")
    if _apply:
        bv.define_user_data_var(_c.vtable_addr, _ref(_c.vtable_name))
if _apply:
    bv.update_analysis_and_wait()
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_rv = os.path.join(REPO, ".scratch/classes/%s.types.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_review) + "\n")
print("review -> %s" % _rv)
print("%s: %d classes, %d functions planned; %s (%.1f s)" % (
    "applied" if _apply else "dry run", len(_classes), len(_functions),
    ", ".join("%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

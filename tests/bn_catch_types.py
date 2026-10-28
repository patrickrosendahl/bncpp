# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py and the class types
# (tests/bn_class_types.py: the class structs must exist):
#   BNDB=DB $B/bn --timeout 900 tests/bn_catch_types.py                 # dry run: plan + review file
#   BNDB=DB APPLY=1 $B/bn --timeout 900 tests/bn_catch_types.py   # apply (in RAM; + SAVE=1: into DB)
# bncpp-28 source 4: the exception object in a catch handler gets the clause's class. Per catch clause of the
# exception tables (cpp/lsda.py through cpp/eh_comments.py) whose type is a class of the scan (cpp/rtti.py), the
# handler code (cpp/eh_render.specialize: the landing pad with the selector fixed to the clause) holds the object's
# address in the variable `x = ___cxa_begin_catch(...)` -> 'X* x'. A variable the handlers of two classes share
# (one pad, no dispatch between them) is a contradiction and stays. Never over a type that already points to a
# struct. Review: .scratch/classes/<binary>.catch.review ('catch' lines: outcome, pad, variable, class).
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, os, time
import binaryninja as _bn
from binaryninja import HighLevelILOperation as Op, NamedTypeReferenceClass, QualifiedName, Type, TypeClass

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_p = _dev["pkgname"]
_rtti = importlib.import_module(_p + ".cpp.rtti")
_names = importlib.import_module(_p + ".cpp.rtti_names")
_bnimage = importlib.import_module(_p + ".cpp.bnimage")
_ehc = importlib.import_module(_p + ".cpp.eh_comments")
_ehr = importlib.import_module(_p + ".cpp.eh_render")
_env = globals().get("env") or {}
_apply = (_env.get("APPLY") or os.environ.get("APPLY")) == "1"
_t0 = time.time()
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_counts, _review = {}, []


def _count(key, n=1):
    _counts[key] = _counts.get(key, 0) + n


_img = _bnimage.BNImage(bv)
_types = _rtti.scan(_img)
_labels = _names.labels(_types, _img.demangle, _names.label_overrides(_types, _img.symbol_at))


def _class(t):
    """the scan's typeinfo address of a catch type (an address, or BN's name typeinfo_for_X), else None"""
    if isinstance(t, int):
        return t if t in _types else None
    return next((k for k in _img.symbol_keys(t) if isinstance(k, int) and k in _types), None)


def _struct(t):
    """the struct name a pointer type points to, else None"""
    if t is None or t.type_class != TypeClass.PointerTypeClass:
        return None
    tg = t.target
    if tg.type_class == TypeClass.NamedTypeReferenceClass:
        return str(tg.name)
    if tg.type_class == TypeClass.StructureTypeClass and tg.registered_name is not None:
        return str(tg.registered_name.name)
    return None


_plan = {}  # (function start, variable) -> {label: [(pad, selector)]}
_funcs = {}
_seen = set()
for _owner, _table in sorted(_ehc.index(bv).owners.items()):
    _of = bv.get_function_at(_owner)
    for _cs in _table.call_sites:
        if _cs.landing_pad is None:
            continue
        _on_pad = sum(c.kind == c.CATCH for c in _cs.clauses)
        for _c in _cs.clauses:
            if _c.kind != _c.CATCH or _c.type is None or (_cs.landing_pad, _c.type_index) in _seen:
                continue
            _seen.add((_cs.landing_pad, _c.type_index))
            _count("catch clauses")
            _a = _class(_c.type)
            if _a is None:
                continue
            _count("catch clauses: a class of the scan")
            _pf = bv.get_function_at(_cs.landing_pad)
            if _pf is None:
                _count("pad: no function")
                continue
            _h = _ehr.specialize(_pf, _c.type_index, _on_pad, _of)
            if _h is None:
                _count("pad: no dispatch found")
                continue
            _found = 0
            for _s in _h.stmts:
                if _s.operation != Op.HLIL_VAR_INIT or _ehr.callee(_ehr._strip(_s.src)) != "cxa_begin_catch":
                    continue
                _f = _s.function.source_function
                _funcs[_f.start] = _f
                _plan.setdefault((_f.start, _s.dest), {}).setdefault(_labels[_a], []).append(
                    (_cs.landing_pad, _c.type_index))
                _found += 1
            _count("handlers with the object in a variable" if _found else "handlers: no begin_catch variable")

for (_fs, _v), _ev in sorted(_plan.items(), key=lambda kv: (kv[0][0], kv[0][1].name)):
    _f = _funcs[_fs]
    _label = next(iter(_ev)) if len(_ev) == 1 else None
    _now = _v.type
    _where = ", ".join("%#x #%d" % x for l in sorted(_ev) for x in _ev[l])
    if _label is None:
        _what = "contradiction"
    elif _struct(_now) == _label:
        _what = "already"
    elif _struct(_now) is not None:
        _what = "kept (other struct)"
    elif bv.get_type_by_name(QualifiedName([_label])) is None:
        _what = "no struct"
    else:
        _what = "typed"
    _count("variables: " + _what)
    _review.append("%s catch %s %s %s: %s  (from %s)   [now: %s]" % (
        "apply" if _what == "typed" else "keep ", _f.name, _v.name, _what, " / ".join(sorted(_ev)), _where, _now))
    if _apply and _what == "typed":
        _f.create_user_var(_v, Type.pointer(bv.arch, Type.named_type_reference(
            NamedTypeReferenceClass.StructNamedTypeClass, QualifiedName([_label]))), _v.name)
if _apply and _counts.get("variables: typed"):
    bv.update_analysis_and_wait()

_rv = os.path.join(REPO, ".scratch/classes/%s.catch.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_review) + "\n")
print("review -> %s" % _rv)
print("%s: %s (%.1f s)" % ("applied" if _apply else "dry run", ", ".join(
    "%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))
_e.finish(globals())  # SAVE=1 / SAVE=/abs/new.bndb persists the view's changes (tests/bn_engine.py)

# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 600 tests/bn_class_apply.py                       # dry run: counts + directive file
#   bnrun --bndb DB --timeout 600 --env APPLY=1 tests/bn_class_apply.py         # apply (in RAM)
#   bnrun --bndb-save DB                                                         # then persist, path-scoped
# The class scan (cpp/rtti.py) through BN, named by cpp/rtti_names.py, as annotate directives (R:/D:/C:) into
# .scratch/classes/<binary>.directives. Applying never overwrites what someone named or wrote: a function is
# renamed only while its name is BN's (auto symbol, sub_...), a data symbol only where there is none or an auto
# one, a comment only where there is none. Every skip is counted.
import importlib, os, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_names = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_names")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_env = globals().get("env") or {}
_apply = (_env.get("APPLY") or os.environ.get("APPLY")) == "1"

_t0 = time.time()


def _demangle(mangled):
    try:
        _ty, parts = _bn.demangle_gnu3(bv.arch, mangled)
    except Exception:
        return None
    return str(_bn.types.QualifiedName(parts)) if parts else None


def _call_targets(addr):
    """per call site: a local function's address, or an import's raw name"""
    f = bv.get_function_at(addr)
    if f is None:
        return None
    out = []
    for site in f.call_sites:
        for t in bv.get_callees(site.address, f, site.arch):
            s = bv.get_symbol_at(t)
            out.append(s.raw_name if s is not None and s.type in _bnimage._IMPORTS else t)
    return out


def _symbol_at(addr):
    s = bv.get_symbol_at(addr)
    return (s.full_name, not s.auto) if s is not None else None


_types = _rtti.scan(_bnimage.BNImage(bv))
_overrides = _names.label_overrides(_types, _symbol_at)  # classes someone named through their vtable symbol
_dirs = _names.directives(_types, _demangle, _call_targets, _overrides)
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = os.path.join(REPO, ".scratch/classes/%s.directives" % _name)
os.makedirs(os.path.dirname(_out), exist_ok=True)
with open(_out, "w") as _fh:
    _fh.write("".join("%s:%#x:%s\n" % d for d in _dirs))

_counts = {}
_review = []  # "apply|keep  directive  [what is there now]" for the review file


def _count(key):
    _counts[key] = _counts.get(key, 0) + 1


def _note(action, d, now=""):
    _review.append("%-5s %s:%#x:%s%s" % (action, d[0], d[1], d[2], "   [now: %s]" % now if now else ""))


for _kind, _addr, _text in _dirs:
    if _kind == "R":
        _f = bv.get_function_at(_addr)
        if _f is None:
            _count("R no function")
            _note("skip", (_kind, _addr, _text), "no function")
            continue
        if not _f.symbol.auto:
            _count("R kept (named)")
            _note("keep", (_kind, _addr, _text), _f.name)
            continue
        _count("R rename")
        _note("apply", (_kind, _addr, _text), _f.name)
        if _apply:
            bv.define_user_symbol(_bn.Symbol(_bn.SymbolType.FunctionSymbol, _addr, _text))
    elif _kind == "D":
        _s = bv.get_symbol_at(_addr)
        if _s is not None and not _s.auto:
            _count("D kept (named)")
            _note("keep", (_kind, _addr, _text), _s.full_name)
            continue
        _count("D define")
        _note("apply", (_kind, _addr, _text), _s.full_name if _s is not None else "")
        if _apply:
            bv.define_user_symbol(_bn.Symbol(_bn.SymbolType.DataSymbol, _addr, _text))
    else:
        _fs = bv.get_functions_containing(_addr) or []
        _old = [f.get_comment_at(_addr) for f in _fs] if _fs else [bv.get_comment_at(_addr)]
        if any(_old):
            _count("C kept (existing)")
            _note("keep", (_kind, _addr, _text), "; ".join(o for o in _old if o).replace("\n", " ")[:120])
            continue
        _count("C set")
        _note("apply", (_kind, _addr, _text))
        if _apply:
            for _f in _fs:
                _f.set_comment_at(_addr, _text)
            if not _fs:
                bv.set_comment_at(_addr, _text)
with open(_out[:-len(".directives")] + ".names.review", "w") as _fh:
    _fh.write("\n".join(_review) + "\n")
print("%d typeinfos, %d directives -> %s (+ .names.review)" % (len(_types), len(_dirs), _out))
print("%s: %s (%.1f s)" % ("applied" if _apply else "dry run", ", ".join(
    "%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

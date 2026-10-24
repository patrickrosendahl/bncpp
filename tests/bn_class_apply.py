# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 600 tests/bn_class_apply.py                       # dry run: counts + directive file
#   bnrun --bndb DB --timeout 600 --env APPLY=1 tests/bn_class_apply.py         # apply (in RAM)
#   bnrun --bndb-save DB                                                         # then persist, path-scoped
# The class scan (cpp/rtti.py) through BN, named by cpp/rtti_names.py, as annotate directives (R:/D:/C:) into
# .scratch/classes/<binary>.directives. Applying never overwrites what someone named or wrote: a function is
# renamed only while its name is BN's own (no symbol: sub_..., or BN's auto thunk name j_...) -- a symbol from the
# binary is auto too and is kept (bncpp-94: Job::run(int) had become Job::vfunc2) --, a data symbol only where
# there is none or an auto one, a comment only where there is none. Every skip is counted. One exception: a function still carrying our own
# placeholder (Owner::vfuncN, Owner::vfuncI_at_N [thunk], Owner::vfuncN [thunk]: rtti_names.placeholder_owner) from an
# earlier apply takes a better name for the same owner (bncpp-23: operator(); bncpp-57: the thunk forms).
# A vtable slot is a function entry by definition: a slot target BN has no function at gets one (bncpp-30: tiny
# functions such as a lone 'ret' or a tail jump; arm64 SynthV 210), then its name -- only in executable code. The
# review says whether it lies inside another function's body; APPLY reports the neighbours (the function containing
# it, the one before it) whose shape (size, blocks) the new function changed.
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
_img = _bnimage.BNImage(bv)
_types = _rtti.scan(_img)
_overrides = _names.label_overrides(_types, _img.symbol_at)  # classes someone named through their vtable symbol
_dirs = _names.directives(_types, _img.demangle, _img.call_targets, _overrides)
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = os.path.join(REPO, ".scratch/classes/%s.directives" % _name)
os.makedirs(os.path.dirname(_out), exist_ok=True)
with open(_out, "w", encoding="utf-8") as _fh:
    _fh.write("".join("%s:%#x:%s\n" % d for d in _dirs))

_counts = {}
_review = []  # "apply|keep  directive  [what is there now]" for the review file


def _own_placeholder(now, text):
    owner = _names.placeholder_owner(now)  # Owner::vfuncN, also the thunk forms (bncpp-57)
    return owner is not None and text.startswith(owner + "::") and text != now


def _count(key):
    _counts[key] = _counts.get(key, 0) + 1


def _note(action, d, now=""):
    _review.append("%-5s %s:%#x:%s%s" % (action, d[0], d[1], d[2], "   [now: %s]" % now if now else ""))


def _bn_name(f):
    # BN's own name: no symbol at the address (sub_...) or BN's thunk name (auto j_...); every other auto symbol
    # comes from the binary (exports, demangled locals, stubs such as _objc_msgSend$x)
    s = bv.get_symbol_at(f.start)
    return s is None or (s.auto and s.raw_name.startswith("j_"))


def _shape(f):
    return (f.start, f.total_bytes, len(f.basic_blocks))


_created, _neighbours = [], {}
for _kind, _addr, _text in _dirs:
    if _kind == "R":
        _f = bv.get_function_at(_addr)
        if _f is None:
            if not bv.is_offset_executable(_addr):
                _count("R no function, not code")
                _note("skip", (_kind, _addr, _text), "no function, not executable")
                continue
            _in = bv.get_functions_containing(_addr) or []
            _count("R create function" + (" (inside another)" if _in else ""))
            _note("apply", (_kind, _addr, _text), "no function: create%s" % (
                " (inside %s)" % ", ".join(f.name for f in _in) if _in else ""))
            _created.append((_addr, _text, _in))  # created after the loop: neighbours first, before any change
            continue
        if not _f.symbol.auto and _own_placeholder(_f.name, _text):
            _count("R upgrade (own placeholder)")
            _note("apply", (_kind, _addr, _text), _f.name)
            if _apply:
                bv.define_user_symbol(_bn.Symbol(_bn.SymbolType.FunctionSymbol, _addr, _text))
            continue
        if not _f.symbol.auto:
            _count("R kept (named)")
            _note("keep", (_kind, _addr, _text), _f.name)
            continue
        if not _bn_name(_f):
            _count("R kept (binary symbol)")
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
if _apply and _created:
    for _addr, _text, _in in _created:
        _prev = bv.get_previous_function_start_before(_addr)
        for _n in _in + ([bv.get_function_at(_prev)] if _prev is not None else []):
            if _n is not None:
                _neighbours.setdefault(_n.start, _shape(_n))
    for _addr, _text, _in in _created:
        bv.create_user_function(_addr)
        bv.define_user_symbol(_bn.Symbol(_bn.SymbolType.FunctionSymbol, _addr, _text))
    bv.update_analysis_and_wait()
    _counts["R created, function there now"] = sum(1 for a, _t, _i in _created if bv.get_function_at(a) is not None)
    for _a, _was in sorted(_neighbours.items()):
        _n = bv.get_function_at(_a)
        _now = _shape(_n) if _n is not None else None
        if _now != _was:
            _count("R create: neighbour changed")
            _review.append("note  neighbour %#x %s: (start, bytes, blocks) %s -> %s" % (
                _a, _n.name if _n is not None else "-", _was, _now))
with open(_out[:-len(".directives")] + ".names.review", "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_review) + "\n")
print("%d typeinfos, %d directives -> %s (+ .names.review)" % (len(_types), len(_dirs), _out))
print("%s: %s (%.1f s)" % ("applied" if _apply else "dry run", ", ".join(
    "%s %d" % kv for kv in sorted(_counts.items())), time.time() - _t0))

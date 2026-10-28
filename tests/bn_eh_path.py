# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB FROM='0x10032b410|name|part*of*name[,…]' [TI='0x1009d0bb0|typeinfo_for_X[,…]'] \
#         [BASES=1] [VIRTUAL=0] [APPLY=1 [SAVE=1]] $B/bn --timeout 600 tests/bn_eh_path.py
# bncpp-24: what the functions at FROM throw, followed up the direct callers (cpp/eh_path.py): who catches it,
# where it terminates, where it leaves the known call graph. TI: the thrown typeinfos (default: the ones FROM passes
# to ___cxa_throw or to a function that only throws (bncpp-92), starting at those throw sites; none: unknown, every
# catch (T) is a 'may catch'). BASES=1: base classes from the class scan (slow on big binaries). VIRTUAL=0: direct
# callers only (default: also the virtual call sites of a function in a vtable, through the X::VTable members BN has
# references to and on dynamic_cast results -- cpp/eh_virtual.py, bncpp-66 / bncpp-95). Review:
# .scratch/eh/<binary>.path.review (the report, then one line per call site with the comment APPLY would set).
# CAST_BUDGET: seconds for the dynamic_cast callers not cached yet (default 120; SynthV: ~4.5 min in all, so a few
# runs -- the report says how many are done).
# APPLY=1 sets the comments (in RAM; never over another comment). NOCACHE=1: no bncache file (call graph and
# dynamic_cast callers computed in full; tests/bn_dump.py's .ehpath, which takes _lines).
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, os, re, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_p = _dev["pkgname"]
_ep = importlib.import_module(_p + ".cpp.eh_path")
_lp = importlib.import_module(_p + ".cpp.landing_pads")
_bnimage = importlib.import_module(_p + ".cpp.bnimage")
_cg = importlib.import_module(_p + ".shared.callgraph")
_cache = importlib.import_module(_p + ".shared.bncache")
_env = globals().get("env") or {}
_get = lambda k, d=None: _env.get(k) or os.environ.get(k) or d
_t0 = time.time()
_TYPEDEFS = [(re.compile(r"\b%s\b" % a), b) for a, b in (
    ("uint8_t", "unsigned char"), ("int8_t", "signed char"), ("uint16_t", "unsigned short"), ("int16_t", "short"),
    ("uint32_t", "unsigned int"), ("int32_t", "int"), ("uint64_t", "unsigned long"), ("int64_t", "long"))]


def _plain(n):
    """a symbol name without leading '_' and its trailing parameter list (balanced, so 'guarded_apply(int)::$_0::
    operator()(int) const' keeps the 'guarded_apply(int)' scope and the '()' of operator(), bncpp-118); BN's
    int32_t & co. as the source spells them"""
    n = n.lstrip("_").strip()
    for rx, b in _TYPEDEFS:
        n = rx.sub(b, n)
    while n.split(" ")[-1] in ("const", "volatile", "&", "&&", "noexcept") and " " in n:
        n = n.rsplit(" ", 1)[0]
    if not n.endswith(")") or n.endswith("operator()"):
        return n
    depth = 0
    for k in range(len(n) - 1, -1, -1):
        depth += {")": 1, "(": -1}.get(n[k], 0)
        if depth == 0:
            return n[:k] if n[:k] else n
    return n


def _matches(want, name):
    """want with '*' wildcards (the parts in order, anywhere in the name), else equal"""
    if "*" not in want:
        return want == name
    k = 0
    for part in want.split("*"):
        k = name.find(part, k)
        if k < 0:
            return False
        k += len(part)
    return want.endswith("*") or name.endswith(want.rsplit("*", 1)[1])


def _func_addr(a):
    """a hex address, or a function name (an import such as may_throw); '*' matches any text ('__func<schedule*
    operator()'); a name without '*' that is no symbol's full name is looked for as a part of one (unique only);
    'a|b': the first alternative that names a function"""
    if "|" in a:  # alternatives: the first that names a function
        for alt in a.split("|")[:-1]:
            try:
                return _func_addr(alt)
            except ValueError:
                pass
        return _func_addr(a.split("|")[-1])
    if a.startswith("0x"):
        return int(a, 16)
    # every symbol at the start, the auto one too: bn_class_apply.py's user name (Job::vfunc2) hides
    # Job::run (bncpp-99)
    names = lambda f, raw=True: set(_plain(n) for sym in bv.get_symbols(f.start)
                                    for n in ((sym.raw_name,) if raw else ()) + (sym.full_name, sym.short_name))
    want = _plain(a)
    funcs = sorted((f for f in bv.functions if any(_matches(want, n) for n in names(f))), key=lambda f: f.start)
    if not funcs and "*" not in want:
        funcs = sorted((f for f in bv.functions if any(want in n for n in names(f, False))), key=lambda f: f.start)
        if len(funcs) > 1:
            raise ValueError("FROM: %r is a part of %d functions' names, name one (or use '*'): %s" % (
                a, len(funcs), [sorted(names(f, False))[0] for f in funcs[:8]]))
    if not funcs:
        near = sorted(set(n for f in bv.functions for n in names(f, False)
                          if any(p in n for p in want.split("::") if p)))[:8]
        raise ValueError("FROM: no function %r (compared raw, full and short names of all symbols at a function "
                         "start, without leading '_' and the parameter list); similar: %s" % (a, near or "none"))
    if len(funcs) > 1:
        print("FROM %r: %d functions, took %#x %s" % (a, len(funcs), funcs[0].start, funcs[0].symbol.full_name))
    return funcs[0].start


def _split(text):
    """a comma list whose items may hold commas inside () / <> ('schedule(Worker*, int)::$_0::operator()')"""
    out, depth, cur = [], 0, ""
    for c in text:
        depth += {"(": 1, "<": 1, ")": -1, ">": -1}.get(c, 0)
        if c == "," and depth <= 0:
            out, cur = out + [cur], ""
        else:
            cur += c
    return [a.strip() for a in out + [cur] if a.strip()]


_from = [_func_addr(a) for a in _split(_get("FROM", ""))]
if not _from:
    raise ValueError("FROM: comma list of function addresses or names")
_ti = []
for t in (_get("TI") or "").split(","):
    t = t.strip()
    if t:
        _ti.append(int(t, 16) if t.startswith("0x") else t)
_sites = []
_img = _bnimage.BNImage(bv)
_thr = {}
if not _ti:  # what FROM throws: start at its throw sites (a throw in a catch body decides in its owner's table),
    _thr = _ep.throwers(bv, _img.demangle)  # calls to functions that only throw included (bncpp-92)
    for a in _from:
        f = bv.get_function_at(a)
        for site, t in (_ep.throw_sites(f, _thr) if f else []):
            _sites.append(site)
            _ti += [t] if t not in _ti else []
_cache_file = _cache.Cache(bv) if _get("NOCACHE") != "1" else None
_edges = _cg.edges(bv, _cache_file) if _cache_file is not None else [tuple(e) for e in _cg.build(bv)]
_bases = _ep.rtti_bases(_img) if _get("BASES") == "1" else None
_guards = [h.start for h, _t in _lp.terminate_helpers(bv)]
_vc = None
if _get("VIRTUAL", "1") != "0":
    _rtti = importlib.import_module(_p + ".cpp.rtti")
    _rn = importlib.import_module(_p + ".cpp.rtti_names")
    _ev = importlib.import_module(_p + ".cpp.eh_virtual")
    _types = _rtti.scan(_img)
    _vc = _ev.VirtualCallers(bv, _types, _rn.labels(_types, _img.demangle, _rn.label_overrides(_types, _img.symbol_at)),
                             _cache_file, float(_get("CAST_BUDGET", "120")) if _cache_file is not None else None)
_tr = _ep.Trace(bv, _img, _edges, _ti, _bases, _guards, _vc)
_tr.run(sites=_sites) if _sites else _tr.run(_from)
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = os.path.join(REPO, ".scratch/eh")
os.makedirs(_out, exist_ok=True)
_lines = ["thrown: %s; terminate helpers: %s; throwers: %d" % (
    ", ".join("%#x" % t if isinstance(t, int) else t for t in _ti) or "unknown",
    ", ".join("%#x" % g for g in _guards) or "none", len(_thr))]
_lines += _tr.report() + [""] + ["%#x %-10s %s" % (st.site, st.kind, _tr.comment(st)) for st in _tr.all_steps()]
if __name__ != "__bn_dump__":  # bn_dump.py's .ehpath takes _lines (bncpp-117)
    with open(os.path.join(_out, _name + ".path.review"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(_lines) + "\n")
    _done, _skipped = _tr.annotate(apply=_get("APPLY") == "1")
    print("\n".join(_tr.report()))
    if _vc is not None and _vc.cast_progress is not None and _vc.cast_progress[0] < _vc.cast_progress[1]:
        print("dynamic_cast callers: %d of %d analysed (CAST_BUDGET); run again for the rest" % _vc.cast_progress)
    print("%s %d comments, %d skipped (another comment there); review %s (%.1f s)" % (
        "set" if _get("APPLY") == "1" else "would set", _done, _skipped, os.path.join(_out, _name + ".path.review"),
        time.time() - _t0))
_e.finish(globals())  # SAVE=1 / SAVE=/abs/new.bndb persists APPLY's comments (tests/bn_engine.py)

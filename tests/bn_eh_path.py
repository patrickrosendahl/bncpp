# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 600 --env FROM=0x10032b410|name[,…] [--env TI=0x1009d0bb0|typeinfo_for_X[,…]] \
#         [--env BASES=1] [--env APPLY=1] tests/bn_eh_path.py
# bncpp-24: what the functions at FROM throw, followed up the direct callers (cpp/eh_path.py): who catches it,
# where it terminates, where it leaves the known call graph. TI: the thrown typeinfos (default: the ones FROM
# passes to ___cxa_throw, starting at those throw sites; none: unknown, every catch (T) is a 'may catch'). BASES=1: base classes from the class
# scan (slow on big binaries). Review: .scratch/eh/<binary>.path.review (the report, then one line per call site
# with the comment APPLY would set). APPLY=1 sets the comments (in RAM; never over another comment).
import importlib, os, time
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
def _func_addr(a):
    """a hex address, or a function name (an import such as may_throw)"""
    if a.startswith("0x"):
        return int(a, 16)
    plain = lambda n: n.lstrip("_").split("(")[0]  # '_may_throw', 'may_throw(int32_t)' -> 'may_throw'
    funcs = sorted((f for f in bv.functions if plain(f.name) == a or plain(f.symbol.full_name) == a),
                   key=lambda f: f.start)
    if not funcs:
        raise ValueError("FROM: no function %r" % a)
    return funcs[0].start


_from = [_func_addr(a.strip()) for a in _get("FROM", "").split(",") if a.strip()]
if not _from:
    raise ValueError("FROM: comma list of function addresses or names")
_ti = []
for t in (_get("TI") or "").split(","):
    t = t.strip()
    if t:
        _ti.append(int(t, 16) if t.startswith("0x") else t)
_sites = []
if not _ti:  # what FROM throws: start at its throw sites (a throw in a catch body decides in its owner's table)
    for a in _from:
        f = bv.get_function_at(a)
        for site, t in (_ep.throw_sites(f) if f else []):
            _sites.append(site)
            _ti += [t] if t not in _ti else []
_img = _bnimage.BNImage(bv)
_edges = _cg.edges(bv, _cache.Cache(bv))
_bases = _ep.rtti_bases(_img) if _get("BASES") == "1" else None
_guards = [h.start for h, _t in _lp.terminate_helpers(bv)]
_tr = _ep.Trace(bv, _img, _edges, _ti, _bases, _guards)
_tr.run(sites=_sites) if _sites else _tr.run(_from)
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = os.path.join(REPO, ".scratch/eh")
os.makedirs(_out, exist_ok=True)
_lines = ["thrown: %s; terminate helpers: %s" % (", ".join("%#x" % t if isinstance(t, int) else t for t in _ti) or
                                                 "unknown", ", ".join("%#x" % g for g in _guards) or "none")]
_lines += _tr.report() + [""] + ["%#x %-10s %s" % (st.site, st.kind, _tr.comment(st)) for st in _tr.steps]
with open(os.path.join(_out, _name + ".path.review"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(_lines) + "\n")
_done, _skipped = _tr.annotate(apply=_get("APPLY") == "1")
print("\n".join(_tr.report()))
print("%s %d comments, %d skipped (another comment there); review %s (%.1f s)" % (
    "set" if _get("APPLY") == "1" else "would set", _done, _skipped, os.path.join(_out, _name + ".path.review"),
    time.time() - _t0))

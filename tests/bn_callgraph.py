# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB $B/bn --timeout 300 tests/bn_callgraph.py            # the call graph, from the cache or built + cached
#   options: --env ASYNC=1 (build in the background task, wait for it), --env ADDR=0x... (callers / callees of one)
# shared/callgraph.py, cached per binary by shared/bncache.py (next to the database: <x>.bndb.bncpp-cache.json).
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, time
import binaryninja as _bn

_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_bncache = importlib.import_module(_dev["pkgname"] + ".shared.bncache")
_cg = importlib.import_module(_dev["pkgname"] + ".shared.callgraph")
_env = globals().get("env") or {}
_t0 = time.time()
_cache = _bncache.Cache(bv)
_from_cache = _cache.get("callgraph", _cg.VERSION) is not None
if _env.get("ASYNC") == "1":
    _got = []
    _task = _cg.edges_async(bv, _cache, _got.append)
    if _task is not None:
        _task.join()
    _edges = _got[0] if _got else None
else:
    _edges = _cg.edges(bv, _cache)
if _edges is None:
    raise RuntimeError("cancelled")
_callers, _callees = _cg.index(_edges)
print("%s: %d edges (%d unresolved sites), %d callers, %d callees -> %s (%.1f s)" % (
    "cache" if _from_cache else "built", len(_edges), sum(1 for e in _edges if e[2] is None), len(_callees),
    len(_callers), _cache.path, time.time() - _t0))
if _env.get("ADDR"):
    _a = int(_env["ADDR"], 0)
    for _site, _c in sorted(_callers.get(_a, [])):
        print("  caller %#x at %#x %s" % (_c, _site, bv.get_function_at(_c).name if bv.get_function_at(_c) else ""))
    for _site, _c in sorted(_callees.get(_a, []), key=lambda x: x[0]):
        _f = bv.get_function_at(_c) if _c is not None else None
        print("  callee %s at %#x %s" % ("%#x" % _c if _c is not None else "?", _site, _f.name if _f else ""))

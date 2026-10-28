# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB RANGE=0x100320000:0x100340000 [OUT=DIR] [BUDGET=S] $B/bn --timeout 900 tests/bn_eh_cluster.py
#   python3 tests/suite/suite.py survey DIR       # check's counters on the result (bncpp-175)
# The exception handling of one address range of a real binary, as the suite dump does it for a test (bncpp-170 /
# bncpp-175: SynthV's license cluster): the landing pads of the range's LSDA owners and of the functions BN types
# __noreturn although they catch (cpp/landing_pads.returning_todo) get functions, those are marked returning (in
# rounds, with the pads of the code that became reachable), then every owner in the range is written in Pseudo C
# and Pseudo Cpp to DIR/cluster.{pc,pcpp}, its table to DIR/cluster.lsda, and DIR/cluster.catches lists the owners
# with a catch clause that is no terminate guard (survey's missing_try counts only those).
# In RAM only (never saved). DIR default: .scratch/eh/<binary>.cluster-<lo>. BUDGET (default 600 s): pad creation
# stops there; the rendering always runs.
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, os, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = _bn._cpp_dev
_M = lambda n: importlib.import_module(_dev["pkgname"] + ".cpp." + n)
_pc, _lp, _lsda, _bnimage, _er, _ec = (_M(n) for n in ("pseudo_cpp", "landing_pads", "lsda", "bnimage", "eh_render",
                                                       "eh_comments"))
_env = globals().get("env") or {}
_get = lambda k, d=None: _env.get(k) or os.environ.get(k) or d
_lo, _hi = (int(x, 0) for x in _get("RANGE", "").split(":")) if _get("RANGE") else (None, None)
if _lo is None:
    raise ValueError("RANGE=lo:hi (addresses)")
_budget = float(_get("BUDGET", "600"))
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = _get("OUT") or os.path.join(REPO, ".scratch/eh/%s.cluster-%x" % (_name, _lo))
os.makedirs(_out, exist_ok=True)
_t0 = time.time()
_img = _bnimage.BNImage(bv)
_tables = _lsda.parse_all(_img)
_owners = sorted(a for a in _tables if _lo <= a < _hi)
_counts = {"owners": len(_owners)}


def _pads_todo():
    # the range's owners, and the __noreturn functions that catch (their pads decide returning_todo)
    want = set(_owners) | {a for a, t in _tables.items() if bv.get_function_at(a) is not None
                           and not bv.get_function_at(a).can_return.value}
    return [p for p in _lp.pads(bv) if p.owner in want and bv.get_function_at(p.addr) is None]


_todo = _pads_todo()
_counts["pads without a function"] = len(_todo)
_made = 0
while _todo and time.time() - _t0 < _budget:
    _chunk, _todo = _todo[:200], _todo[200:]
    _made += len(_lp.create(bv, _chunk))
_counts["pads created"] = _made
_counts["pads left (budget)"] = len(_todo)
_returning = []
for _round in range(4):
    _rt = _lp.returning_todo(bv)
    if not _rt or time.time() - _t0 > _budget:
        break
    _returning += _lp.mark_returning(bv, _rt)
    _more = _pads_todo()
    _counts["pads created"] += len(_lp.create(bv, _more))
_counts["marked returning"] = len(_returning)
_texts = {"pc": [], "pcpp": [], "lsda": [], "catches": []}
_ix = _ec.index(bv)
for _o in _owners:
    _f = bv.get_function_at(_o)
    _t = _tables[_o]
    _texts["lsda"] += _lsda.format_lsda(_t, _img.symbol_name(_o), _img.segment_start(_o)) + [""]
    if _f is None:
        continue
    for _cs in _t.call_sites:
        _c = [c for c in _cs.clauses if c.kind == c.CATCH]
        if _cs.landing_pad is not None and _c and not (
                all(c.type is None for c in _c) and _er.is_terminate_guard(bv, _cs.landing_pad, _ix.guards)):
            _texts["catches"].append(_f.symbol.full_name)
            break
    for _key, _language in (("pc", "Pseudo C"), ("pcpp", _dev["LANGUAGE_NAME"])):
        _texts[_key].append("// %s @ %#x" % (_f.symbol.full_name, _f.start))
        try:
            _texts[_key].extend(_pc.render_function(_f, _language))
        except Exception as _ex:
            _texts[_key].append("// render failed: %r" % (_ex,))
        _texts[_key].append("")
    del _f
for _key, _lines in _texts.items():
    with open(os.path.join(_out, "cluster." + _key), "w", encoding="utf-8") as _fh:
        _fh.write("\n".join(_lines) + "\n")
print("returning: %s" % ", ".join("%#x %s" % (f.start, f.name) for f in _returning))
print("%s: %s (%.0f s)" % (_out, ", ".join("%s %d" % kv for kv in _counts.items()), time.time() - _t0))

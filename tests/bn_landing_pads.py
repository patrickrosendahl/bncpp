# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB $B/bn --timeout 600 tests/bn_landing_pads.py                 # dry run: review file only
#   BNDB=DB APPLY=1 $B/bn --timeout 600 tests/bn_landing_pads.py   # create them (in RAM; + SAVE=1: into DB)
#   BNDB=DB APPLY=noreturn $B/bn --timeout 600 tests/bn_landing_pads.py   # only bncpp-52's marks, recount
#   … APPLY=1 PADS=0:2000 …   # create only that slice of the pads still to create (bncpp-54: chunks)
#   … APPLY=returning …        # after the last slice: only bncpp-175's returning marks (+ the pads they reach)
# bncpp-4: a user function at every LSDA landing pad that no function starts at (cpp/landing_pads.py), so the
# handler code is in a view. Review: .scratch/eh/<binary>.pads.review, one line per pad:
#   create|keep  pad  owner  clauses  [now: in no function | inside <function>]
# bncpp-52, first: 'terminate helper' lines, 'padded calls' lines (bncpp-62: imports called last before padding)
# and 'noreturn' lines for the helpers / terminate callees / padded imports APPLY marks
# __noreturn (never over a user type; BASELINE=F as bn_class_types.py: only over a type BN inferred).
# bncpp-175, last: 'returning' lines -- LSDA owners BN types __noreturn although a catch pad of theirs returns (they
# return only from their own catch; BN cuts their callers off after the call). Judged from the pad functions, so a
# dry run lists the candidates ('returning?': __noreturn with a catch clause that is no terminate guard) and APPLY=1 (without PADS) or
# APPLY=returning marks them (a returning user type, never over can_return at full confidence) and creates the
# pads of the code that became reachable, in rounds.
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, os, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_lp = importlib.import_module(_dev["pkgname"] + ".cpp.landing_pads")
_env = globals().get("env") or {}
_mode = _env.get("APPLY") or os.environ.get("APPLY") or ""
_apply = _mode == "1"
_mark = _mode in ("1", "noreturn")  # APPLY=noreturn: only the terminate helpers, then the counts again
_returning = _mode == "returning" or (_apply and not _env.get("PADS"))
_t0 = time.time()
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name


def _fname(a):
    s = bv.get_symbol_at(a)
    return s.full_name if s is not None else "%#x" % a


# bncpp-52: terminate helpers first (their guards become pads of their own once BN knows they do not return)
_helpers = _lp.terminate_helpers(bv)
_baseline = None
if _env.get("BASELINE"):
    import json
    with open(_env["BASELINE"], encoding="utf-8") as _fh:
        _baseline = json.load(_fh)


def _protected(f):
    return f.has_user_type and (_baseline is None or _baseline.get("%#x" % f.start) != str(f.type))


_marks = _lp.noreturn_todo(bv, _protected)
_head = ["terminate helper %#x %s -> %s %#x  [can_return: %s / %s]" % (
    h.start, h.name, t.name, t.start, h.can_return.value, t.can_return.value) for h, t in _helpers]
_padded = _lp.padded_calls(bv)
_head += ["padded calls %#x %s  [%d of %d call sites]" % (f.start, f.name, n, m) for f, n, m in _padded]
_head += ["noreturn %#x %s   [now: %s]" % (f.start, f.name, f.type) for f in _marks]
if _mark:
    _lp.mark_noreturn(bv, _marks)
_all = _lp.pads(bv)
_todo = [p for p in _all if bv.get_function_at(p.addr) is None]
_counts = {"terminate helpers": len(_helpers), "padded imports": len(_padded), "to mark noreturn": len(_marks),
           "pads": len(_all), "pads with a function": len(_all) - len(_todo), "to create": len(_todo),
           "in no function": 0, "inside another function": 0}
_review = []
for _p in _all:
    _in = bv.get_functions_containing(_p.addr)
    _now = "function here" if bv.get_function_at(_p.addr) is not None else \
        "inside " + ", ".join(f.symbol.full_name for f in _in) if _in else "in no function"
    if _now != "function here":
        _counts["in no function" if not _in else "inside another function"] += 1
    _review.append("%s %#x  owner %s  %s   [now: %s]" % ("create" if _now != "function here" else "keep  ",
                                                         _p.addr, _fname(_p.owner), _p.kinds, _now))
if _apply:
    _chunk = _todo
    if _env.get("PADS"):  # a slice of the pads to create, by index into the todo list: short runs (bncpp-54)
        _a, _b = (int(x) if x else None for x in _env["PADS"].split(":"))
        _chunk = _todo[_a:_b]
    _t1 = time.time()
    _made = _lp.create(bv, _chunk)
    _counts["created"] = sum(1 for p in _made if bv.get_function_at(p.addr) is not None)
    _counts["create + analysis s"] = int(time.time() - _t1)
    _counts["functions now"] = len(bv.functions)
_er = importlib.import_module(_dev["pkgname"] + ".cpp.eh_render")
_guards = importlib.import_module(_dev["pkgname"] + ".cpp.eh_comments").index(bv).guards
_cands = []
for _o, _t in sorted(_lp._lsda.parse_all(_lp.BNImage(bv)).items()):
    _f = bv.get_function_at(_o)
    if _f is None or _f.can_return.value:
        continue
    for _cs in _t.call_sites:
        _c = [c for c in _cs.clauses if c.kind == "catch"]
        if _cs.landing_pad is not None and _c and not (
                all(c.type is None for c in _c) and _er.is_terminate_guard(bv, _cs.landing_pad, _guards)):
            _cands.append(_f)
            break
_counts["returning candidates"] = len(_cands)
_head += ["returning? %#x %s  [now: %s, can_return confidence %d]" % (f.start, f.name, f.type, f.can_return.confidence)
          for f in _cands]
if _returning:
    _t1 = time.time()
    _rounds = []
    for _round in range(4):
        _rt = _lp.returning_todo(bv)
        if not _rt:
            break
        _head += ["returning %#x %s -> %s  [round %d]" % (f.start, f.name, ret, _round + 1) for f, ret in _rt]
        _lp.mark_returning(bv, _rt)
        _rounds.append((len(_rt), len(_lp.create(bv))))
    _counts["marked returning"] = sum(n for n, _ in _rounds)
    _counts["pads created after them"] = sum(m for _, m in _rounds)
    _counts["returning s"] = int(time.time() - _t1)
    _counts["functions now"] = len(bv.functions)
_rv = os.path.join(REPO, ".scratch/eh/%s.pads.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_head + _review) + "\n")
print("review -> %s" % _rv)
print("%s: %s (%.1f s)" % ("applied" if _apply else "noreturn marked" if _mark else "dry run",
                           ", ".join("%s %d" % kv for kv in _counts.items()),
                           time.time() - _t0))
_e.finish(globals())  # SAVE=1 / SAVE=/abs/new.bndb persists the view's changes (tests/bn_engine.py)

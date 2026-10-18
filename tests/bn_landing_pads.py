# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 600 tests/bn_landing_pads.py                 # dry run: review file only
#   bnrun --bndb DB --timeout 600 --env APPLY=1 tests/bn_landing_pads.py   # create them (in RAM), then save PATH
#   bnrun --bndb DB --timeout 600 --env APPLY=noreturn tests/bn_landing_pads.py   # only bncpp-52's marks, recount
# bncpp-4: a user function at every LSDA landing pad that no function starts at (cpp/landing_pads.py), so the
# handler code is in a view. Review: .scratch/eh/<binary>.pads.review, one line per pad:
#   create|keep  pad  owner  clauses  [now: in no function | inside <function>]
# bncpp-52, first: 'terminate helper' lines, 'padded calls' lines (bncpp-62: imports called last before padding)
# and 'noreturn' lines for the helpers / terminate callees / padded imports APPLY marks
# __noreturn (never over a user type; --env BASELINE=F as bn_class_types.py: only over a type BN inferred).
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
    _made = _lp.create(bv, _todo)
    _counts["created"] = sum(1 for p in _made if bv.get_function_at(p.addr) is not None)
_rv = os.path.join(REPO, ".scratch/eh/%s.pads.review" % _name)
os.makedirs(os.path.dirname(_rv), exist_ok=True)
with open(_rv, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_head + _review) + "\n")
print("review -> %s" % _rv)
print("%s: %s (%.1f s)" % ("applied" if _apply else "noreturn marked" if _mark else "dry run",
                           ", ".join("%s %d" % kv for kv in _counts.items()),
                           time.time() - _t0))

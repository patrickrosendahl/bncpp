# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 600 [--env N=100] [--env TAG=before] tests/bn_eh_sample.py
# bncpp-54: what landing-pad functions buy in the Pseudo Cpp view, measured on a fixed sample: every k-th function
# with an LSDA that has a catch clause (N of them, by address). Per function: try blocks placed, catch clauses whose
# landing pad is in no function, clauses shown as the whole pad (dispatch not found), render time. Writes
# .scratch/eh/<binary>.sample.<TAG> (one line per function, then the totals) and prints the totals.
import importlib, os, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_pc = _dev["pseudo_cpp"]
_lang = _dev["LANGUAGE_NAME"]
_lsda = importlib.import_module(_dev["pkgname"] + ".cpp.lsda")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_env = globals().get("env") or {}
_n = int(_env.get("N") or 100)
_tag = _env.get("TAG") or "sample"
_t0 = time.time()
_owners = sorted(a for a, t in _lsda.parse_all(_bnimage.BNImage(bv)).items()
                 if any(c.kind == c.CATCH for cs in t.call_sites for c in cs.clauses))
_step = max(1, len(_owners) // _n)
_sample = _owners[::_step][:_n]
_rows, _tot = [], {"functions": 0, "no function": 0, "try": 0, "pad in no function": 0, "whole pad": 0,
                   "render s": 0.0}
for a in _sample:
    f = bv.get_function_at(a)
    if f is None:
        _rows.append("%#x no function" % a)
        _tot["no function"] += 1
        continue
    t1 = time.time()
    try:
        text = _pc.render_function(f, _lang)
    except Exception as ex:
        text = ["// render failed: %r" % (ex,)]
    dt = time.time() - t1
    c = {"try": sum(1 for l in text if l.strip() == "try"),
         "pad in no function": sum("is in no function" in l for l in text),
         "whole pad": sum("dispatch on the selector was not found" in l for l in text)}
    _tot["functions"] += 1
    _tot["render s"] += dt
    for k, v in c.items():
        _tot[k] += v
    _rows.append("%#x %-40s try %d  pad in no function %d  whole pad %d  %.2f s" % (
        a, f.symbol.full_name[:40], c["try"], c["pad in no function"], c["whole pad"], dt))
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = os.path.join(REPO, ".scratch/eh/%s.sample.%s" % (_name, _tag))
os.makedirs(os.path.dirname(_out), exist_ok=True)
_summary = "owners with a catch: %d, sampled every %d: %s (%.1f s)" % (
    len(_owners), _step, ", ".join("%s %s" % (k, ("%.1f" % v) if isinstance(v, float) else v)
                                   for k, v in _tot.items()), time.time() - _t0)
with open(_out, "w", encoding="utf-8") as fh:
    fh.write("\n".join(_rows + ["", _summary]) + "\n")
print(_summary)
print("->", _out)

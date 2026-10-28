# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB ADDRS=0x10015d610,0x10032b410 [PADS=1] [OUT=DIR] $B/bn --timeout 300 tests/bn_render.py
# Writes the functions at ADDRS in the latest dev-loaded Pseudo Cpp and in Pseudo C to OUT/<addr>.{pcpp,pc}
# (default .scratch/render/<binary>/), plus OUT/<addr>.lsda (the decoded exception table, if any). For acceptance
# cases in large databases (bncpp-19), where the suite dump's view-wide steps are too slow.
# PADS=1 first creates a user function at each landing pad of these functions that has none (cpp/landing_pads.py,
# only these owners' pads; in RAM -- the database changes only on a save, which this script never does).
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
_pc = _dev["pseudo_cpp"]
_lang = _dev["LANGUAGE_NAME"]
_lsda = importlib.import_module(_dev["pkgname"] + ".cpp.lsda")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_env = globals().get("env") or {}
_get = lambda k, d=None: _env.get(k) or os.environ.get(k) or d
_addrs = [int(a, 16) for a in _get("ADDRS", "").split(",") if a.strip()]
if not _addrs:
    raise ValueError("ADDRS: comma list of function addresses")
_name = os.path.basename(bv.file.original_filename)
_name = _name[:-5] if _name.endswith(".bndb") else _name
_out = _get("OUT") or os.path.join(REPO, ".scratch/render", _name)
os.makedirs(_out, exist_ok=True)
_t0 = time.time()
_img = _bnimage.BNImage(bv)

_tables = {}
for a in _addrs:
    t = _lsda.parse_function(_img, a)
    if t is not None:
        _tables[a] = t
        with open(os.path.join(_out, "%x.lsda" % a), "w", encoding="utf-8") as fh:
            fh.write("\n".join(_lsda.format_lsda(t, _img.symbol_name(a), _img.segment_start(a))) + "\n")

if _get("PADS") == "1":
    todo = sorted({cs.landing_pad for t in _tables.values() for cs in t.call_sites
                   if cs.landing_pad is not None and bv.get_function_at(cs.landing_pad) is None})
    for p in todo:
        bv.create_user_function(p)
    if todo:
        bv.update_analysis_and_wait()
    print("pads created: %d (%s)" % (len(todo), ", ".join("%#x" % p for p in todo)))

for a in _addrs:
    f = bv.get_function_at(a)
    if f is None:
        print("%#x: no function" % a)
        continue
    for ext, lang in (("pcpp", _lang), ("pc", "Pseudo C")):
        try:
            lines = _pc.render_function(f, lang)
        except Exception as ex:
            lines = ["// render failed: %r" % (ex,)]
        with open(os.path.join(_out, "%x.%s" % (a, ext)), "w", encoding="utf-8") as fh:
            fh.write("// %s @ %#x\n%s\n" % (f.symbol.full_name, a, "\n".join(lines)))
    print("%#x %s: %d call sites with a pad" % (a, f.symbol.full_name, sum(
        cs.landing_pad is not None for cs in _tables[a].call_sites) if a in _tables else 0))
print("out: %s (%.1f s)" % (_out, time.time() - _t0))

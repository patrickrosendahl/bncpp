# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --parallel --timeout 600 tests/bn_dump.py
#   bnrun --parallel --timeout 300 --env DUMP_KINDS=lsda tests/bn_dump.py   # only some kinds (comma list)
#   bnrun --parallel --timeout 300 --env DUMP_TESTS=TestVirtual tests/bn_dump.py   # only test names starting so
#   bnrun --parallel --timeout 300 --env DUMP_VARIANTS=x86_64-O2,arm64-O2 tests/bn_dump.py   # only these variants
#   bnrun --parallel --timeout 600 --env RESUME=1 tests/bn_dump.py   # skip binaries already dumped by this dev
#          load: all requested outputs carry the current stamp -- continues a dump the bridge timeout cut off
# Opens every suite binary (tests/suite/bin/<variant>/TestX.dylib) in its own (non-UI) view, creates a function at
# every landing pad BN has none at (cpp/landing_pads.py, bncpp-4; serially, bncpp-124) and writes into
# .scratch/suite/out/<variant>/TestX.*:
#   .pcpp  each function in __text / .text in the latest dev-loaded Pseudo Cpp (checked by tests/suite/suite.py)
#   .pc    the same functions in Pseudo C (for comparison)
#   .lsda  the decoded exception tables, read through BN (cpp/bnimage.py; checked, and cross-checked against
#          the offline reference of `suite.py ref-lsda`)
#   .classes  the class scan (cpp/rtti.py through cpp/bnimage.py) with BN's names of the slot functions, then
#          the names cpp/rtti_names.py gives (checked)
#   .fields   the class structs after the whole class pipeline with APPLY in this throwaway view
#          (tests/bn_class_apply.py, bn_class_types.py, bn_class_fields.py NOCACHE=1): counts, then the layouts
#          (cpp/rtti_fields.py; checked), with NAMES=tests/suite/src/<TestX>.names where that exists; then the
#          catch handlers' object variables (tests/bn_catch_types.py APPLY, where a clause catches a class of the
#          scan; bncpp-28). Runs after the others: it changes the view's names and types
#   .ehpath   for the tests in suite.py's EH_PATHS, after the class pipeline (run for it if .fields is not
#          dumped): the exception path from each listed function (tests/bn_eh_path.py NOCACHE=1, its review lines;
#          bncpp-117)
# Every output gets a stamp in out/<variant>/.stamps.json (plugin / scripts / input hashes, tests/suite/suite.py;
# bncpp-134): compare and check warn on outputs from mixed or stale sources.
# Prepend DUMP_BINARIES = [...] to dump other files (output: .scratch/suite/out/other/).
import glob, importlib, importlib.util, os, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_pc = _dev["pseudo_cpp"]
_lang = _dev["LANGUAGE_NAME"]
_lsda = importlib.import_module(_dev["pkgname"] + ".cpp.lsda")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_rtti_names = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_names")
_lp = importlib.import_module(_dev["pkgname"] + ".cpp.landing_pads")
_opt = lambda key: (globals().get("env") or {}).get(key) or os.environ.get(key)
_kinds_arg = _opt("DUMP_KINDS") or "pc,pcpp,lsda,classes,fields,ehpath"
_kinds = [k.strip() for k in _kinds_arg.split(",") if k.strip()]
if set(_kinds) - {"pc", "pcpp", "lsda", "classes", "fields", "ehpath"}:
    raise ValueError("DUMP_KINDS: unknown kind in %r" % _kinds_arg)
_bins = globals().get("DUMP_BINARIES") or sorted(glob.glob(os.path.join(REPO, "tests/suite/bin/*/*.dylib")))
_only = _opt("DUMP_TESTS")
if _only:
    _bins = [b for b in _bins if any(os.path.basename(b).startswith(p) for p in _only.split(","))]
_variants = _opt("DUMP_VARIANTS")
if _variants:
    _bins = [b for b in _bins if os.path.basename(os.path.dirname(b)) in _variants.split(",")]
_resume = _opt("RESUME") == "1"
_out = os.path.join(REPO, ".scratch/suite/out")
_spec = importlib.util.spec_from_file_location("_suite", os.path.join(REPO, "tests/suite/suite.py"))
_suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_suite)
_stamp = {"plugin": _suite.plugin_hash(_dev["pkg"].__path__[0]), "scripts": _suite.scripts_hash(), "dev": _lang}


def _render(func, language):
    try:
        return _pc.render_function(func, language)
    except Exception as ex:
        return ["// render failed: %r" % (ex,)]


def _dump_lsda(bv):
    img = _bnimage.BNImage(bv)
    lines = []
    for start, table in sorted(_lsda.parse_all(img).items()):
        lines += _lsda.format_lsda(table, img.symbol_name(start), img.segment_start(start)) + [""]
    return lines[:-1] if lines else ["no LSDA"]  # tables separated by an empty line


def _dump_classes(bv):
    img = _bnimage.BNImage(bv)
    types = _rtti.scan(img)
    if not types:
        return ["no typeinfo"]
    lines = _rtti.format_scan(types, img.symbol_name) + ["", "names (cpp/rtti_names.py; now: BN's name)"]
    for kind, addr, text in _rtti_names.directives(types, img.demangle, img.call_targets):
        now = img.symbol_name(addr) if kind != "C" else None
        lines.append("%s %#x %s%s" % (kind, addr, text, "   [now: %s]" % now if now and now != text else ""))
    return lines


def _dump_fields(bv, binary):
    if not _rtti.scan(_bnimage.BNImage(bv)):
        return ["no typeinfo"]
    env = {"APPLY": "1", "NOCACHE": "1"}
    names = os.path.join(REPO, "tests/suite/src", os.path.splitext(os.path.basename(binary))[0] + ".names")
    if os.path.exists(names):  # field names like another session's schema (bncpp-59)
        env["NAMES"] = names
    g = {}
    for script in ("bn_class_apply.py", "bn_class_types.py", "bn_class_fields.py"):
        g = {"__name__": "__bn_dump__", "bv": bv, "CPP_REPO": REPO, "env": dict(env)}
        path = os.path.join(REPO, "tests", script)
        with open(path, encoding="utf-8") as fh:
            exec(compile(fh.read(), path, "exec"), g)
    lines = ["%s %d" % kv for kv in sorted(g["_counts"].items()) if not kv[0].startswith("s ")]  # no timings
    params = [line for line, _what in sorted(g["_param_review"].values())]  # bncpp-28
    lines += [g["_unsettled"]] if g.get("_unsettled") else []  # bncpp-60: suite.py check gates on it
    out = lines + [""] + g["_fields"].format_layouts(g["_lays"]) + ([""] + params if params else [])
    # bncpp-28 source 4: the catch handlers' object variables, after the class structs exist
    c = {"__name__": "__bn_dump__", "bv": bv, "CPP_REPO": REPO, "env": {"APPLY": "1"}}
    path = os.path.join(REPO, "tests", "bn_catch_types.py")
    with open(path, encoding="utf-8") as fh:
        exec(compile(fh.read(), path, "exec"), c)
    if c["_counts"].get("catch clauses: a class of the scan"):
        out += [""] + ["%s %d" % kv for kv in sorted(c["_counts"].items())] + c["_review"]
    return out


def _dump_ehpath(bv, froms):
    out = []
    for a in froms:
        g = {"__name__": "__bn_dump__", "bv": bv, "CPP_REPO": REPO, "env": {"FROM": a, "NOCACHE": "1"}}
        path = os.path.join(REPO, "tests", "bn_eh_path.py")
        try:
            with open(path, encoding="utf-8") as fh:
                exec(compile(fh.read(), path, "exec"), g)
            lines = g["_lines"]
        except ValueError as ex:  # FROM names no function
            lines = ["error: %s" % ex]
        out += (["== FROM %s" % a] + lines + [""])
    return out[:-1]


_ok = _skipped = 0
for _path in _bins:
    _variant = os.path.basename(os.path.dirname(_path)) \
        if os.path.dirname(os.path.dirname(_path)) == os.path.join(REPO, "tests/suite/bin") else "other"
    _base = os.path.splitext(os.path.basename(_path))[0]
    _dir = os.path.join(_out, _variant)
    _want = dict(_stamp, input=_suite.input_hash(_path))
    _froms = _suite.EH_PATHS.get(_base) if "ehpath" in _kinds else None
    if _resume:
        _have = _suite.read_stamps(_dir).get(_base, {})
        if all(os.path.exists(os.path.join(_dir, "%s.%s" % (_base, k))) and _have.get(k, {}).get(k2) == x
               for k in _kinds if k != "ehpath" or _froms for k2, x in _want.items() if k2 != "dev"):
            _skipped += 1
            continue
    _bv = _bn.load(_path)
    try:
        # bncpp-4/52: the landing pads BN did not make functions, so their handlers are dumped too; one at a time, or
        # BN's parallel analysis of pads that share a tail splits it off in some runs only (bncpp-124)
        _lp.recover(_bv, serial=True)
        _texts = {}
        _views = [(k, l) for k, l in (("pc", "Pseudo C"), ("pcpp", _lang)) if k in _kinds]
        if _views:
            _text = _bv.sections.get("__text") or _bv.sections.get(".text")
            for _key, _ in _views:
                _texts[_key] = []
            for _f in sorted(_bv.functions, key=lambda f: f.start):
                if _text is not None and not (_text.start <= _f.start < _text.end):
                    continue
                for _key, _language in _views:
                    _texts[_key].append("// %s @ %#x" % (_f.symbol.full_name, _f.start))
                    _texts[_key].extend(_render(_f, _language))
                    _texts[_key].append("")
        if "lsda" in _kinds:
            _texts["lsda"] = _dump_lsda(_bv)
        if "classes" in _kinds:
            _texts["classes"] = _dump_classes(_bv)
        if "fields" in _kinds or _froms:  # after the others: changes the view
            _f = _dump_fields(_bv, _path)
            if "fields" in _kinds:
                _texts["fields"] = _f
        if _froms:  # after the class pipeline (bncpp-117)
            _texts["ehpath"] = _dump_ehpath(_bv, _froms)
        os.makedirs(_dir, exist_ok=True)
        for _key, _lines in _texts.items():
            with open(os.path.join(_dir, "%s.%s" % (_base, _key)), "w", encoding="utf-8") as _fh:
                _fh.write("\n".join(_lines) + "\n")
        _at = time.strftime("%Y-%m-%dT%H:%M:%S")
        _suite.write_stamps(_dir, _base, {k: dict(_want, at=_at) for k in _texts})
        _ok += 1
    finally:
        _bv.file.close()
print("dumped %s of %d of %d binaries into %s%s" % ("+".join(_kinds), _ok, len(_bins), _out,
                                                     " (%d already current: RESUME)" % _skipped if _skipped else ""))

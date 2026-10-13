# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --parallel --timeout 600 tests/bn_dump.py
#   bnrun --parallel --timeout 300 --env DUMP_KINDS=lsda tests/bn_dump.py   # only some kinds (comma list)
# Opens every suite binary (tests/suite/bin/<variant>/TestX.dylib) in its own (non-UI) view and writes into
# .scratch/suite/out/<variant>/TestX.*:
#   .pcpp  each function in __text / .text in the latest dev-loaded Pseudo Cpp (checked by tests/suite/suite.py)
#   .pc    the same functions in Pseudo C (for comparison)
#   .lsda  the decoded exception tables, read through BN (cpp/bnimage.py; checked, and cross-checked against
#          the offline reference of `suite.py ref-lsda`)
# Prepend DUMP_BINARIES = [...] to dump other files (output: .scratch/suite/out/other/).
import glob, importlib, os
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_pc = _dev["pseudo_cpp"]
_lang = _dev["LANGUAGE_NAME"]
_lsda = importlib.import_module(_dev["pkgname"] + ".cpp.lsda")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_kinds_arg = (globals().get("env") or {}).get("DUMP_KINDS") or os.environ.get("DUMP_KINDS") or "pc,pcpp,lsda"
_kinds = [k.strip() for k in _kinds_arg.split(",") if k.strip()]
if set(_kinds) - {"pc", "pcpp", "lsda"}:
    raise ValueError("DUMP_KINDS: unknown kind in %r" % _kinds_arg)
_bins = globals().get("DUMP_BINARIES") or sorted(glob.glob(os.path.join(REPO, "tests/suite/bin/*/*.dylib")))
_out = os.path.join(REPO, ".scratch/suite/out")


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


_ok = 0
for _path in _bins:
    _variant = os.path.basename(os.path.dirname(_path)) if "DUMP_BINARIES" not in globals() else "other"
    _bv = _bn.load(_path)
    try:
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
        _dir = os.path.join(_out, _variant)
        os.makedirs(_dir, exist_ok=True)
        _base = os.path.splitext(os.path.basename(_path))[0]
        for _key, _lines in _texts.items():
            with open(os.path.join(_dir, "%s.%s" % (_base, _key)), "w") as _fh:
                _fh.write("\n".join(_lines) + "\n")
        _ok += 1
    finally:
        _bv.file.close()
print("dumped %s of %d of %d binaries into %s" % ("+".join(_kinds), _ok, len(_bins), _out))

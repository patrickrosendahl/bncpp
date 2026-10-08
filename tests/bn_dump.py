# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --parallel --timeout 600 tests/bn_dump.py
# Opens every suite binary (tests/suite/bin/<variant>/TestX.dylib) in its own (non-UI) view and renders each
# function in __text / .text in the latest dev-loaded Pseudo Cpp (.pcpp, checked by tests/suite/suite.py) and
# in Pseudo C (.pc, for comparison) into .scratch/suite/out/<variant>/TestX.*.
# Prepend DUMP_BINARIES = [...] to dump other files (output: .scratch/suite/out/other/).
import glob, os
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None:
    raise RuntimeError("run tests/bn_dev_load.py first")
_pc = _dev["pseudo_cpp"]
_lang = _dev["LANGUAGE_NAME"]
_bins = globals().get("DUMP_BINARIES") or sorted(glob.glob(os.path.join(REPO, "tests/suite/bin/*/*.dylib")))
_out = os.path.join(REPO, ".scratch/suite/out")


def _render(func, language):
    try:
        return _pc.render_function(func, language)
    except Exception as ex:
        return ["// render failed: %r" % (ex,)]


_ok = 0
for _path in _bins:
    _variant = os.path.basename(os.path.dirname(_path)) if "DUMP_BINARIES" not in globals() else "other"
    _bv = _bn.load(_path)
    try:
        _texts = {"pc": [], "pcpp": []}
        _text = _bv.sections.get("__text") or _bv.sections.get(".text")
        for _f in sorted(_bv.functions, key=lambda f: f.start):
            if _text is not None and not (_text.start <= _f.start < _text.end):
                continue
            for _key, _language in (("pc", "Pseudo C"), ("pcpp", _lang)):
                _texts[_key].append("// %s @ %#x" % (_f.symbol.full_name, _f.start))
                _texts[_key].extend(_render(_f, _language))
                _texts[_key].append("")
        _dir = os.path.join(_out, _variant)
        os.makedirs(_dir, exist_ok=True)
        _base = os.path.splitext(os.path.basename(_path))[0]
        for _key, _lines in _texts.items():
            with open(os.path.join(_dir, "%s.%s" % (_base, _key)), "w") as _fh:
                _fh.write("\n".join(_lines) + "\n")
        _ok += 1
    finally:
        _bv.file.close()
print("dumped %d of %d binaries into %s" % (_ok, len(_bins), _out))

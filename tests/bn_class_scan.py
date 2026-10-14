# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb BINARY_OR_BNDB --timeout 300 tests/bn_class_scan.py [-- OUT]
# The class scan (cpp/rtti.py) through BN (cpp/bnimage.py): every typeinfo with its name, bases and vtables, as
# text into OUT (default .scratch/classes/<binary>.bn.classes). Slots are plain addresses so that the output
# compares with the offline reference (tests/ref_class_scan.py --out) line by line.
import importlib, os, sys, time
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")

_t0 = time.time()
_name = os.path.basename(bv.file.original_filename)
if _name.endswith(".bndb"):
    _name = _name[:-5]
_out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, ".scratch/classes/%s.bn.classes" % _name)
_types = _rtti.scan(_bnimage.BNImage(bv))
os.makedirs(os.path.dirname(_out), exist_ok=True)
with open(_out, "w", encoding="utf-8") as _fh:
    _fh.write("\n".join(_rtti.format_scan(_types)) + "\n")
_kinds = {}
for _t in _types.values():
    _kinds[(_t.kind, _t.kind_from)] = _kinds.get((_t.kind, _t.kind_from), 0) + 1
print("%d typeinfos %s, %d with vtables -> %s (%.1f s)" % (
    len(_types), sorted(_kinds.items()), sum(1 for t in _types.values() if t.vtables), _out, time.time() - _t0))

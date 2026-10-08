# Run inside Binary Ninja via the script bridge:  bnrun --timeout 60 tests/bn_dev_load.py
# Copies the plugin package to /tmp/cpp_devN/, renames the language to "Pseudo Cpp devN" and imports it, so
# the language view can be iterated without restarting Binary Ninja (BN can't unregister a language
# representation). Modelled on binary-jvm tests/bn_dev_load.py.
import importlib.util, os, shutil, sys
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")  # prepend CPP_REPO = "..." for another checkout
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None:
    _dev = _bn._cpp_dev = {"n": 0}
_dev["n"] += 1
_n = _dev["n"]
_name = "cpp_dev%d" % _n
_dst = os.path.join("/tmp", _name)
shutil.rmtree(_dst, ignore_errors=True)
shutil.copytree(REPO, _dst, ignore=lambda d, names: [f for f in names if not (f.endswith(".py") or (
    os.path.isdir(os.path.join(d, f)) and d == REPO and f in ("cpp", "shared")))])
_c = os.path.join(_dst, "constants.py")
_src = open(_c).read()
open(_c, "w").write(_src.replace('LANGUAGE_NAME = "Pseudo Cpp"', 'LANGUAGE_NAME = "Pseudo Cpp dev%d"' % _n))
_spec = importlib.util.spec_from_file_location(_name, os.path.join(_dst, "__init__.py"), submodule_search_locations=[_dst])
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_name] = _mod
_spec.loader.exec_module(_mod)  # registers the language
_dev["pkg"] = _mod
_dev["pseudo_cpp"] = sys.modules[_name + ".cpp.pseudo_cpp"]
_dev["LANGUAGE_NAME"] = sys.modules[_name + ".constants"].LANGUAGE_NAME
print("registered", _dev["LANGUAGE_NAME"], "from", _dst)

# The test scripts under bn-script-bridge's `bn` launcher (bnengine: Binary Ninja in this python process, no app,
# bn-script-bridge 04cf44e+, 2026-10-28) or, as before, inside the app (bnrun --gui, a dev load) -- bncpp-177.
#   import importlib.util as _u
#   _s = _u.spec_from_file_location("bn_engine", "/Users/patrick/dev/binary-cpp/tests/bn_engine.py")
#   _e = _u.module_from_spec(_s); _s.loader.exec_module(_e); _e.setup(globals())
# setup(g) gives the script what bnrun and bn_dev_load.py gave it, where nothing did:
#   the engine           bnengine.engine() under the launcher (BN_SA_APP set, no core yet); once per process
#   binaryninja._cpp_dev  {pkgname, pkg, pseudo_cpp, LANGUAGE_NAME}: a dev load's, else the installed plugin -- the
#                        plugins folder links this repo, so the engine loads the working tree at its start
#   env                  os.environ
#   bv                   with need_bv: the view of $BNDB (bnengine.open: one handle per file; write=True when
#                        $APPLY is set, so the script can save with bv.file.save_auto_snapshot())
import os, sys

BRIDGE = "/Users/patrick/dev/bn-script-bridge"
PLUGIN = "binary-cpp"  # the installed plugin's package (the plugins folder entry's name)


def setup(g, need_bv=False):
    if os.environ.get("BN_SA_APP") and BRIDGE not in sys.path:
        sys.path.insert(0, BRIDGE)
    if os.environ.get("BN_SA_APP"):
        import bnengine
        if not getattr(bnengine, "_bncpp_started", False):
            bnengine.engine()
            bnengine._bncpp_started = True
    import binaryninja
    if getattr(binaryninja, "_cpp_dev", None) is None:
        pkg = sys.modules.get(PLUGIN)
        if pkg is None:
            raise RuntimeError("the %s plugin is not loaded (plugins folder link?) and no dev load ran" % PLUGIN)
        binaryninja._cpp_dev = {"pkgname": PLUGIN, "pkg": pkg, "pseudo_cpp": sys.modules[PLUGIN + ".cpp.pseudo_cpp"],
                                "LANGUAGE_NAME": sys.modules[PLUGIN + ".constants"].LANGUAGE_NAME}
    if g.get("env") is None:
        g["env"] = dict(os.environ)
    if need_bv and g.get("bv") is None:
        import bnengine
        path = g["env"].get("BNDB")
        if not path:
            sys.exit("set BNDB=/abs/path.bndb (the view this script works on)")
        g["bv"] = bnengine.open(path, write=bool(g["env"].get("APPLY")))
    return binaryninja._cpp_dev

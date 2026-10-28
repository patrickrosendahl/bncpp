# The test scripts under bn-script-bridge's `bn` launcher (bnengine: Binary Ninja in this python process, no app,
# bn-script-bridge 16c1602+, 2026-10-28; the bnrun bridge is gone) or in the app's script console after a dev load
# -- bncpp-177.
#   import importlib.util as _u
#   _s = _u.spec_from_file_location("bn_engine", "/Users/patrick/dev/binary-cpp/tests/bn_engine.py")
#   _e = _u.module_from_spec(_s); _s.loader.exec_module(_e); _e.setup(globals())
# setup(g) gives the script what bnrun and bn_dev_load.py used to give it, where nothing did:
#   the engine           bnengine.engine() under the launcher (BN_SA_APP set, no core yet); once per process.
#                        Since bn-script-bridge d47734e the engine's init thread stays parked, so
#                        update_analysis_and_wait() works on the main thread too (before, it returned at once there:
#                        half-analysed views, bn-2; f43ee71 ran scripts in a worker thread for that)
#   binaryninja._cpp_dev  {pkgname, pkg, pseudo_cpp, LANGUAGE_NAME}: a dev load's, else the installed plugin -- the
#                        plugins folder links this repo, so the engine loads the working tree at its start
#   env                  os.environ
#   bv                   with need_bv: the view of $BNDB, a .bndb or a raw binary (bnengine.open: one handle per
#                        file, a .bndb opens lean with its saved analysis; write=True when $APPLY or $SAVE is set)
# finish(g) at the end of a script that changes the view: edits live in RAM and die with the process, so it saves
# only on request -- SAVE=1 into the .bndb itself, SAVE=/abs/new.bndb into a new database (a raw binary's only
# way) -- and says so either way. A no-op where the caller supplied bv (bn_dump.py, bn_class_pipeline.py).
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
        g["bv"] = bnengine.open(path, write=bool(g["env"].get("APPLY") or g["env"].get("SAVE")))
        g["_bn_engine_bv"] = g["bv"]
    return binaryninja._cpp_dev


def finish(g):
    bv = g.get("_bn_engine_bv")
    if bv is None or bv is not g.get("bv"):
        return
    target = (g.get("env") or {}).get("SAVE") or ""
    if not target or target == "0":
        if (g.get("env") or {}).get("APPLY"):
            print("not saved (APPLY in RAM only; SAVE=1 or SAVE=/abs/new.bndb persists it)")
        return
    if target == "1":
        if not bv.file.filename.lower().endswith(".bndb"):
            sys.exit("SAVE=1 needs a .bndb view; a raw binary saves with SAVE=/abs/new.bndb")
        ok = bv.file.save_auto_snapshot()
    else:
        ok = bv.create_database(target)
    print("saved %s: %s" % (bv.file.filename if target == "1" else target, "ok" if ok else "FAILED"))
    if not ok:
        sys.exit(1)

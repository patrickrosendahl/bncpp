# On the Binary Ninja engine (B=/Users/patrick/dev/bn-script-bridge; tests/bn_engine.py, bncpp-177):
#   BNDB=DB [BASELINE=F] [NAMES=F] $B/bn --timeout 1800 tests/bn_class_pipeline.py             # dry runs
#   BNDB=DB [BASELINE=F] [NAMES=F] APPLY=1 $B/bn --timeout 1800 tests/bn_class_pipeline.py
#   (SAVE=1 with APPLY saves into DB; without it the changes die with the process)
# bncpp-55: the class steps in their one valid order, in one lane -- names (bn_class_apply.py), types
# (bn_class_types.py), fields (bn_class_fields.py) -- each with the same env (APPLY, BASELINE, NAMES, ROUNDS, ...),
# each printing its own run line. A step that fails stops the pipeline (the later steps need its result). A dry run
# is the three dry runs: the fields step then counts the classes the types step would create as 'no type yet'.
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import os, time

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_env = globals().get("env") or {}
_t0 = time.time()
for _script in ("bn_class_apply.py", "bn_class_types.py", "bn_class_fields.py"):
    print("== %s" % _script)
    _g = {"__name__": "__bn_class_pipeline__", "bv": bv, "CPP_REPO": REPO, "env": dict(_env), "print": print}  # the bridge's print
    _path = os.path.join(REPO, "tests", _script)
    with open(_path, encoding="utf-8") as _fh:
        exec(compile(_fh.read(), _path, "exec"), _g)
_apply = (_env.get("APPLY") or os.environ.get("APPLY")) == "1"
print("pipeline %s: names -> types -> fields (%.1f s)" % ("applied" if _apply else "dry run", time.time() - _t0))
_e.finish(globals())  # SAVE=1 / SAVE=/abs/new.bndb persists the view's changes (tests/bn_engine.py)

# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --bndb DB --timeout 1800 [--env BASELINE=F] [--env NAMES=F] tests/bn_class_pipeline.py             # dry runs
#   bnrun --bndb DB --timeout 1800 [--env BASELINE=F] [--env NAMES=F] --env APPLY=1 tests/bn_class_pipeline.py
#   bnrun --bndb-save DB                                                                                     # then persist
# bncpp-55: the class steps in their one valid order, in one lane -- names (bn_class_apply.py), types
# (bn_class_types.py), fields (bn_class_fields.py) -- each with the same env (APPLY, BASELINE, NAMES, ROUNDS, ...),
# each printing its own run line. A step that fails stops the pipeline (the later steps need its result). A dry run
# is the three dry runs: the fields step then counts the classes the types step would create as 'no type yet'.
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

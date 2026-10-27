"""bncpp-102: does loading and closing small views next to a big analysis corrupt Binary Ninja's heap?

NOT RUN YET. It aims to crash the shared app: run it only in a quiet moment, with the user's OK, after the other
sessions have saved (bnrun --bndb PATH --bndb-save). Two crashes to reproduce (BN 6.1.11003):
  2026-10-23 16:52 SIGABRT, malloc_report in thread 'Worker PRI Function Destruction', while a bridge thread was in
                   BNLoadFilename (the raw SynthV arm64 slice), after --parallel scripts had run load() +
                   create_database() + file.close() cycles on small binaries (bncpp-29)
  2026-10-22 17:54 SIGSEGV in BNGetFunctionSymbol, called from a bridge script's Python thread
Modes (env MODE):
  cycles  N times: load a suite dylib, wait for analysis, create_database into a temp dir, close (bncpp-29's pattern);
          run it with --parallel while another lane analyses a big binary (the 16:52 situation)
  stale   keep Function objects of a closed view and read their symbols (the 17:54 frame)
  bnrun --parallel --timeout 600 --env MODE=cycles --env N=20 tests/repro_close_abort/bn_cycles.py
  bnrun --parallel --timeout 120 --env MODE=stale tests/repro_close_abort/bn_cycles.py
"""
import os, tempfile, time
import binaryninja

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_env = globals().get("env") or {}
MODE = _env.get("MODE", "cycles")
N = int(_env.get("N", "20"))
BIN = _env.get("BIN") or os.path.join(REPO, "tests/suite/bin/x86_64-O2/TestVirtual.dylib")

t0 = time.time()
if MODE == "cycles":
    with tempfile.TemporaryDirectory() as d:
        for i in range(N):
            bv = binaryninja.load(BIN)
            bv.update_analysis_and_wait()
            n = len(bv.functions)
            bv.create_database(os.path.join(d, "c%d.bndb" % i))
            bv.file.close()
            print("cycle %d: %d functions, %.1f s" % (i, n, time.time() - t0))
elif MODE == "stale":
    bv = binaryninja.load(BIN)
    bv.update_analysis_and_wait()
    funcs = list(bv.functions)
    bv.file.close()
    del bv
    print("closed; reading %d stale functions' symbols" % len(funcs))
    print([f.symbol.full_name for f in funcs][:5])
else:
    raise ValueError("MODE: cycles or stale")
print("survived (%.1f s)" % (time.time() - t0))

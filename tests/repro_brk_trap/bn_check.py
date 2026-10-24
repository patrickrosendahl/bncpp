"""bncpp-101 (2) / bncpp-30: on arm64 BN does not end a function at 'brk #0x1' and creates none at trap bodies that
only a vtable reaches.

repro.cpp at -O2 gives four one-instruction functions 'brk #0x1' (Base's D1/D0 destructors of an abstract class,
Never's ~Never and f) right after Leaf::f, reachable only through the vtables in __const. With the local symbols
stripped BN has only LC_FUNCTION_STARTS and the vtable pointers to find them.

Result (BN 6.1.11003, 2026-10-24): BN makes functions at the three traps a vtable points to (data refs), but none at
0x514 (Base's D1: in LC_FUNCTION_STARTS, no reference) -- while it does make the other LC_FUNCTION_STARTS entries
without references (the lone 'ret' at 0x4a0). A function at a trap ends there (a user function at 0x514 with the one
at 0x518 removed: 0x514-0x518), so the SynthV run-through from one trap into the next does not reproduce here.

Build:   clang++ -arch arm64 -O2 -std=c++17 -fvisibility=hidden -dynamiclib -o repro.stripped.arm64.dylib repro.cpp \
           -Wl,-exported_symbol,__Z9make_leafi -Wl,-exported_symbol,_make_never && strip -x repro.stripped.arm64.dylib
Bridge:  bnrun --parallel --timeout 120 --env D=$PWD bn_check.py
"""
import os
import binaryninja

_env = globals().get("env") or {}
D = _env.get("D", os.path.dirname(os.path.abspath(globals().get("__file__", "."))))
TRAPS = (0x514, 0x518, 0x51c, 0x520)  # file offsets == addresses in the dylib (base 0)

bv = binaryninja.load(os.path.join(D, "repro.stripped.arm64.dylib"))
try:
    bv.update_analysis_and_wait()
    base = bv.start
    print("functions: %d" % len(bv.functions))
    for f in sorted(bv.functions, key=lambda f: f.start):
        print("  %#x %-20s %s" % (f.start, f.name, [hex(r.start) + "-" + hex(r.end) for r in f.address_ranges]))
    for t in TRAPS:
        a = base + t
        own = [f.name for f in bv.get_functions_containing(a)]
        print("trap %#x: function starting here: %s; containing: %s; code refs to it: %d, data refs: %d" % (
            a, bv.get_function_at(a) is not None, own, len(list(bv.get_code_refs(a))), len(list(bv.get_data_refs(a)))))
    # does a function end at 'brk #0x1'? with 0x518 undefined, a function at 0x514 shows whether it runs on into
    # the next trap (the SynthV shape: the second trap has no function of its own)
    bv.remove_user_function(bv.get_function_at(base + 0x518))
    bv.update_analysis_and_wait()
    bv.create_user_function(base + 0x514)
    bv.update_analysis_and_wait()
    f = bv.get_function_at(base + 0x514)
    print("user function at 0x514 with 0x518 removed: %s" % (
        [hex(r.start) + "-" + hex(r.end) for r in f.address_ranges] if f else None))
finally:
    bv.file.close()

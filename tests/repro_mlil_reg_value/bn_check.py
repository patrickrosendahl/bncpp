"""bncpp-155 (BN support): MLIL get_reg_value / get_var_for_reg report r15's entry value at a call after BN folded
`lea r15, [rbp-0x50]` away; LLIL and Function.get_reg_value_at say stack frame offset -0x58.
  bnrun --parallel --timeout 120 tests/repro_mlil_reg_value/bn_check.py
"""
import binaryninja, gc
bv = binaryninja.load(__import__("os").path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"), "tests/suite/bin/x86_64-O2/TestClosureThrow.dylib"))
try:
    bv.update_analysis_and_wait()
    print("BN", binaryninja.core_version())
    f = bv.get_function_at(0x4006c0)
    m = next(x for x in f.mlil.instructions if x.address == 0x4006f6)
    l = next(x for x in f.llil.instructions if x.address == 0x4006f6)
    print("MLIL", m, "| var_for_reg:", m.get_var_for_reg("r15"), "| mlil reg_value:", m.get_reg_value("r15"),
          "| llil reg_value:", l.get_reg_value("r15"), "| get_reg_value_at:", f.get_reg_value_at(0x4006f6, "r15"))
    f = m = l = None
finally:
    gc.collect(); bv.file.close()

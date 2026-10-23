"""bncpp-29: after a database round trip every function reports has_user_type == True, although nobody set a type.

Repro of the Binary Ninja behaviour (BN 6.1.11003-dev): load a raw binary (0 functions with has_user_type),
create_database(), load the .bndb: every function -- sub_ functions and imports included -- has has_user_type True,
with the same type and confidence as before. The flag does not freeze analysis: patch the body to read a second
argument and BN re-infers the parameters in the database view as in the raw one. So the flag is spurious, and only
code that trusts it ("never over a user type") is affected; our workaround: BASELINE in tests/bn_class_types.py /
bn_class_fields.py (protect only types that differ from a fresh analysis).

Build:     clang -arch x86_64 -O1 -o repro repro.c && strip repro
Headless:  python3 bn_check.py repro      (writes repro.bndb next to it)
Bridge:    bnrun --parallel --timeout 300 --env D=$PWD bn_check.py
"""
import os, sys
import binaryninja

PATCH_AT, PATCH = 0x1000004f4, b"\x8d\x04\x37"  # 'lea eax, [rdi+6]' -> 'lea eax, [rdi+rsi]' in the first sub_ (add3)


def count(bv, tag):
    fs = list(bv.functions)
    print("%-34s %d functions, has_user_type: %d" % (tag, len(fs), sum(f.has_user_type for f in fs)))


def main(path):
    db = path + ".bndb"
    if os.path.exists(db):
        os.remove(db)
    bv = binaryninja.load(path)
    count(bv, "raw binary, fresh analysis")
    raw = {f.start: (str(f.type), f.type.confidence) for f in bv.functions}
    bv.create_database(db)
    count(bv, "same view after create_database")
    bv.file.close()
    for kw, tag in (({}, "the .bndb, load()"), ({"update_analysis": False}, "the .bndb, update_analysis=False")):
        bv = binaryninja.load(db, **kw)
        count(bv, tag)
        print("  types and confidence as before: %d of %d" % (
            sum(raw.get(f.start) == (str(f.type), f.type.confidence) for f in bv.functions), len(raw)))
        bv.file.close()
    for p in (path, db):  # does the flag freeze inference? no: both views re-infer after the patch
        bv = binaryninja.load(p)
        f = bv.functions[1] if bv.get_function_at(PATCH_AT - 4) is None else bv.get_function_at(PATCH_AT - 4)
        before = str(f.type)
        bv.write(PATCH_AT, PATCH)
        bv.update_analysis_and_wait()
        f = bv.get_function_at(f.start)
        print("%-6s %s: %s -> after patch %s (has_user_type %s)" % (
            os.path.basename(p), f.name, before, f.type, f.has_user_type))
        bv.file.close()


if __name__ == "__main__" or "env" in globals():
    for _p in (sys.argv[1:] if __name__ == "__main__" else [os.path.join(env["D"], "repro")]):
        main(_p)

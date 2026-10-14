"""How do virtual calls read in HLIL? Before/after numbers for bncpp-27.

Read-only. Over a sample of the functions named by the class directives (every Nth R: entry of
.scratch/classes/<binary>.directives, written by tests/bn_class_apply.py), counts the HLIL calls whose target is
not a constant (indirect calls) and how many of those read as a named member call through the vptr
('->vptr->'), plus the functions whose first parameter is named 'this'.
  bnrun --bndb DB --timeout 900 tests/bn_vcall_count.py [-- STRIDE]     (default stride 10)
"""
import os, sys, time
from binaryninja import HighLevelILOperation as Op

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
stride = int(sys.argv[1]) if len(sys.argv) > 1 else 10
name = os.path.basename(bv.file.original_filename)
name = name[:-5] if name.endswith(".bndb") else name
funcs = [int(line.split(":")[1], 16) for line in open(os.path.join(REPO, ".scratch/classes/%s.directives" % name), encoding="utf-8")
         if line.startswith("R:")][::stride]
CALLS = (Op.HLIL_CALL, Op.HLIL_TAILCALL, Op.HLIL_CALL_SSA)
DIRECT = (Op.HLIL_CONST_PTR, Op.HLIL_IMPORT, Op.HLIL_EXTERN_PTR, Op.HLIL_CONST)

t0 = time.time()
counts = {"functions": 0, "no hlil": 0, "this param": 0, "indirect calls": 0, "named vptr calls": 0,
          "other calls via this": 0}
examples = []


def walk(i):
    if i.operation in CALLS:
        dest = i.dest
        if dest.operation not in DIRECT:
            counts["indirect calls"] += 1
            text = str(dest)
            if "->vptr->" in text:
                counts["named vptr calls"] += 1
            elif "this" in text:
                counts["other calls via this"] += 1
                if len(examples) < 12:
                    examples.append(text)
    for o in i.operands:
        if hasattr(o, "operation"):
            walk(o)
        elif isinstance(o, list):
            for x in o:
                if hasattr(x, "operation"):
                    walk(x)


for a in funcs:
    f = bv.get_function_at(a)
    if f is None:
        continue
    counts["functions"] += 1
    params = f.type.parameters
    if params and params[0].name == "this":
        counts["this param"] += 1
    try:
        h = f.hlil
    except Exception:
        h = None
    if h is None or h.root is None:
        counts["no hlil"] += 1
        continue
    walk(h.root)
print("sample 1/%d of %d functions: %s (%.1f s)" % (stride, len(funcs) * stride, ", ".join(
    "%s %d" % kv for kv in counts.items()), time.time() - t0))
for e in examples:
    print("   ", e[:120])

"""Binary side of the sloppy line mapping (bncpp-36): per function, the HLIL statements in structured order with
their features, dumped to disk so the matcher and the statement alignment run off BN.

Read-only, chunked: functions sorted by address, from address START (hex) on, COUNT of them, stopping early after BUDGET seconds (the
last line says where to go on). Appends JSON lines to OUT (absolute: the script runs inside BN).
  bnrun --lock --view kernelcache --timeout 120 --env OUT=$PWD/.scratch/linemap/kernel/feat.jsonl \
        [--env START=0xADDR] [--env COUNT=2000] [--env BUDGET=90] [--env FORCE=1] tests/bn_line_features.py
FORCE=1 generates HLIL for functions that have none yet (slow on a big view); default: only what is available
(those count as 'nohlil' and keep start/end/name). Never forced: functions BN skipped (analysis_skipped -- forcing
them re-analyses a huge function in someone else's view, one native call the timeout cannot stop) and those over
MAXBYTES (default 16000); they are written as 'skipped'.

One line per function:
  {"start": hex, "end": hex, "name": str|null (null: an auto sub_ name), "stmts": [[addr, kind, depth, feats]]}
  kind: the statement's HLIL operation without HLIL_ (if / while / for / switch / case carry only their condition)
  feats: [[addr, k, v]] with k str (a string the expression references), num (an int constant, not 0/1/-1),
  call (a named callee), bl (an unnamed callee; v = its address as hex)
shared.linematch reads the flat features (every statement's feats, in order) like tests/ref_bin_features.py's.
"""
import json, os, time
from binaryninja import HighLevelILOperation as Op

OUT = env.get("OUT") or os.environ.get("OUT")
START = int(env.get("START", os.environ.get("START", "0")), 0)   # an address (resume point) or 0
COUNT = int(env.get("COUNT", os.environ.get("COUNT", "2000")))
BUDGET = float(env.get("BUDGET", os.environ.get("BUDGET", "90")))
FORCE = (env.get("FORCE") or os.environ.get("FORCE")) == "1"
MAXBYTES = int(env.get("MAXBYTES", os.environ.get("MAXBYTES", "16000")))
if not OUT or not os.path.isabs(OUT):
    raise RuntimeError("OUT=<absolute path> required")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# structural operations: their sub-statements are walked, the condition (if any) is a statement of its own
NEST = {
    Op.HLIL_BLOCK: (None, ("body",)),
    Op.HLIL_IF: ("condition", ("true", "false")),
    Op.HLIL_WHILE: ("condition", ("body",)),
    Op.HLIL_DO_WHILE: ("condition", ("body",)),
    Op.HLIL_FOR: ("condition", ("init", "body", "update")),
    Op.HLIL_SWITCH: ("condition", ("cases", "default")),
    Op.HLIL_CASE: (None, ("body",)),
}
SKIP = (Op.HLIL_NOP, Op.HLIL_LABEL, Op.HLIL_VAR_DECLARE)
CALLS = (Op.HLIL_CALL, Op.HLIL_TAILCALL)
_names = {}
MASK = (1 << (8 * bv.address_size)) - 1


def callee_name(addr):
    """a callee's name unless BN made it up (sub_X); cached"""
    if addr not in _names:
        s = bv.get_symbol_at(addr)
        n = s.full_name if s is not None else None
        if n is not None and "sub_" in n:
            n = None
        _names[addr] = n
    return _names[addr]


def string_at(addr):
    s = bv.get_string_at(addr)
    if s is not None and s.start == addr:
        return s.value
    return None


def feats_of(expr, out):
    """the features of an expression tree, in traversal order"""
    nodes = list(expr.traverse(lambda x: x))
    # a call's constant dest is already a call / bl feature; its CONST_PTR node must not also emit the target
    # address as num (bncpp-36: only pointer constants that resolve no string do that)
    call_dests = {(d.operation, d.constant) for e in nodes if e.operation in CALLS
                  for d in (e.dest,)
                  if d.operation in (Op.HLIL_CONST_PTR, Op.HLIL_CONST, Op.HLIL_IMPORT, Op.HLIL_EXTERN_PTR)}
    for e in nodes:
        op = e.operation
        a = "%#x" % e.address
        if op in CALLS:
            d = e.dest
            if d.operation in (Op.HLIL_CONST_PTR, Op.HLIL_CONST, Op.HLIL_IMPORT, Op.HLIL_EXTERN_PTR):
                t = d.constant & MASK
                n = callee_name(t)
                out.append([a, "call", n] if n else [a, "bl", "%#x" % t])
            else:
                out.append([a, "bl", None])
        elif op == Op.HLIL_CONST_PTR:
            s = string_at(e.constant & MASK)
            if s is not None:
                out.append([a, "str", s])
            elif (e.operation, e.constant) not in call_dests:
                out.append([a, "num", e.constant & MASK])  # unanalyzed region: no string resolves (bncpp-36)
        elif op == Op.HLIL_CONST_DATA:
            try:
                v = e.constant_data.data
                s = bytes(v).split(b"\0")[0].decode("utf-8", "replace")
                if s:
                    out.append([a, "str", s])
                else:
                    out.append([a, "num", e.constant & MASK])
            except Exception:
                out.append([a, "num", e.constant & MASK])
        elif op == Op.HLIL_CONST:
            v = e.constant
            if v not in (0, 1, -1):
                out.append([a, "num", v])
    return out


def walk(ins, depth, out):
    """statements of an HLIL subtree in structured (source-like) order"""
    if ins is None:
        return
    if isinstance(ins, list):
        for x in ins:
            walk(x, depth, out)
        return
    op = ins.operation
    if op in SKIP:
        return
    if op in NEST:
        cond, subs = NEST[op]
        if op == Op.HLIL_DO_WHILE:          # the body runs before the condition
            walk(ins.body, depth + 1, out)
            out.append(["%#x" % ins.address, "do_while", depth, feats_of(ins.condition, [])])
            return
        if cond is not None:
            out.append(["%#x" % ins.address, op.name[5:].lower(), depth, feats_of(getattr(ins, cond), [])])
        elif op == Op.HLIL_CASE:
            out.append(["%#x" % ins.address, "case", depth, []])
        for name in subs:
            walk(getattr(ins, name), depth + (0 if op == Op.HLIL_BLOCK else 1), out)
        return
    out.append(["%#x" % ins.address, op.name[5:].lower(), depth, feats_of(ins, [])])


t0 = time.time()
funcs = sorted(bv.functions, key=lambda f: f.start)
n_all = len(funcs)
first = next((k for k, f in enumerate(funcs) if f.start >= START), n_all)
done = nohlil = skipped = errors = stmts = 0
with open(OUT, "a", encoding="utf-8") as fp:
    for i in range(first, min(first + COUNT, n_all)):
        if time.time() - t0 > BUDGET:
            break
        f = funcs[i]
        rec = {"start": "%#x" % f.start, "name": None, "stmts": []}
        try:
            rec["end"] = "%#x" % max(bb.end for bb in f.basic_blocks) if f.basic_blocks else "%#x" % (f.start + 4)
            s = f.symbol
            if s is not None and "sub_" not in s.full_name:
                rec["name"] = s.full_name
            if FORCE and (f.analysis_skipped or f.total_bytes > MAXBYTES):
                rec["skipped"] = True
                skipped += 1
                h = False
            else:
                h = f.hlil if FORCE else f.hlil_if_available
            if h is False:
                pass
            elif h is None or h.root is None:
                rec["nohlil"] = True
                nohlil += 1
            else:
                walk(h.root, 0, rec["stmts"])
                stmts += len(rec["stmts"])
        except Exception as ex:
            rec["error"] = "%s: %s" % (type(ex).__name__, ex)
            errors += 1
        fp.write(json.dumps(rec, separators=(",", ":")) + "\n")
        done += 1
nxt = first + done
print("functions %d..%d of %d: %d written, %d without HLIL, %d skipped, %d errors, %d statements, %.1f s"
      % (first, nxt, n_all, done, nohlil, skipped, errors, stmts, time.time() - t0))
print("next START=%#x" % funcs[nxt].start if nxt < n_all else "complete")

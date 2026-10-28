"""What do virtual call sites say about the slot functions' parameters? Measurement for bncpp-28, source (2).

Read-only. Over a sample of the functions named by the class directives (every Nth R: entry of
.scratch/classes/<binary>.directives), finds the HLIL calls through a vtable struct member (X::VTable, from
tests/bn_class_types.py) and compares each argument past 'this' with the parameter of the slot functions that
the call can reach: X's slot and the same slot in every class whose primary-base chain contains X.
  BNDB=DB $B/bn --timeout 900 tests/bn_vcall_args.py [STRIDE] (default stride 10)
Per argument: the call site's type is a class pointer (a pointer to a struct that is not a VTable) or not; per
reachable slot function, its parameter is the same type, another class pointer (a contradiction) or something
less specific (a candidate). Per (class, slot, argument): the class pointer types seen across the sample's sites.
"""
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import importlib, os, sys, time
import binaryninja as _bn
from binaryninja import HighLevelILOperation as Op, TypeClass

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_rtti = importlib.import_module(_dev["pkgname"] + ".cpp.rtti")
_types_mod = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_types")
_names_mod = importlib.import_module(_dev["pkgname"] + ".cpp.rtti_names")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
stride = int(sys.argv[1]) if len(sys.argv) > 1 else 10
name = os.path.basename(bv.file.original_filename)
name = name[:-5] if name.endswith(".bndb") else name
funcs = [int(line.split(":")[1], 16) for line in open(os.path.join(REPO, ".scratch/classes/%s.directives" % name),
                                                       encoding="utf-8") if line.startswith("R:")][::stride]
t0 = time.time()
img = _bnimage.BNImage(bv)
scan = _rtti.scan(img)
classes, _functions = _types_mod.plan(scan, img.demangle, img.call_targets,
                                      _names_mod.label_overrides(scan, img.symbol_at))
by_label = {c.name: c for c in classes}
# label -> labels of the classes whose primary-base chain contains it (itself included)
lab_of = {c.typeinfo: c.name for c in classes}
derived = {c.name: {c.name} for c in classes}
for c in classes:
    a, seen = c.typeinfo, set()
    while a is not None and a not in seen and a in scan:
        seen.add(a)
        if a in lab_of:
            derived.setdefault(lab_of[a], set()).add(c.name)
        a = _names_mod._primary_base(scan[a])
t_scan = time.time() - t0

CALLS = (Op.HLIL_CALL, Op.HLIL_TAILCALL)
DIRECT = (Op.HLIL_CONST_PTR, Op.HLIL_IMPORT, Op.HLIL_EXTERN_PTR, Op.HLIL_CONST)
counts = {}
slots = {}      # (label, index, arg) -> {site type: n}
examples = []


def count(k, n=1):
    counts[k] = counts.get(k, 0) + n


def named(t):
    """the struct name a pointer type points at, else None"""
    if t is None or t.type_class != TypeClass.PointerTypeClass:
        return None
    tgt = t.target
    if tgt.type_class == TypeClass.NamedTypeReferenceClass:
        return str(tgt.name)
    if tgt.type_class == TypeClass.StructureTypeClass and tgt.registered_name is not None:
        return str(tgt.registered_name.name)
    return None


def call(i, fname):
    dest = i.dest
    if dest.operation in DIRECT:
        return
    count("indirect calls")
    vt = named(dest.src.expr_type) if dest.operation == Op.HLIL_DEREF_FIELD else None
    if vt is None or not vt.endswith("::VTable"):
        receiver(dest, fname)
        return
    label = vt[:-len("::VTable")]
    c = by_label.get(label)
    if c is None or dest.offset % 8 or dest.offset // 8 >= len(c.members):
        count("vtable calls, class not in the plan")
        return
    count("vtable calls")
    k = dest.offset // 8
    targets = set()
    for d in derived.get(label, {label}):
        dm = by_label[d].members
        if k < len(dm) and isinstance(dm[k][1], int):
            targets.add(dm[k][1])
    count("reachable slot functions", len(targets))
    for j, p in enumerate(i.params[1:], 1):
        count("args past this")
        st = p.expr_type
        sn = named(st)
        if sn is None or sn.endswith("::VTable"):
            continue
        count("args: class pointer at the site")
        key = (label, k, j)
        slots.setdefault(key, {})
        slots[key][sn] = slots[key].get(sn, 0) + 1
        for t in targets:
            f = bv.get_function_at(t)
            if f is None or j >= len(f.type.parameters):
                count("callee param missing")
                continue
            pt = f.type.parameters[j].type
            pn = named(pt)
            if pn == sn:
                count("callee param: same class")
            elif pn is not None:
                count("callee param: another class (contradiction)")
                if len(examples) < 10:
                    examples.append("contra %s %s: site %s, %#x param %d %s" % (fname, dest, sn, t, j, pt))
            else:
                count("callee param: less specific (candidate)")
                if len(examples) < 20:
                    examples.append("cand   %s %s: site %s, %#x param %d %s" % (fname, dest, sn, t, j, pt))


def receiver(dest, fname):
    """an untyped indirect call: *(*R + k) or *(R->vptr ... ) -- what is R?"""
    d = dest
    if d.operation == Op.HLIL_DEREF and d.src.operation == Op.HLIL_ADD:
        d = d.src.left
    elif d.operation == Op.HLIL_DEREF:
        d = d.src
    elif d.operation == Op.HLIL_DEREF_FIELD:
        d = d.src
    else:
        count("untyped: dest %s" % d.operation.name)
        return
    if d.operation != Op.HLIL_DEREF:
        count("untyped: not *(*R + k), %s" % d.operation.name)
        return
    r = d.src
    kind = r.operation.name
    if r.operation == Op.HLIL_VAR:
        v = r.var
        if v in r.function.source_function.parameter_vars:
            kind += " param"
        else:
            kind += " local"
            src = origin(r.function, v)
            count("untyped local receiver from: " + src)
            if len(rexamples.setdefault("from " + src, [])) < 3:
                rexamples["from " + src].append("%s: %s" % (fname, dest))
    kind += " : " + ("class*" if named(r.expr_type) else "other")
    count("untyped receiver: " + kind)
    if len(rexamples.setdefault(kind, [])) < 3:
        rexamples[kind].append("%s: %s" % (fname, dest))


rexamples = {}
fields = {}  # untyped receivers loaded from this->field: 'class field' -> calls
CALLS_ALL = (Op.HLIL_CALL, Op.HLIL_TAILCALL)


def origin(h, v, depth=0):
    """where a local's value comes from: its (single) definition's source, through plain copies"""
    try:
        defs = h.get_var_definitions(v)
    except Exception:
        return "?"
    if len(defs) != 1:
        return "%d definitions" % len(defs) if defs else "no definition"
    d = defs[0]
    src = getattr(d, "src", None)
    if d.operation == Op.HLIL_VAR_INIT or d.operation == Op.HLIL_ASSIGN:
        src = d.src
    if src is None:
        return d.operation.name
    if src.operation == Op.HLIL_VAR and depth < 4:
        if src.var in h.source_function.parameter_vars:
            return "copy of a param"
        return origin(h, src.var, depth + 1)
    if src.operation in CALLS_ALL:
        return "call result (%s)" % ("direct" if src.dest.operation in DIRECT else "indirect")
    if src.operation in (Op.HLIL_DEREF, Op.HLIL_DEREF_FIELD, Op.HLIL_ARRAY_INDEX, Op.HLIL_STRUCT_FIELD):
        base = src.src
        while base.operation in (Op.HLIL_ADD, Op.HLIL_DEREF_FIELD, Op.HLIL_DEREF, Op.HLIL_STRUCT_FIELD) and \
                base.operation != Op.HLIL_VAR:
            base = base.left if base.operation == Op.HLIL_ADD else base.src
        own = base.operation == Op.HLIL_VAR and base.var in h.source_function.parameter_vars \
            and h.source_function.parameter_vars[0] == base.var and named(base.expr_type)
        if own:  # which field (bncpp-34: the fields worth a 'Y*' type)
            key = "%s %s" % (named(base.expr_type), src.src if src.operation == Op.HLIL_DEREF else
                             getattr(src, "member_index", None) is not None and str(src) or str(src))
            fields[key[:90]] = fields.get(key[:90], 0) + 1
        return "load (%s)" % ("this->field" if own else "other memory")
    return src.operation.name


def walk(i, fname):
    if i.operation in CALLS:
        call(i, fname)
    for o in i.operands:
        if hasattr(o, "operation"):
            walk(o, fname)
        elif isinstance(o, list):
            for x in o:
                if hasattr(x, "operation"):
                    walk(x, fname)


for a in funcs:
    f = bv.get_function_at(a)
    if f is None:
        continue
    count("functions")
    try:
        h = f.hlil
    except Exception:
        h = None
    if h is None or h.root is None:
        count("no hlil")
        continue
    walk(h.root, f.name)
agree = sum(1 for v in slots.values() if len(v) == 1)
print("scan %.1f s; sample 1/%d of %d functions (%.1f s): %s" % (
    t_scan, stride, len(funcs) * stride, time.time() - t0, ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
print("(class, slot, arg) with a class pointer at some site: %d, one type across sites %d, several %d" % (
    len(slots), agree, len(slots) - agree))
for e in examples:
    print("   ", e[:200])
for k, v in sorted(rexamples.items()):
    for e in v:
        print("   %-28s %s" % (k, e[:160]))
print("untyped receivers from this->field: %d fields, top 25:" % len(fields))
for k, n in sorted(fields.items(), key=lambda kv: -kv[1])[:25]:
    print("   %3d %s" % (n, k))

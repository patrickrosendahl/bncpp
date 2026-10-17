"""Names for what cpp/rtti.py recovered: class labels, vtable / typeinfo data symbols and virtual function names,
as annotate directives (the bnrun bridge's annotate lane: R:ADDR:NAME function, D:ADDR:NAME data, C:ADDR:TEXT).

  label       a name someone gave the class (a 'vtable_<X>' user symbol on its primary vtable, label_overrides),
              else the demangled real name (the type name string, else a __ZTI / __ZTS bind), else
              cls_<hash prefix> (8 hex digits, longer where two classes would collide) -- a pure function of the
              class's identity
  functions   a slot function is named after the most-base class that has it in a primary vtable, at its index
              there: Owner::vfuncN; Owner::~Owner and Owner::~Owner [deleting] for slots 0 / 1 when the code shows
              a destructor pair (slot 1 calls slot 0 and operator delete, or deletes once more than slot 0) in
              the class or in one along its primary-base chain (a primary base's slots are a prefix of the
              derived class's: an abstract class's deleting destructor is a trap, its derived ones show the pair).
              A function in the vtables of unrelated classes (identical code folding) only gets a comment.
              A closure target's call slot (cpp/rtti_closures.py, bncpp-23) is Closure::operator() (member invoke).
  thunks      a function only in secondary vtables (none in a primary one) adjusts 'this' for a base subobject:
              slot i of Class's vtable for Base at +16 is Class::~Class [thunk] / [deleting] [thunk] where Base's
              slots 0 / 1 are destructors, else its target's name + ' [thunk]' where the code only forwards to one
              function of this image, else Class::vfuncI_at_16 [thunk] (optimised thunks inline the body). A
              comment names the subobject (Class's Base at +16) and the forwarding target.
  data        vtable_for_<label> at the vtable's offset_to_top word (the start, unless the class has virtual
              bases: their offsets come before it), typeinfo_for_<label> at the typeinfo; a construction vtable
              is construction_vtable_for_<base>_in_<label>

Pure Python, no Binary Ninja import. Hooks: demangle(mangled) -> str | None; call_targets(addr) -> [name or
address per call site] | None (None: the function is unknown, no destructor evidence).
"""

OPERATOR_DELETE = ("__ZdlPv", "__ZdlPvm", "__ZdlPvSt11align_val_t", "__ZdlPvmSt11align_val_t")


def label_overrides(types, symbol_at):
    """{typeinfo: label} from names someone gave a class's primary vtable: a user data symbol 'vtable_<X>' at
    the vtable's start (not this module's 'vtable_for_...') labels the class X. symbol_at(addr) -> (name,
    user-defined?) | None"""
    out = {}
    for addr, t in types.items():
        prim = [vt for vt in t.vtables if vt.primary]
        s = symbol_at(prim[0].addr - 16) if prim else None
        if s is not None and s[1] and s[0].startswith("vtable_") and not s[0].startswith("vtable_for_"):
            out[addr] = s[0][len("vtable_"):]
    return out


def labels(types, demangle=None, overrides=None):
    """{typeinfo address: label}; overrides (label_overrides) win"""
    out, hashed = {}, {}
    for addr, t in types.items():
        if overrides and addr in overrides:
            out[addr] = overrides[addr]
            continue
        real = None
        if t.name_kind == "mangled":
            real = _type_name(t.name, demangle)
        for b in t.bind_names:
            real = real or _type_name(b[5:], demangle)  # __ZTI + name
        if real:
            out[addr] = real
        else:
            hashed[addr] = "".join(c for c in (t.name or "%x" % addr) if c.isalnum())
    for addr, h in hashed.items():
        width = 8  # longer only where another class shares the prefix
        while width < len(h) and any(o != addr and oh[:width] == h[:width] for o, oh in hashed.items()):
            width += 4
        out[addr] = "cls_" + h[:width]
    return out


def _type_name(name, demangle):
    """'N4synv6configE' -> 'synv::config' with a demangler (None if it fails: a name mangled beyond repair by an
    obfuscator is labelled like a hash), the mangled name without one"""
    if demangle is None:
        return name
    d = demangle("__ZTS" + name)
    if not d or d.startswith("__ZTS") or d.startswith("_ZTS"):
        return None
    for prefix in ("typeinfo name for ", "typeinfo_name_for_"):
        if d.startswith(prefix):
            return d[len(prefix):]
    return d


def _ancestors(types, addr):
    seen, todo = [], [addr]
    while todo:
        a = todo.pop()
        t = types.get(a)
        if t is None:
            continue
        for b, _of in t.bases:
            if isinstance(b, int) and b not in seen:
                seen.append(b)
                todo.append(b)
    return seen


def _is_dtor_pair(call_targets, d1, d0):
    if not (isinstance(d1, int) and isinstance(d0, int)) or call_targets is None:
        return False
    c1, c0 = call_targets(d1), call_targets(d0)
    if c1 is None or c0 is None:
        return False
    deletes0 = sum(1 for c in c0 if c in OPERATOR_DELETE)
    deletes1 = sum(1 for c in c1 if c in OPERATOR_DELETE)
    return deletes0 >= 1 and (d1 in c0 or deletes0 == deletes1 + 1)


def _primary_base(t):
    """the base sharing the class's primary vtable: the si base, or a vmi non-virtual base at offset 0"""
    if t.kind == "si" and t.bases and isinstance(t.bases[0][0], int):
        return t.bases[0][0]
    for b, of in t.bases:
        if t.kind == "vmi" and isinstance(b, int) and of is not None and not of & 1 and of >> 8 == 0:
            return b
    return None


def dtor_classes(types, call_targets=None):
    """the classes whose primary vtable starts with a destructor pair: shown by its code (_is_dtor_pair) in the
    class or in one along its primary-base chain, up or down"""
    def prim(t):
        p = [vt for vt in t.vtables if vt.primary]
        return p[0] if p and len(p[0].slots) >= 2 else None

    shown = set(a for a, t in types.items() if prim(t) and _is_dtor_pair(call_targets, *prim(t).slots[:2]))
    root = {}  # class -> the top of its primary-base chain

    def top(a):
        if a not in root:
            b = _primary_base(types[a])
            root[a] = top(b) if b in types and b != a else a
        return root[a]

    groups = set(top(a) for a in shown)
    return set(a for a, t in types.items() if prim(t) and top(a) in groups)


def owners(types, call_targets=None):
    """{function address: (owner typeinfo, index, role)} for the functions in primary vtables, role "dtor" /
    "deleting" / "invoke" (a closure's call operator) / "vfunc"; a function in the vtables of unrelated classes
    maps to None"""
    users = {}  # function -> [(class, index)] over primary vtables
    for addr, t in types.items():
        for vt in t.vtables:
            if not vt.primary:
                continue
            for i, s in enumerate(vt.slots):
                if isinstance(s, int):
                    users.setdefault(s, []).append((addr, i))
    dtor_pairs = dtor_classes(types, call_targets)
    out = {}
    for f, us in users.items():
        classes = set(c for c, _i in us)
        out[f] = None
        for c, i in sorted(us):  # the class all others derive from (or are)
            if all(o == c or c in _ancestors(types, o) for o in classes):
                cl = types[c].closure
                role = ("dtor", "deleting")[i] if c in dtor_pairs and i in (0, 1) else \
                    "invoke" if cl is not None and i == cl.invoke_index else "vfunc"
                out[f] = (c, i, role)
                break
    return out, users


def thunks(types, own, call_targets):
    """{function: (class typeinfo, subobject offset, slot index, forwarding target or None)} for the functions in
    secondary vtables that are in no primary one: this-adjusting thunks (the first vtable that has it)"""
    out = {}
    for addr in sorted(types):
        for vt in types[addr].vtables:
            if not vt.secondary:
                continue
            for i, s in enumerate(vt.slots):
                if not isinstance(s, int) or s in own or s in out:
                    continue
                calls = (call_targets(s) if call_targets is not None else None) or []
                local = [c for c in calls if isinstance(c, int)]
                out[s] = (addr, -vt.offset_to_top, i, local[0] if len(local) == 1 == len(calls) else None)
    return out


def _subobject(types, addr, offset):
    """the non-virtual base of the class at addr that sits at offset (vmi offset_flags), else None"""
    for b, of in types[addr].bases:
        if isinstance(b, int) and of is not None and not of & 1 and of >> 8 == offset and b in types:
            return b
    return None


def directives(types, demangle=None, call_targets=None, overrides=None):
    """[(kind, addr, text)] -- R / D / C directives for the annotate lane, sorted by address"""
    lab = labels(types, demangle, overrides)
    out = []
    # data symbols
    for addr, t in types.items():
        out.append(("D", addr, "typeinfo_for_" + lab[addr]))
        for vt in t.vtables:
            name = "vtable_for_" + lab[addr] if vt.construction_for is None else \
                "construction_vtable_for_%s_in_%s" % (lab[addr], lab.get(vt.construction_for, "?"))
            out.append(("D", vt.addr - 16, name + ("" if vt.offset_to_top == 0 else "_at_%d" % -vt.offset_to_top)))
    own, users = owners(types, call_targets)
    for f, o in sorted(own.items()):
        if o is None:
            us = sorted(users[f])
            out.append(("C", f, "virtual in unrelated classes: " + ", ".join(
                "%s[%d]" % (lab[c], i) for c, i in us[:6]) + (" ..." if len(us) > 6 else "")))
            continue
        c, i, role = o
        out.append(("R", f, function_name(lab[c], i, role)))
    dtors = dtor_classes(types, call_targets)
    for f, (c, offset, i, target) in sorted(thunks(types, own, call_targets).items()):
        base = _subobject(types, c, offset)
        where = "%s's %s at +%d" % (lab[c], lab[base], offset) if base else "%s's subobject at +%d" % (lab[c], offset)
        o = own.get(target)
        if base in dtors and i in (0, 1):
            name = function_name(lab[c], i, ("dtor", "deleting")[i])
        elif o is not None:
            name = function_name(lab[o[0]], o[1], o[2])
        else:
            name = "%s::vfunc%d_at_%d" % (lab[c], i, offset)
        out.append(("R", f, name + " [thunk]"))
        out.append(("C", f, "thunk for %s%s" % (where, " -> %#x" % target if target is not None else "")))
    out.sort(key=lambda d: (d[1], d[0]))
    return out


def _short(label):
    """the unqualified class name without template arguments: a::B<c::D> -> B (only top-level :: split)"""
    depth, start = 0, 0
    for i, ch in enumerate(label):
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        elif depth == 0 and label.startswith("::", i):
            start = i + 2
    return label[start:].split("<", 1)[0]


def function_name(label, index, role):
    short = _short(label)
    if role == "dtor":
        return "%s::~%s" % (label, short)
    if role == "deleting":
        return "%s::~%s [deleting]" % (label, short)
    if role == "invoke":
        return "%s::operator()" % label
    return "%s::vfunc%d" % (label, index)


def member_name(index, role):
    """the vtable struct member of a slot (an identifier)"""
    return {"dtor": "dtor", "deleting": "deleting_dtor", "invoke": "invoke"}.get(role, "vfunc%d" % index)

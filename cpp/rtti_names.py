"""Names for what cpp/rtti.py recovered: class labels, vtable / typeinfo data symbols and virtual function names,
as annotate directives (the bnrun bridge's annotate lane: R:ADDR:NAME function, D:ADDR:NAME data, C:ADDR:TEXT).

  label       the demangled real name (the type name string, else a __ZTI / __ZTS bind), else cls_<hash prefix>
              (8 hex digits, longer where two classes would collide) -- a pure function of the class's identity
  functions   a slot function is named after the most-base class that has it in a primary vtable, at its index
              there: Owner::vfuncN; Owner::~Owner and Owner::~Owner [deleting] for slots 0 / 1 when the code shows
              a destructor pair (slot 1 calls slot 0 and operator delete, or deletes once more than slot 0).
              A function in the vtables of unrelated classes (identical code folding) only gets a comment.
  data        vtable_for_<label> at the vtable's start (offset_to_top), typeinfo_for_<label> at the typeinfo

Pure Python, no Binary Ninja import. Hooks: demangle(mangled) -> str | None; call_targets(addr) -> [name or
address per call site] | None (None: the function is unknown, no destructor evidence).
"""

OPERATOR_DELETE = ("__ZdlPv", "__ZdlPvm", "__ZdlPvSt11align_val_t", "__ZdlPvmSt11align_val_t")


def labels(types, demangle=None):
    """{typeinfo address: label}"""
    out, hashed = {}, {}
    for addr, t in types.items():
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


def owners(types, call_targets=None):
    """{function address: (owner typeinfo, index, role)} for the functions in primary vtables, role "dtor" /
    "deleting" / "vfunc"; a function in the vtables of unrelated classes maps to None"""
    users = {}  # function -> [(class, index)] over primary vtables
    for addr, t in types.items():
        for vt in t.vtables:
            if vt.offset_to_top != 0:
                continue
            for i, s in enumerate(vt.slots):
                if isinstance(s, int):
                    users.setdefault(s, []).append((addr, i))
    dtor_pairs = set()
    for addr, t in types.items():
        prim = [vt for vt in t.vtables if vt.offset_to_top == 0]
        if prim and len(prim[0].slots) >= 2 and _is_dtor_pair(call_targets, prim[0].slots[0], prim[0].slots[1]):
            dtor_pairs.add(addr)
    out = {}
    for f, us in users.items():
        classes = set(c for c, _i in us)
        out[f] = None
        for c, i in sorted(us):  # the class all others derive from (or are)
            if all(o == c or c in _ancestors(types, o) for o in classes):
                role = ("dtor", "deleting")[i] if c in dtor_pairs and i in (0, 1) else "vfunc"
                out[f] = (c, i, role)
                break
    return out, users


def directives(types, demangle=None, call_targets=None):
    """[(kind, addr, text)] -- R / D / C directives for the annotate lane, sorted by address"""
    lab = labels(types, demangle)
    out = []
    # data symbols
    for addr, t in types.items():
        out.append(("D", addr, "typeinfo_for_" + lab[addr]))
        for vt in t.vtables:
            out.append(("D", vt.addr - 16, "vtable_for_" + lab[addr] + (
                "" if vt.offset_to_top == 0 else "_at_%d" % -vt.offset_to_top)))
    own, users = owners(types, call_targets)
    for f, o in sorted(own.items()):
        if o is None:
            us = sorted(users[f])
            out.append(("C", f, "virtual in unrelated classes: " + ", ".join(
                "%s[%d]" % (lab[c], i) for c, i in us[:6]) + (" ..." if len(us) > 6 else "")))
            continue
        c, i, role = o
        out.append(("R", f, function_name(lab[c], i, role)))
    out.sort(key=lambda d: (d[1], d[0]))
    return out


def function_name(label, index, role):
    short = label.rsplit("::", 1)[-1].split("<", 1)[0]
    if role == "dtor":
        return "%s::~%s" % (label, short)
    if role == "deleting":
        return "%s::~%s [deleting]" % (label, short)
    return "%s::vfunc%d" % (label, index)


def member_name(index, role):
    """the vtable struct member of a slot (an identifier)"""
    return {"dtor": "dtor", "deleting": "deleting_dtor"}.get(role, "vfunc%d" % index)

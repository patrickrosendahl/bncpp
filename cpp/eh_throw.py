"""`throw` statements from ___cxa_throw (bncpp-65).

Itanium code throws in three steps: `x = ___cxa_allocate_exception(size)`, the object built in place (a constructor
called on x, or stores into it where the constructor was inlined or the type is a scalar), then
`___cxa_throw(x, typeinfo_for_T, destructor)`. plan() finds that shape in a function's HLIL; rewrite() turns
Pseudo C's lines of it into one line:
    throw T(args);    the constructor call `T::T(x, args)` (its name must be T's constructor's)
    throw v;          one store of a scalar `*x = v`
    throw T{a, b};    stores that do not overlap, the first at offset 0 (an inlined constructor), in offset order;
                      a vtable pointer stored at 0 is left out (the type says it)
The allocation, the construction and the `/* no return */` after the throw are left out. The construction must
come right before the throw and x must not be used anywhere else, or the statements stay as they are. Works on
lines keyed by (function start, HLIL instruction index), so the try planning and catch bodies can use it too.
"""
from binaryninja import HighLevelILOperation

from ..shared.hlil import walk
from ..shared.tokens import TT, tok
from . import eh_comments

Op = HighLevelILOperation
_THROW, _ALLOC = "cxa_throw", "cxa_allocate_exception"
_WRAPS = (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART)
_VTABLE = __import__("re").compile(r"^&?_*vtable_for_")
_SCALAR = __import__("re").compile(r"^(?:u?int\d+_t|(?:un)?signed\b.*|char\d*_t|wchar_t|char|short|int|long.*|bool|"
                                   r"float|double|.*\*)$")


class Throw:
    """one throw: kind 'ctor' / 'scalar' / 'aggregate', the type's name, the instruction index of the throw
    statement and of the construction statements (in order), and the ones to leave out"""
    __slots__ = ("kind", "type", "at", "parts", "drop", "alloc")

    def __init__(self, kind, type_, at, parts, drop):
        self.kind, self.type, self.at, self.parts, self.drop = kind, type_, at, parts, drop


def _strip(e):
    while e.operation in _WRAPS:
        e = e.src
    return e


def _callee(e):
    if e is None or e.operation not in (Op.HLIL_CALL, Op.HLIL_TAILCALL):
        return ""
    return str(e.dest).lstrip("_")


def _call(s):
    """the call a statement makes: the statement itself, or the value of an assignment / return"""
    if s.operation in (Op.HLIL_CALL, Op.HLIL_TAILCALL):
        return s
    if s.operation in (Op.HLIL_VAR_INIT, Op.HLIL_ASSIGN):
        return _strip(s.src) if _strip(s.src).operation == Op.HLIL_CALL else None
    if s.operation == Op.HLIL_RET and len(s.src) == 1 and _strip(s.src[0]).operation in (Op.HLIL_CALL,
                                                                                          Op.HLIL_TAILCALL):
        return _strip(s.src[0])
    return None


def _uses(e, var):
    return sum(1 for i in walk(e) if i.operation == Op.HLIL_VAR and i.var == var)


def _store_offset(dest, var):
    """the byte offset a store's destination writes into the object var points to, or None"""
    if dest.operation == Op.HLIL_DEREF:
        a = _strip(dest.src)
        if a.operation == Op.HLIL_VAR and a.var == var:
            return 0
        if a.operation == Op.HLIL_ADD and _strip(a.left).operation == Op.HLIL_VAR and _strip(a.left).var == var \
                and a.right.operation == Op.HLIL_CONST:
            return a.right.constant
    if dest.operation == Op.HLIL_ARRAY_INDEX and _strip(dest.src).operation == Op.HLIL_VAR \
            and _strip(dest.src).var == var and dest.index.operation == Op.HLIL_CONST:
        return dest.index.constant * dest.size
    if dest.operation in (Op.HLIL_DEREF_FIELD,) and _strip(dest.src).operation == Op.HLIL_VAR \
            and _strip(dest.src).var == var:
        return dest.offset
    if dest.operation == Op.HLIL_STRUCT_FIELD:  # x[1].d: a part of an element
        inner = _store_offset(dest.src, var)
        return inner + dest.offset if inner is not None else None
    return None


def _type_name(ti):
    """'std::runtime_error' from the typeinfo argument (a pointer to typeinfo_for_T), None if unknown"""
    e = _strip(ti)
    if e.operation == Op.HLIL_ADDRESS_OF:
        e = e.src
    if e.operation not in (Op.HLIL_CONST_PTR, Op.HLIL_IMPORT, Op.HLIL_EXTERN_PTR):
        return None
    sym = e.function.source_function.view.get_symbol_at(e.constant)
    return eh_comments.type_name(sym.full_name if sym is not None else str(e).lstrip("&"))


def _is_ctor(name, type_):
    """name is T's constructor ('std::runtime_error::runtime_error' for std::runtime_error)"""
    last = type_.rsplit("::", 1)[-1].split("<", 1)[0]
    return name.lstrip("_") == type_ + "::" + last or name.endswith("::" + last) and name.startswith(type_)


def plan(func):
    """{instruction index of a throw statement: Throw} for func's HLIL"""
    hlil = func.hlil
    if hlil is None or hlil.root is None:
        return {}
    out = {}
    for blk in walk(hlil.root):
        if blk.operation != Op.HLIL_BLOCK:
            continue
        stmts = list(blk.body)
        for k, s in enumerate(stmts):
            t = _one(stmts, k, s)
            if t is not None:
                out[t.at] = t
    return out


def _one(stmts, k, s):
    call = _call(s)
    if _callee(call) != _THROW or len(call.params) < 2:
        return None
    x = _strip(call.params[0])
    if x.operation != Op.HLIL_VAR:
        return None
    var = x.var
    type_ = _type_name(call.params[1])
    if not type_:
        return None
    alloc = None
    for j in range(k - 1, -1, -1):
        d = stmts[j]
        if d.operation in (Op.HLIL_VAR_INIT, Op.HLIL_ASSIGN) and _callee(_strip(d.src)) == _ALLOC and (
                d.dest == var if d.operation == Op.HLIL_VAR_INIT
                else d.dest.operation == Op.HLIL_VAR and d.dest.var == var):
            alloc = j
            break
    if alloc is None:
        return None
    # the construction: the statements right before the throw that use x
    first = k
    while first - 1 > alloc and _uses(stmts[first - 1], var):
        first -= 1
    if any(_uses(stmts[j], var) for j in range(alloc + 1, first)) or _uses(s, var) != 1:
        return None
    parts = stmts[first:k]
    if not parts:
        return None
    kind = None
    if len(parts) == 1 and parts[0].operation == Op.HLIL_CALL:
        c = parts[0]
        if c.params and _strip(c.params[0]).operation == Op.HLIL_VAR and _strip(c.params[0]).var == var \
                and _uses(c, var) == 1 and _is_ctor(str(c.dest), type_):
            kind = "ctor"
    elif all(p.operation == Op.HLIL_ASSIGN and _uses(p.src, var) == 0 and _uses(p.dest, var) == 1
             and _store_offset(p.dest, var) is not None for p in parts):
        spans = sorted(((_store_offset(p.dest, var), p.dest.size, p) for p in parts), key=lambda x: x[:2])
        if len(parts) == 1 and spans[0][0] == 0 and _SCALAR.match(type_):
            kind = "scalar"
        elif spans[0][0] == 0 and all(a[0] + a[1] <= b[0] for a, b in zip(spans, spans[1:])):
            kind = "aggregate"
            parts = [p for _o, _w, p in spans]
    if kind is None:
        return None
    drop = {stmts[alloc].instr_index} | {p.instr_index for p in parts}
    if k + 1 < len(stmts) and stmts[k + 1].operation == Op.HLIL_NORET:
        drop.add(stmts[k + 1].instr_index)
    t = Throw(kind, type_, s.instr_index, [p.instr_index for p in parts], drop)
    t.alloc = stmts[alloc].instr_index
    return t


# --- lines ------------------------------------------------------------------------------------------------------

def _flat(lines):
    """the tokens of a statement's lines as one line (continuation lines' indentation dropped)"""
    out = []
    for i, toks in enumerate(lines):
        toks = list(toks)
        if i:
            while toks and not toks[0].text.strip():
                toks.pop(0)
            out.append(tok(TT.TextToken, " "))
        out.extend(toks)
    while out and not out[-1].text.strip():
        out.pop()
    return out


def _lead(toks):
    """the leading whitespace tokens, and the rest"""
    n = 0
    while n < len(toks) and not toks[n].text.strip():
        n += 1
    return toks[:n], toks[n:]


def _after_first_arg(toks):
    """the tokens of a call line `f(x, a, b);` after `x, ` up to the closing `)` -> `a, b`"""
    text = [t.text for t in toks]
    try:
        start = next(i for i, t in enumerate(text) if t.endswith("("))
    except StopIteration:
        return None
    depth, i, comma = 0, start, None
    for i in range(start, len(toks)):
        depth += text[i].count("(") - text[i].count(")")
        if depth == 1 and comma is None and "," in text[i] and i > start:
            comma = i
        if depth <= 0:
            break
    else:
        return None
    if comma is None:
        return []
    args = toks[comma + 1:i]
    while args and not args[0].text.strip():
        args = args[1:]
    return args


def _value(toks):
    """the right-hand side of a store line `*x = v;`"""
    text = [t.text for t in toks]
    try:
        eq = next(i for i, t in enumerate(text) if t.strip() == "=")
    except StopIteration:
        return None
    v = toks[eq + 1:]
    while v and v[-1].text.strip() in (";", ""):
        v = v[:-1]
    while v and not v[0].text.strip():
        v = v[1:]
    return v


def rewrite(lines, plans):
    """lines [(tokens, key)] with key (function start, instruction index) or None; plans {function start:
    plan(func)} -> the lines with each planned throw as one `throw ...;` line (a throw whose construction lines
    are not among the lines stays as it is)"""
    throws = {}
    for start, p in plans.items():
        for t in p.values():
            throws[(start, t.at)] = (start, t)
    by_key = {}
    for toks, key in lines:
        if key is not None:
            by_key.setdefault(key, []).append(toks)
    done, drop = {}, set()
    for key, (start, t) in throws.items():
        if key not in by_key or any((start, i) not in by_key for i in t.parts + [t.alloc]):
            continue
        parts = [_flat(by_key[(start, i)]) for i in t.parts]
        lead, _ = _lead(list(by_key[key][0]))
        if t.kind == "ctor":
            args = _after_first_arg(parts[0])
            if args is None:
                continue
            body = [tok(TT.TypeNameToken, t.type), tok(TT.TextToken, "(")] + args + [tok(TT.TextToken, ")")]
        else:
            vals = [_value(p) for p in parts]
            if any(not v for v in vals):
                continue
            if t.kind == "scalar":
                body = vals[0]
            else:
                if _VTABLE.match("".join(x.text for x in vals[0])):
                    vals = vals[1:]
                if not vals:  # only the vptr: a default constructor
                    body = [tok(TT.TypeNameToken, t.type), tok(TT.TextToken, "()")]
                else:
                    body = [tok(TT.TypeNameToken, t.type), tok(TT.TextToken, "{")]
                    for n, v in enumerate(vals):
                        body += ([tok(TT.TextToken, ", ")] if n else []) + v
                    body.append(tok(TT.TextToken, "}"))
        done[key] = lead + [tok(TT.KeywordToken, "throw"), tok(TT.TextToken, " ")] + body + [
            tok(TT.TextToken, ";")]
        drop |= {(start, i) for i in t.drop}
    if not done:
        return lines
    out, seen = [], set()
    for toks, key in lines:
        if key in done:
            if key not in seen:
                seen.add(key)
                out.append((done[key], key))
            continue
        if key in drop:
            continue
        out.append((toks, key))
    return out

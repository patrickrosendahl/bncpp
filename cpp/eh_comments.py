"""The exception tables as comments at the top of a Pseudo Cpp function (bncpp-5).

The first output from the LSDA before try/catch is rendered (bncpp-6). An owner (a function with an LSDA)
lists its call sites that have a landing pad: the range, the pad (and the function BN has there), and the action
chain -- catch clauses with their selector value, the number the pad's dispatch compares (`if (arg3 != 2)`),
cleanup, exception specifications. Call sites without a pad (unwinding goes straight through) are left out. A
landing-pad function names its owner and the call sites that lead to it, with the same clauses.

The tables are decoded once per view (lsda.parse_all through BNImage) and kept for the session; they don't
change with analysis, only the names printed next to them do (looked up at render time).
"""
from . import lsda as _lsda
from .bnimage import BNImage

_TYPEINFO = "typeinfo_for_"


class Index:
    def __init__(self, bv):
        self.owners = _lsda.parse_all(BNImage(bv))  # {function start: LSDA}
        self.pads = {}                              # {pad: [(owner start, CallSite)]}
        for start, table in self.owners.items():
            for cs in table.call_sites:
                if cs.landing_pad is not None:
                    self.pads.setdefault(cs.landing_pad, []).append((start, cs))


_indexes = {}  # session id -> Index


def index(bv):
    key = bv.file.session_id
    ix = _indexes.get(key)
    if ix is None:
        ix = _indexes[key] = Index(bv)
    return ix


def type_name(t):
    """a catch type as C++ spells it: 'typeinfo_for_std::runtime_error' -> 'std::runtime_error'"""
    if t is None:
        return "..."
    if isinstance(t, int):
        return "%#x" % t
    return t[len(_TYPEINFO):] if t.startswith(_TYPEINFO) else t


def clause_text(c):
    if c.kind == c.CATCH:
        return "catch (%s) #%d" % (type_name(c.type), c.type_index)
    if c.kind == c.SPEC:
        return "throw (%s)" % ", ".join(type_name(t) for t in c.type)
    return "cleanup"


def clauses_text(cs):
    return ", ".join(clause_text(c) for c in cs.clauses) if cs.clauses else "cleanup"


def _name(bv, addr):
    f = bv.get_function_at(addr)
    if f is not None:
        return f.symbol.full_name
    inside = bv.get_functions_containing(addr)
    return "(inside %s)" % inside[0].symbol.full_name if inside else "(in no function)"


def _where(bv, cs, owner):
    """' (in f)' when the call site is not in the function at owner (a handler BN split off, a shared tail)"""
    funcs = bv.get_functions_containing(cs.start)
    if not funcs or any(f.start == owner for f in funcs):
        return ""
    return " (in %s)" % funcs[0].symbol.full_name


def lines(bv, start):
    """the comment lines (without '// ') for the function at start: [] if it neither has an LSDA nor is a pad"""
    ix = index(bv)
    out = []
    table = ix.owners.get(start)
    if table is not None:
        sites = [cs for cs in table.call_sites if cs.landing_pad is not None]
        catches = any(c.kind == c.CATCH for cs in sites for c in cs.clauses)
        out.append("exception table (LSDA %#x): %d of %d call sites have a landing pad%s"
                   % (table.addr, len(sites), len(table.call_sites), "; #n = the selector value" if catches else ""))
        for cs in sites:
            out.append("  %#x..%#x%s -> %#x %s: %s" % (cs.start, cs.end, _where(bv, cs, start), cs.landing_pad,
                                                       _name(bv, cs.landing_pad), clauses_text(cs)))
    prev = None
    for owner, cs in ix.pads.get(start, []):
        if owner != prev:
            out.append("landing pad of %s @ %#x" % (_name(bv, owner), owner))
            prev = owner
        out.append("  from %#x..%#x%s: %s" % (cs.start, cs.end, _where(bv, cs, owner), clauses_text(cs)))
    return out

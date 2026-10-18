"""try/catch in Pseudo Cpp from the LSDA (bncpp-6): planning; cpp/pseudo_cpp.py emits.

Try regions. A call site's catch chain (its action chain's catch clauses, innermost first) says which try blocks
enclose the call: a chain (A, B) is a try with catch (A) inside a try with catch (B) -- or one try with both
clauses, which the table cannot tell apart from that and which means the same. Level L of the nesting is the
chain's last L entries: consecutive call sites with the same level-L suffix form one region (a call site
without it -- an unwind-only or cleanup-only call, or another try's -- ends the region). A region that covers
exactly the call sites of its enclosing one is the same try with one more clause. Cleanups never make a region
(destructor-only pads are the unwind path of a scope, not a catch); neither does a catch (...) whose pad is a
terminate guard (a noexcept boundary). Only call sites in the owner's own function count -- the calls of a
handler BN split off (a rethrow, a call inside a catch body) are in the pad's function.

Handler bodies. The handler of clause n is the code of the region's landing pad with the selector fixed to n --
the pad's dispatch tests the selector against the type numbers (`if (arg3 != 2)`). specialize() walks the pad's
HLIL with the selector known: a test on it takes the branch it takes for n, statements after a branch that ends
in a return / tail call / no-return are dead for n, copies of the selector (a -O0 pad stores it to the stack,
or into a variable it then tests) are left out. Joins, nested tests and the no-match path (resume unwinding)
fall out of that. A pad serving several clauses without any test on the selector is not split (None).
"""
from binaryninja import HighLevelILOperation, VariableSourceType

from ..shared.hlil import walk
from . import eh_comments

Op = HighLevelILOperation

# the register the personality hands the selector in (__builtin_eh_return_data_regno(1))
SELECTOR_REG = {"x86_64": "rdx", "aarch64": "x1"}
_TERMINATORS = (Op.HLIL_RET, Op.HLIL_TAILCALL, Op.HLIL_NORET, Op.HLIL_UNREACHABLE, Op.HLIL_JUMP)
# a call in a try is never a tail call (it needs its landing pad): tail calls are no evidence of a region
_CALLS = (Op.HLIL_CALL, Op.HLIL_CALL_SSA)
_WRAPS = (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART)


class Region:
    __slots__ = ("start", "end", "sites", "clauses")

    def __init__(self, start, end, sites, clauses):
        self.start, self.end = start, end  # [start, end) of the call sites
        self.sites = sites                 # [CallSite]
        self.clauses = clauses             # [(Clause, pad)], in the order the personality tries them

    def __repr__(self):
        return "Region(%#x..%#x %s)" % (self.start, self.end, ", ".join(
            "%s -> %#x" % (eh_comments.clause_text(c), p) for c, p in self.clauses))


def _in(func, addr):
    return any(f.start == func.start for f in func.view.get_functions_containing(addr))


def is_terminate_guard(bv, pad):
    f = bv.get_function_at(pad)
    if f is None:
        return False
    return any("terminate" in (bv.get_function_at(t).name if bv.get_function_at(t) else "")
               for site in f.call_sites for t in bv.get_callees(site.address, f, site.arch))


def regions(func):
    """the try regions of func from its LSDA: [Region], outer before inner"""
    bv = func.view
    table = eh_comments.index(bv).owners.get(func.start)
    if table is None:
        return []
    sites = [cs for cs in table.call_sites if _in(func, cs.start)]
    chains = []
    for cs in sites:
        chain = [c for c in cs.clauses if c.kind == c.CATCH] if cs.landing_pad is not None else []
        if len(chain) == 1 and chain[0].type is None and is_terminate_guard(bv, cs.landing_pad):
            chain = []
        chains.append(chain)
    out = []
    prev = {}  # site index tuple -> Region of the level above
    for level in range(1, max((len(c) for c in chains), default=0) + 1):
        runs, key = [], None
        for i, chain in enumerate(chains):
            k = tuple(c.type_index for c in chain[-level:]) if len(chain) >= level else None
            if k is not None and k == key:
                runs[-1].append(i)
            elif k is not None:
                runs.append([i])
            key = k
        cur = {}
        for idxs in runs:
            clause = chains[idxs[0]][-level]
            pad = _pad(sites[i] for i in idxs)
            r = prev.get(tuple(idxs))
            if r is not None:
                r.clauses.insert(0, (clause, pad))  # the same try, one more clause (tried first)
            else:
                r = Region(sites[idxs[0]].start, sites[idxs[-1]].end, [sites[i] for i in idxs], [(clause, pad)])
                out.append(r)
            cur[tuple(idxs)] = r
        prev = cur
    return out


def _pad(sites):
    """the landing pad most of the call sites share (the first on a tie)"""
    count, order = {}, []
    for cs in sites:
        if cs.landing_pad not in count:
            order.append(cs.landing_pad)
        count[cs.landing_pad] = count.get(cs.landing_pad, 0) + 1
    return max(order, key=lambda p: count[p])


def call_addrs(stmt):
    """the addresses of the calls in stmt (try_runs' 'pcs'); [] if it has none"""
    return [i.address for i in walk(stmt) if i.operation in _CALLS]


def body(instr):
    if instr is None:
        return []
    return list(instr.body) if instr.operation == Op.HLIL_BLOCK else [instr]


def selector_vars(func):
    reg = SELECTOR_REG.get(func.arch.name)
    if reg is None:
        return set()
    return {v for v in func.parameter_vars
            if v.source_type == VariableSourceType.RegisterVariableSourceType
            and func.arch.get_reg_name(v.storage) == reg}


class _Selector:
    """what holds the selector: variables, and memory slots it was stored to (by address expression text)"""

    def __init__(self, vars_):
        self.vars, self.mem = set(vars_), set()

    def holds(self, e):
        while e.operation in _WRAPS:
            e = e.src
        if e.operation == Op.HLIL_VAR:
            return e.var in self.vars
        return e.operation == Op.HLIL_DEREF and str(e.src) in self.mem

    def copy(self, s):
        """s copies the selector somewhere: remember where, True"""
        if s.operation == Op.HLIL_VAR_INIT and self.holds(s.src):
            self.vars.add(s.dest)
            return True
        if s.operation == Op.HLIL_ASSIGN and self.holds(s.src):
            if s.dest.operation == Op.HLIL_VAR:
                self.vars.add(s.dest.var)
                return True
            if s.dest.operation == Op.HLIL_DEREF:
                self.mem.add(str(s.dest.src))
                return True
        return False

    def test(self, cond):
        """cond as a function of the selector value, or None if it is no test on the selector"""
        neg = False
        while cond.operation == Op.HLIL_NOT:
            neg, cond = not neg, cond.src
        if cond.operation not in (Op.HLIL_CMP_E, Op.HLIL_CMP_NE):
            return None
        a, b = cond.left, cond.right
        if b.operation != Op.HLIL_CONST:
            a, b = b, a
        if b.operation != Op.HLIL_CONST or not self.holds(a):
            return None
        k, eq = b.constant, (cond.operation == Op.HLIL_CMP_E) != neg
        return lambda n: (n == k) == eq


def specialize(pad_func, n, clauses_on_pad):
    """the statements of pad_func's handler for selector value n: [HLIL statement], or None where the pad
    serves several clauses but has no test on the selector (or no HLIL)"""
    hlil = pad_func.hlil
    if hlil is None or hlil.root is None:
        return None
    sel = _Selector(selector_vars(pad_func))
    out = []
    tests = [0]

    def visit(stmts):
        """append the live statements; True if the path ended (return, tail call, no return)"""
        for s in stmts:
            if sel.copy(s):
                continue
            if s.operation == Op.HLIL_IF:
                t = sel.test(s.condition)
                if t is not None:
                    tests[0] += 1
                    if visit(body(s.true if t(n) else s.false)):
                        return True
                    continue
            if s.operation != Op.HLIL_NOP:  # Pseudo C leaves them out of a block too
                out.append(s)
            if s.operation in _TERMINATORS:
                return True
        return False

    visit(body(hlil.root))
    if not tests[0] and clauses_on_pad > 1:
        return None
    return out

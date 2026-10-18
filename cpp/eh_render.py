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
import re as _re

from binaryninja import HighLevelILOperation, VariableSourceType

from ..shared.hlil import walk
from . import eh_comments

Op = HighLevelILOperation

# the registers the personality hands the exception pointer and the selector in
# (__builtin_eh_return_data_regno(0) / (1))
EXCEPTION_REG = {"x86_64": "rax", "aarch64": "x0"}
SELECTOR_REG = {"x86_64": "rdx", "aarch64": "x1"}
_TERMINATORS = (Op.HLIL_RET, Op.HLIL_TAILCALL, Op.HLIL_NORET, Op.HLIL_UNREACHABLE, Op.HLIL_JUMP)
# a call in a try is never a tail call (it needs its landing pad): tail calls are no evidence of a region
_CALLS = (Op.HLIL_CALL, Op.HLIL_CALL_SSA)
_WRAPS = (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART)
LOOPS = (Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_FOR)


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


def param_vars(func, regs):
    """func's parameter variables in the register regs[arch] (EXCEPTION_REG / SELECTOR_REG)"""
    reg = regs.get(func.arch.name)
    if reg is None:
        return set()
    return {v for v in func.parameter_vars
            if v.source_type == VariableSourceType.RegisterVariableSourceType
            and func.arch.get_reg_name(v.storage) == reg}


class _Holder:
    """what holds a value the personality passed in (the selector, the exception pointer): variables, and memory
    slots it was stored to (by address expression text)"""

    def __init__(self, vars_):
        self.vars, self.mem = set(vars_), set()

    def holds(self, e):
        e = _strip(e)
        if e.operation == Op.HLIL_VAR:
            return e.var in self.vars
        return e.operation == Op.HLIL_DEREF and str(e.src) in self.mem

    def copy(self, s):
        """s copies the value somewhere: remember where, True"""
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


class Handler:
    """a clause's handler code: stmts (the live statements) and cont, the address where it goes on in the owner's
    own code (None: it returns, tail-calls or does not return)"""

    def __init__(self, stmts, cont):
        self.stmts, self.cont = stmts, cont


def specialize(pad_func, n, clauses_on_pad, owner=None):
    """pad_func's handler for selector value n (a Handler), or None where the pad serves several clauses but has
    no test on the selector (or no HLIL). With owner, the handler ends where the pad's code runs on into a basic
    block of owner: BN follows the jump back from the catch body into the owner and copies the owner's code from
    there (the rest of a loop around the try) into the pad function -- that is the code after the try. A tail
    call into code that still dispatches or catches (a cleanup pad jumping to the shared dispatch, a catch body
    BN split off) is followed (bncpp-64)."""
    r = _specialize(pad_func, n, owner, _Holder(param_vars(pad_func, SELECTOR_REG)), 0)
    if r is None:
        return None
    stmts, cont, tests = r
    if not tests and clauses_on_pad > 1:
        return None
    return Handler(stmts, cont)


def _specialize(func, n, owner, sel, depth):
    """(live statements, continuation | None, selector tests resolved) of func with the selector known to sel"""
    hlil = func.hlil
    if hlil is None or hlil.root is None:
        return None
    out, cont, tests = [], [], [0]

    def visit(stmts):
        """append the live statements; True if the path ended (return, tail call, no return, the owner's code)"""
        for s in stmts:
            if owner is not None and owner.get_basic_block_at(s.address) is not None:
                cont.append(s.address)
                return True
            if sel.copy(s):
                continue
            if s.operation == Op.HLIL_IF:
                t = sel.test(s.condition)
                if t is not None:
                    tests[0] += 1
                    if visit(body(s.true if t(n) else s.false)):
                        return True
                    continue
            if s.operation == Op.HLIL_TAILCALL and depth < 3:
                f = _follow(func, s, n, owner, sel, depth)
                if f is not None:
                    out.extend(f[0])
                    cont.extend([f[1]] if f[1] is not None else [])
                    tests[0] += f[2]
                    return True
            if s.operation != Op.HLIL_NOP:  # Pseudo C leaves them out of a block too
                out.append(s)
            if s.operation in _TERMINATORS:
                return True
        return False

    visit(body(hlil.root))
    return out, (cont[0] if cont else None), tests[0]


def _follow(func, call, n, owner, sel, depth):
    """_specialize of the function a handler tail-calls, if it is handler code: it tests the selector or calls
    begin/end_catch. The selector's holders carry over by argument position (a -O0 pad passes its frame pointer:
    the slot `(char*)arg5 - 0x24` is `(char*)arg1 - 0x24` in the callee)"""
    if call.dest.operation != Op.HLIL_CONST_PTR:
        return None
    target = func.view.get_function_at(call.dest.constant)
    if target is None or target.start == func.start or (owner is not None and target.start == owner.start):
        return None
    params = list(target.parameter_vars)
    seeded = _Holder(param_vars(target, SELECTOR_REG))
    rename = {}
    for i, arg in enumerate(call.params):
        arg = _strip(arg)
        if arg.operation == Op.HLIL_VAR and i < len(params):
            rename[arg.var.name] = params[i].name
            if arg.var in sel.vars:
                seeded.vars.add(params[i])
    for m in sel.mem:
        seeded.mem.add(_re.sub(r"\b\w+\b", lambda w: rename.get(w.group(0), w.group(0)), m))
    r = _specialize(target, n, owner, seeded, depth + 1)
    if r is None:
        return None
    if r[2] or any(callee(i) in (_BEGIN, _END) for st in r[0] for i in walk(st)):
        return r
    return None


# --- EH plumbing in a catch body (bncpp-7) ------------------------------------------------------------------------

_BEGIN, _END, _RETHROW = "cxa_begin_catch", "cxa_end_catch", "cxa_rethrow"
_SCALAR = __import__("re").compile(r"^(?:u?int\d+_t|(?:un)?signed\b.*|char\d*_t|wchar_t|char|short|int|long.*|bool|"
                                   r"float|double|.*\*)$")


def callee(e):
    """the plain name of the function an HLIL_CALL calls ('cxa_begin_catch'), '' if unknown"""
    if e is None or e.operation not in (Op.HLIL_CALL, Op.HLIL_TAILCALL):
        return ""
    return str(e.dest).lstrip("_")


def _strip(e):
    """e without extensions, low parts and offset-0 field accesses (`arg2.d`: the selector's low 32 bits)"""
    while e.operation in _WRAPS or (e.operation == Op.HLIL_STRUCT_FIELD and e.offset == 0):
        e = e.src
    return e


def catch_var(type_name):
    """the catch header's declarator: 'e' for a scalar or pointer type, '&e' for a class (caught by reference);
    None for catch (...)"""
    if type_name == "...":
        return None
    return "e" if _SCALAR.match(type_name) else "&e"


class Plumbing:
    """what the catch body of one clause hides and renames:
      stmts     the statements that remain
      rethrow   expr indexes of `___cxa_rethrow()` statements, printed as `throw;`
      names     {variable name: text} -- a variable that holds the exception object's address prints as '&e',
                one that holds a scalar exception's value as 'e'"""

    def __init__(self, stmts, rethrow, names):
        self.stmts, self.rethrow, self.names = stmts, rethrow, names


def plumbing(pad_func, stmts, type_name):
    """hide the EH plumbing in stmts, the catch body of a clause catching type_name (from specialize):
    begin/end_catch statements, the exception pointer's copies (a -O0 pad stores it to the stack), the `/* no
    return */` after a rethrow; `T v = ___cxa_begin_catch(x)` names the catch variable"""
    exn = _Holder(param_vars(pad_func, EXCEPTION_REG))
    var = catch_var(type_name)
    out, rethrow, names = [], set(), {}
    after_rethrow = False
    for s in stmts:
        if after_rethrow and s.operation == Op.HLIL_NORET:
            continue
        after_rethrow = False
        if exn.copy(s):
            continue
        name = callee(s)
        if name in (_BEGIN, _END):
            continue
        if name == _RETHROW:
            rethrow.add(s.expr_index)
            out.append(s)
            after_rethrow = True
            continue
        if var is not None and s.operation == Op.HLIL_VAR_INIT:
            src = _strip(s.src)
            if callee(src) == _BEGIN:  # void* rax = ___cxa_begin_catch(x): the object's address
                names[s.dest.name] = "&e"
                continue
            if var == "e" and src.operation == Op.HLIL_DEREF and callee(_strip(src.src)) == _BEGIN:
                names[s.dest.name] = "e"  # int32_t v = *(int32_t*)___cxa_begin_catch(x): the value
                continue
        out.append(s)
    if var is None:  # catch (...): `void* x = ___cxa_begin_catch(e)` with x used nowhere else goes too
        unused = [s for s in out if s.operation == Op.HLIL_VAR_INIT and callee(_strip(s.src)) == _BEGIN and not any(
            i.operation == Op.HLIL_VAR and i.var == s.dest for o in out if o is not s for i in walk(o))]
        out = [s for s in out if all(s is not u for u in unused)]
    return Plumbing(out, rethrow, names)


def loop_for(stmts, region, cont):
    """the index of the loop in stmts the region's try sits inside (bncpp-64), or None: every call of the block in
    the region's range is in that loop, and so is the handler's continuation -- after the catch, the loop goes on"""
    if cont is None:
        return None
    inside = [a for s in stmts for a in call_addrs(s) if region.start <= a < region.end]
    if not inside:
        return None
    for k, s in enumerate(stmts):
        if s.operation not in LOOPS:
            continue
        addrs = [i.address for i in walk(s)]
        if min(addrs) <= cont <= max(addrs) and set(inside) <= set(call_addrs(s)):
            return k
    return None

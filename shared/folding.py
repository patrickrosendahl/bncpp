# shared with binary-jvm/shared/folding.py (the folding core of jvm-46/60 and bncpp-11/13/106; synced at
# binary-jvm d67a36e); keep language-neutral
"""Evaluation-order-safe folding of single-use temporaries (bncpp-13, jvm-46).

A temporary that a function assigns once and reads once can be printed at its single use instead of on its own
line (`int t = a + b; return f(t);` -> `return f(a + b);`) -- but only when moving its value past the statements
in between does not change what runs, in what order. That is the whole difficulty, and it is language-neutral:
it depends only on side effects (does a node run a call / write memory?) and on memory reads (does the value
read memory that something in between writes?). FoldMixin does that analysis over a flat statement list and
records the decision; the language class turns it into tokens.

What the language class must provide (hooks):
  hlil                              the HighLevelILFunction (for .root; used to count defs / uses)
  side_effect(instr)   -> bool      the node, evaluated, runs a call or writes memory (HLIL_CALL / assignments /
                                    an intrinsic that is not pure). A fold is refused if anything evaluated
                                    before the temporary's use has a side effect.
  reads_memory(instr)  -> bool      the node reads memory (a load / field / array index). A fold of a value that
                                    is not pure is refused if anything evaluated before the use reads memory
                                    (the value might depend on memory the in-between code wrote).
Optional hooks (the defaults keep the mixin usable on its own):
  foldable_var(var)    -> bool      False for a variable that must never fold (e.g. an exception temporary,
                                    `this`); default: everything folds.
  foldable_value(e)    -> bool      False for a definition value that must stay on its own line; default True.
  fold_declared                     class attribute: also fold `T x; .. x = v; use(x)` (default True)
  value_parts(value)   -> [expr]    the expressions a language's own tuple value evaluates, in order (the "own"
                                    plan key, or tuples the language puts into self.inline itself)
  eval_operands(e)     -> [expr] | None   the operands of e in evaluation order when the language evaluates e
                                    differently from its HLIL operands (e.g. a string concatenation: its
                                    operands), else None
  fold_use_ok(body, j, plan) -> bool      body[j] may receive a folded value (default True; labels, gotos and
                                    loops never do)
  fold_transparent(body, j, plan)   body[j] prints nothing between a definition and its use (default: NOPs,
                                    folded statements, plan["hidden_decls"])
  fold_skip(body, j, var, value, value_pure) -> bool   var's value may move past body[j], a printed statement
                                    that is not its use (default False: a fold goes into the next statement)
  strip(e)                          e without the wraps a load / temporary may carry (default: zx / sx /
                                    low_part / offset-0 field of a variable, as native HLIL prints them)
  incdec_store(st)     -> (value stored, same(e)) | None   st stores to a variable / memory and same(e) tells
                                    whether e is that same location (default: HLIL_ASSIGN)
  incdec_target(st, load) -> expr   what prints as f in f++ / ++f (default: the store's destination)

FoldMixin keeps:
  self.inline   {var: value}        folded temporaries: their single use prints this value in their place. The
                                    language emitter substitutes it. A value is an expression or a tuple:
                  ("ternary", x, if, a, b[, flip])          c ? a : b (flip: print it turned round, !c ? b : a)
                  ("incdec", f, "+"/"-", pre, store index, store)   f++ / ++f; the store prints with it
                  (kind, ...)                                a language's own (value_parts)
A plan is a dict the mixin fills in place:
  "skip"     {index}                statements another pass already placed elsewhere (not folded here)
  "folded"   {index}                definitions whose value moved into a later statement (do not print)
  "incdec"   {index: (t, value)}    post/pre increment candidates (plan_incdec); folded like any temporary
  "ternary"  {index: (x, value)}    ternary candidates another pass placed (fold_candidate reads them)
  "own"      {index: (x, value, pure, {index})}  a language's own candidates: value a tuple of its own kind
                                    (evaluated as value_parts(value)), folded with the listed statements
  "part_of"  {index: index}         statements printed as part of a later one (a concatenation's appends): a
                                    fold may pass them only into that statement
  "evaluated_at" [(index, expr)]    operands that run at an earlier statement than where they print: a fold of a
                                    definition after that statement does not move past them
"""
from binaryninja import HighLevelILOperation

from .hlil import children, walk

Op = HighLevelILOperation

_WRAPS = (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART)
# a compound store `*(a) op= v` is ASSIGN(dest, op(<a copy of dest>, v)); the copy is not printed (bncpp-106)
_COMPOUND_OPS = (Op.HLIL_ADD, Op.HLIL_SUB, Op.HLIL_MUL, Op.HLIL_AND, Op.HLIL_OR, Op.HLIL_XOR, Op.HLIL_LSL,
                 Op.HLIL_LSR, Op.HLIL_ASR)
_MEMORY_LVALUES = (Op.HLIL_DEREF, Op.HLIL_DEREF_FIELD, Op.HLIL_ARRAY_INDEX)
_VARS = (Op.HLIL_VAR, Op.HLIL_VAR_SSA)


class FoldMixin:
    # the language class sets these; defaults keep the mixin usable on its own
    inline = None
    fold_declared = True

    def foldable_var(self, var):
        return True

    def foldable_value(self, value):
        return True

    def value_parts(self, value):
        """the expressions a language's own tuple value evaluates, in order"""
        return ()

    def eval_operands(self, e):
        return None

    def fold_use_ok(self, body, j, plan):
        return True

    def fold_skip(self, body, j, var, value, value_pure):
        return False

    def strip(self, e):
        return _strip(e)

    def incdec_store(self, st):
        if st.operation != Op.HLIL_ASSIGN:
            return None
        return st.src, lambda e: self.same_lvalue(st.dest, e)

    def incdec_target(self, st, load):
        return st.dest

    def same_lvalue(self, a, b):
        return _same_lvalue(a, b)

    # --- counting ---------------------------------------------------------------------------------------

    def _counts(self):
        if getattr(self, "_fold_counts", None) is None:
            uses, defs = {}, {}
            try:
                for i in walk_printed(self.hlil.root):
                    if i.operation == Op.HLIL_VAR:
                        uses[i.var] = uses.get(i.var, 0) + 1
                    elif i.operation == Op.HLIL_VAR_INIT:
                        defs[i.dest] = defs.get(i.dest, 0) + 1
                    elif i.operation == Op.HLIL_VAR_DECLARE:
                        defs[i.var] = defs.get(i.var, 0) + 2  # declared apart from its assignment
            except Exception:
                pass
            self._fold_counts = (uses, defs)
        return self._fold_counts

    def var_count(self, var):
        return self._counts()[0].get(var, 0)

    def def_count(self, var):
        return self._counts()[1].get(var, 0)

    @staticmethod
    def refs(instr, var):
        return sum(1 for i in walk_printed(instr) if i.operation == Op.HLIL_VAR and i.var == var)

    def _addr_taken(self):
        """variables whose address is taken somewhere: their storage identity matters, so they must never fold
        (`int t = a; f(&t)` is not `f(&a)` -- the addresses differ even when the values are equal)"""
        if getattr(self, "_addr_set", None) is None:
            s = set()
            try:
                for i in walk(self.hlil.root):
                    if i.operation == Op.HLIL_ADDRESS_OF and i.src.operation == Op.HLIL_VAR:
                        s.add(i.src.var)
            except Exception:
                pass
            self._addr_set = s
        return self._addr_set

    # --- purity -----------------------------------------------------------------------------------------

    def pure(self, e):
        """e, evaluated, has no side effect"""
        return not any(self.side_effect(i) for i in self.eval_nodes(e)[0])

    def eval_nodes(self, e, stop_var=None, out=None):
        """the nodes of e in evaluation order (operands before the operation), folded temporaries expanded to
        their value. With stop_var: stop at its read and return (nodes before it, True); a read reached only on a
        conditionally evaluated path (the right side of && / ||, a ?:) returns (.., None) -- the value cannot be
        moved there, it might not run."""
        if out is None:
            out = []
        o = e.operation
        if o in _VARS:
            if stop_var is not None and e.var == stop_var:
                return out, True
            value = (self.inline or {}).get(e.var)
            if value is not None and not isinstance(value, tuple):
                return self.eval_nodes(value, stop_var, out)
            if isinstance(value, tuple) and value[0] == "ternary":
                # c ? a : b: the condition runs first; a and b only maybe -- their nodes count (a call in either
                # still runs before what follows), but nothing can be moved into them
                r = self.eval_nodes(value[2].condition, stop_var, out)
                if r[1] is not False:
                    return r
                if stop_var is not None and any(self.refs(v, stop_var) for v in value[3:5]):
                    return out, None
                for v in value[3:5]:
                    self.eval_nodes(v, None, out)
            elif isinstance(value, tuple) and value[0] == "incdec":
                # f++: f is read, then the store writes it back
                r = self.eval_nodes(value[1], stop_var, out)
                if r[1] is not False:
                    return r
                out.append(value[5])
            elif isinstance(value, tuple):
                for v in self.value_parts(value):
                    r = self.eval_nodes(v, stop_var, out)
                    if r[1] is not False:
                        return r
            out.append(e)
            return out, False
        kids = self.eval_operands(e)
        if kids is not None:
            pass
        # the right operand of a short-circuit && / || is only evaluated when the left allows it
        elif o in (Op.HLIL_AND, Op.HLIL_OR) and _is_bool(e):
            r = self.eval_nodes(e.left, stop_var, out)
            if r[1] is not False:
                return r
            if stop_var is not None and self.refs(e.right, stop_var):
                return out, None
            kids = [e.right]
        elif o in (Op.HLIL_IF, Op.HLIL_SWITCH):
            kids = [e.condition]
        elif o == Op.HLIL_ASSIGN and compound_copy(e) is not None:
            kids = [e.dest, e.src.right]  # the address once, then the operand; the copy's load is the store's own
        elif o == Op.HLIL_ASSIGN:
            # a store evaluates its target's address, not the target: a local is no read, `*p = v` no load of *p
            d = e.dest
            kids = ([] if d.operation == Op.HLIL_VAR else list(children(d))) + [e.src]
        elif o in (Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_FOR, Op.HLIL_BLOCK):
            if stop_var is not None:
                return out, None  # a loop/block body is not a place a value can be moved into
            kids = []
        else:
            kids = list(children(e))
        for c in kids:
            r = self.eval_nodes(c, stop_var, out)
            if r[1] is not False:
                return r
        out.append(e)
        return out, False

    # --- candidates -------------------------------------------------------------------------------------

    def fold_candidate(self, body, k, plan):
        """(var, value, value is pure) when body[k] defines a temporary read exactly once, else None"""
        s = body[k]
        if k in plan.get("ternary", {}):
            var, value = plan["ternary"][k]
            if self.var_count(var) - self.refs(s, var) != 1:
                return None
            return var, value, all(self.pure(v) for v in (value[2].condition, value[3], value[4]))
        if k in plan.get("incdec", {}):
            var, value = plan["incdec"][k]
            return var, value, False
        if k in plan.get("own", {}):
            return plan["own"][k][:3]
        if k in plan.get("skip", ()):
            return None
        if s.operation == Op.HLIL_VAR_INIT:
            var, uses = s.dest, 1
        elif self.fold_declared and s.operation == Op.HLIL_ASSIGN and s.dest.operation == Op.HLIL_VAR and \
                self.declared(s.dest.var):
            var, uses = s.dest.var, 2  # `T x; .. x = v; use(x)`: the store's own read of x and the use
        else:
            return None
        if self.var_count(var) != uses or (uses == 1 and self.def_count(var) != 1) or var in self._addr_taken() or \
                not self.foldable_var(var) or not self.foldable_value(s.src):
            return None
        return var, s.src, self.pure(s.src)

    def declared(self, var):
        """var has a declaration of its own and no initialized definition (its assignments are HLIL_ASSIGNs)"""
        return self.def_count(var) == 2

    def fold_lists(self, root):
        """the statement lists plan_folds runs on: every HLIL block's body; a do-while's body with the loop
        condition as a last item, so the body's last statements can fold into it (`t = i; i -= 1; } while (t)`
        -> `} while (i--)`) -- not when the body has a `continue` of this loop, which skips them"""
        conds = {}
        for i in walk(root):
            if i.operation == Op.HLIL_DO_WHILE and i.body.operation == Op.HLIL_BLOCK and not _continues(i.body):
                conds[i.body.expr_index] = i.condition
        for blk in walk(root):
            if blk.operation == Op.HLIL_BLOCK:
                body = list(blk.body)
                if blk.expr_index in conds:
                    body.append(conds[blk.expr_index])
                yield body

    def fold_transparent(self, body, j, plan):
        """body[j] is not printed between a definition and its use and has nothing that matters in between"""
        s = body[j]
        if j in plan.get("folded", ()):
            return True  # its value moved into a later use
        return s.operation in (Op.HLIL_NOP,) or \
            (s.operation == Op.HLIL_VAR_DECLARE and j in plan.get("hidden_decls", ()))

    # --- planning ---------------------------------------------------------------------------------------

    def plan_folds(self, body, lo, hi, plan, barrier=()):
        """fold each temporary of body[lo..hi] into its use where it is safe; barrier: indexes a fold may not
        cross (e.g. a try run). Folds are decided from the last statement back, so a chain `a=..; b=f(a); g(b)`
        collapses (b folds into g, then a folds into the folded use)."""
        folded = plan.setdefault("folded", set())
        for k in range(hi, lo - 1, -1):
            if k in folded or k in barrier:
                continue
            try:
                self.plan_fold(body, k, hi, plan, folded, barrier)
            except Exception:
                pass  # this statement stays as it is

    def plan_fold(self, body, k, hi, plan, folded, barrier):
        c = self.fold_candidate(body, k, plan)
        if c is None:
            return
        var, value, value_pure = c
        store = value[4] if isinstance(value, tuple) and value[0] == "incdec" else None
        # the next printed statement after the definition (skipping what is not printed between the two), and
        # the statements printed as part of it (a concatenation's appends: checked in its evaluation order)
        parts, part_of = [], plan.get("part_of", {})
        j = k + 1
        while j <= hi and j not in barrier:
            if j == store or self.fold_transparent(body, j, plan) or \
                    self.fold_skip(body, j, var, value, value_pure):
                j += 1
            elif j in part_of:
                parts.append(j)
                j += 1
            else:
                break
        if j > hi or j in barrier or any(part_of[p] != j for p in parts):
            return
        u = body[j]
        if isinstance(value, tuple) and value[0] == "ternary" and j in plan.get("ternary", {}):
            return  # no conditional expression inside another one
        if not self.fold_use_ok(body, j, plan) or \
                u.operation in (Op.HLIL_LABEL, Op.HLIL_GOTO, Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_FOR) or \
                j in plan.get("skip", ()):
            return
        # the use must read var exactly once, in a place it can be evaluated (not on a conditional path)
        uses = sum(1 for i in self.eval_nodes(u)[0] if i.operation in _VARS and i.var == var)
        if uses != 1:
            return
        before, found = self.eval_nodes(u, var)
        if found is not True:
            return
        # operands evaluated at a statement before body[k] run before it, not at their use
        earlier = {i.expr_index for at, op in plan.get("evaluated_at", ()) if at < k for i in walk(op)}
        before = [i for i in before if i.expr_index not in earlier]
        if any(self.side_effect(i) for i in before):
            return  # a call / store would then run after the value instead of before it
        if not value_pure and any(self.reads_memory(i) for i in before):
            return  # the value is not pure and something read between could have changed what it reads
        (self.inline if self.inline is not None else plan.setdefault("inline", {}))[var] = value
        folded.add(k)
        if store is not None:
            folded.add(store)
        if k in plan.get("own", {}):
            folded.update(plan["own"][k][3])

    # --- x++ / ++x as a value (bncpp-11, jvm-60) --------------------------------------------------------

    def plan_incdec(self, body, k, plan):
        """`t = f; f = t + 1; use(t)` (post) / `t = f + 1; f = t; use(t)` (pre), f a local or a store target ->
        plan["incdec"][k] = (t, ("incdec", f, "+"/"-", pre, store index, store)); plan_fold then folds it into the
        use as f++ / ++f and drops the store with it. The matching strips the wraps of strip() (native HLIL wraps a
        load / temporary in zx / sx / low_part / an offset-0 field). t may be declared apart (`T t; .. t = f;`,
        with fold_declared), and the post store may read f again (`f = f - 1`: t still equals f)."""
        if k + 1 > len(body) - 1:
            return
        s, st = body[k], body[k + 1]
        if k in plan.get("skip", ()) or k + 1 in plan.get("skip", ()):
            return
        if s.operation == Op.HLIL_VAR_INIT and self.def_count(s.dest) == 1:
            t, own = s.dest, 0
        elif self.fold_declared and s.operation == Op.HLIL_ASSIGN and s.dest.operation == Op.HLIL_VAR and \
                self.declared(s.dest.var):
            t, own = s.dest.var, 1  # the assignment's own read of t
        else:
            return
        store = self.incdec_store(st)
        if t in self._addr_taken() or not self.foldable_var(t) or store is None:
            return
        val, same = store
        if self.var_count(t) - own - self.refs(st, t) != 1:
            return  # t is read once besides the store
        strip = self.strip
        is_t = lambda e: strip(e).operation == Op.HLIL_VAR and strip(e).var == t
        # post: t = f ; f = t + 1 -- the definition copies f, the store writes f + 1 back (or f + 1 again)
        step = _unit_step(strip(val), lambda e: is_t(e) or same(e))
        if step is not None and same(s.src):
            load, pre = s.src, False
        else:
            # pre: t = f + 1 ; f = t -- the definition is f + 1, the store copies it back to f
            src = strip(s.src)
            step = _unit_step(src, same)
            if step is None or not is_t(val):
                return
            load, pre = src.left, True
        plan.setdefault("incdec", {})[k] = (t, ("incdec", self.incdec_target(st, load), step, pre, k + 1, st))

    # --- c ? a : b (bncpp-9, jvm-59) --------------------------------------------------------------------

    def plan_ternary(self, body, k, plan):
        """`T x; if (c) x = a; else x = b;` / `T x = b; if (c) x = a;` (a conditional move) with body[k] the
        declaration / initialization, x set nowhere else and read once more -> plan["ternary"][index of the if] =
        (x, ("ternary", x, if, a, b)) and plan["ternary_def"][that index] = k. plan_fold folds it into x's use like
        a temporary; where it cannot, the language prints `T x = c ? a : b;`. a and b: free of side effects or a
        single call (each only runs on its own branch, as before)."""
        s = body[k]
        if k in plan.get("skip", ()):
            return
        if s.operation == Op.HLIL_VAR_DECLARE and self.declared(s.var):
            x, init = s.var, None
        elif s.operation == Op.HLIL_VAR_INIT and self.def_count(s.dest) == 1:
            x, init = s.dest, s.src
        else:
            return
        if x in self._addr_taken() or not self.foldable_var(x):
            return
        j = k + 1
        while j < len(body) and self.fold_transparent(body, j, plan):
            j += 1
        if j >= len(body) or j in plan.get("ternary", {}) or j in plan.get("skip", ()):
            return
        iff = body[j]
        if iff.operation != Op.HLIL_IF or self.refs(iff.condition, x):
            return
        branches = [iff.true] if init is not None else [iff.true, iff.false]
        if init is not None and iff.false.operation not in (Op.HLIL_NOP,):
            return
        values = []
        for b in branches:
            items = list(b.body) if b.operation == Op.HLIL_BLOCK else [b]
            if len(items) != 1 or items[0].operation != Op.HLIL_ASSIGN or \
                    items[0].dest.operation != Op.HLIL_VAR or items[0].dest.var != x:
                return
            v = items[0].src
            if self.refs(v, x) or not self.ternary_value(v):
                return
            values.append(v)
        if init is not None:
            # the initial value now runs after the condition, and only when it fails
            if self.refs(init, x) or not self.pure(init) or not self.pure(iff.condition):
                return
            values.append(init)
        if self.var_count(x) - self.refs(iff, x) != 1:
            return  # read once besides the assignments
        plan.setdefault("ternary", {})[j] = (x, ("ternary", x, iff, values[0], values[1]))
        plan.setdefault("ternary_def", {})[j] = k

    def ternary_value(self, v):
        """a value a conditional expression may hold: free of side effects, or with a single call as its only one;
        no conditional inside it (a bool-to-int `c ? 1 : 0` only as the whole value: it reads as `&&` / `||`)"""
        if any(i.operation == Op.HLIL_BOOL_TO_INT for i in walk(v) if i is not v and i.expr_index != v.expr_index):
            return False
        effects = [i for i in self.eval_nodes(v)[0] if self.side_effect(i)]
        return not effects or (len(effects) == 1 and effects[0].operation == Op.HLIL_CALL)


def compound_copy(i):
    """the copy of the destination inside a compound store to memory (`*(p + (t << 3)) |= v` is
    ASSIGN(*(p + (t << 3)), *(p + (t << 3)) | v)), else None. The base language prints the address once, so its
    variables are read once there (a local's `x += v` keeps both: x is written, too)."""
    if i.operation != Op.HLIL_ASSIGN or i.dest.operation not in _MEMORY_LVALUES or \
            i.src.operation not in _COMPOUND_OPS or not _same_tree(i.dest, i.src.left):
        return None
    return i.src.left


def walk_printed(instr):
    """walk(instr) without the destination copies of compound stores (compound_copy)"""
    stack = [instr]
    while stack:
        i = stack.pop()
        yield i
        skip = compound_copy(i)
        kids = list(children(i))
        if skip is not None:
            kids = [i.dest, i.src.right]
            yield i.src  # the operation itself, not its left operand
        stack.extend(reversed(kids))


def _same_tree(a, b):
    """a and b are the same expression: operations, sizes, variables and constants"""
    if a.operation != b.operation or a.size != b.size:
        return False
    ka, kb = a.operands, b.operands
    if len(ka) != len(kb):
        return False
    for x, y in zip(ka, kb):
        if hasattr(x, "operation") and hasattr(y, "operation"):
            if not _same_tree(x, y):
                return False
        elif isinstance(x, list) or isinstance(y, list):
            if not isinstance(x, list) or not isinstance(y, list) or len(x) != len(y) or \
                    not all(_same_tree(p, q) if hasattr(p, "operation") else p == q for p, q in zip(x, y)):
                return False
        elif x != y:
            return False
    return True


def _continues(body):
    """body has a `continue` of its own loop (not one inside a nested loop)"""
    stack = [body]
    while stack:
        i = stack.pop()
        if i.operation == Op.HLIL_CONTINUE:
            return True
        if i.operation not in (Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_FOR):
            stack.extend(children(i))
    return False


def _is_bool(e):
    try:
        return e.size == 0
    except Exception:
        return False


def _strip(e):
    """e without the zx / sx / low_part wraps, and without the offset-0 field read native HLIL uses for the low
    part of a wider variable (`(uint32_t)x` of a uint64_t x is STRUCT_FIELD(x, 0))"""
    while e.operation in _WRAPS or (e.operation == Op.HLIL_STRUCT_FIELD and e.offset == 0 and
                                    e.src.operation == Op.HLIL_VAR):
        e = e.src
    return e


def _same_lvalue(a, b):
    """a and b are the same simple lvalue (a local, or a load of the same constant address), ignoring the
    zx / sx / low_part a native load / store may wrap it in"""
    a, b = _strip(a), _strip(b)
    if a.operation == Op.HLIL_VAR and b.operation == Op.HLIL_VAR:
        return a.var == b.var
    if a.operation == Op.HLIL_DEREF and b.operation == Op.HLIL_DEREF:
        sa, sb = _strip(a.src), _strip(b.src)
        return sa.operation == sb.operation == Op.HLIL_CONST_PTR and sa.constant == sb.constant
    return False


def unit_step(e, is_base):
    """"+" / "-" when e is `base + 1` / `base - 1` (also `base + -1`) and is_base(base), else None"""
    if e.operation not in (Op.HLIL_ADD, Op.HLIL_SUB) or e.right.operation != Op.HLIL_CONST or \
            not is_base(e.left) or e.right.size not in (1, 2, 4, 8):
        return None
    c = e.right.constant & ((1 << (8 * e.right.size)) - 1)
    if c >= 1 << (8 * e.right.size - 1):
        c -= 1 << (8 * e.right.size)
    if c not in (1, -1):
        return None
    return "+" if (c == 1) == (e.operation == Op.HLIL_ADD) else "-"


_unit_step = unit_step

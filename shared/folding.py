# shared with binary-jvm/pseudo_java.py (eval_nodes / pure / fold_candidate / fold_transparent / plan_folds /
# plan_fold / plan_incdec, the folding core of jvm-46/60; synced at HEAD -- back-port the cut, bncpp-14/jvm-68);
# keep language-neutral
"""Evaluation-order-safe folding of single-use temporaries (bncpp-13).

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
  foldable_var(var)    -> bool      (optional) False for a variable that must never fold (e.g. an exception
                                    temporary, `this`); default: everything folds.

FoldMixin keeps:
  self.inline   {var: value expr}   folded temporaries: their single use prints this value in their place. The
                                    language emitter substitutes it (bncpp-13 renders the value through the base
                                    language at the use's precedence and splices it by expr index).
A plan is a dict the mixin fills in place:
  "skip"     {index}                statements another pass already placed elsewhere (not folded here)
  "folded"   {index}                definitions whose value moved into a later statement (do not print)
  "incdec"   {index: (t, value)}    post/pre increment candidates (plan_incdec); folded like any temporary
  "ternary"  {index: (x, value)}    ternary candidates another pass placed (fold_candidate reads them)
"""
from binaryninja import HighLevelILOperation

from .hlil import children, walk

Op = HighLevelILOperation

_WRAPS = (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART)


class FoldMixin:
    # the language class sets these; defaults keep the mixin usable on its own
    inline = None

    def foldable_var(self, var):
        return True

    # --- counting ---------------------------------------------------------------------------------------

    def _counts(self):
        if getattr(self, "_fold_counts", None) is None:
            uses, defs = {}, {}
            try:
                for i in walk(self.hlil.root):
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
        return sum(1 for i in walk(instr) if i.operation == Op.HLIL_VAR and i.var == var)

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
        """the nodes of e in C evaluation order (operands before the operation), folded temporaries expanded to
        their value. With stop_var: stop at its read and return (nodes before it, True); a read reached only on a
        conditionally evaluated path (the right side of && / ||, a ?:) returns (.., None) -- the value cannot be
        moved there, it might not run."""
        if out is None:
            out = []
        o = e.operation
        if o == Op.HLIL_VAR:
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
                for v in value[3:5]:
                    if stop_var is not None and self.refs(v, stop_var):
                        return out, None
                    self.eval_nodes(v, None, out)
            elif isinstance(value, tuple) and value[0] == "incdec":
                self.eval_nodes(value[5], None, out)  # f++ is the store to f
            out.append(e)
            return out, False
        # the right operand of a short-circuit && / || is only evaluated when the left allows it
        if o in (Op.HLIL_AND, Op.HLIL_OR) and _is_bool(e):
            r = self.eval_nodes(e.left, stop_var, out)
            if r[1] is not False:
                return r
            if stop_var is not None and self.refs(e.right, stop_var):
                return out, None
            kids = [e.right]
        elif o in (Op.HLIL_IF, Op.HLIL_SWITCH):
            kids = [e.condition]
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
        if k in plan.get("incdec", {}):
            var, value = plan["incdec"][k]
            return var, value, False
        if k in plan.get("ternary", {}):
            var, value = plan["ternary"][k]
            if self.var_count(var) - self.refs(s, var) != 1:
                return None
            return var, value, all(self.pure(v) for v in (value[2].condition, value[3], value[4]))
        if k in plan.get("skip", ()):
            return None
        if s.operation == Op.HLIL_VAR_INIT:
            var, uses = s.dest, 1
        elif s.operation == Op.HLIL_ASSIGN and s.dest.operation == Op.HLIL_VAR and self.declared(s.dest.var):
            var, uses = s.dest.var, 2  # `T x; .. x = v; use(x)`: the store's own read of x and the use
        else:
            return None
        if self.var_count(var) != uses or (uses == 1 and self.def_count(var) != 1) or var in self._addr_taken() or \
                not self.foldable_var(var):
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
        # the next printed statement after the definition (skipping what is not printed between the two)
        j = k + 1
        while j <= hi and j not in barrier and (j == store or self.fold_transparent(body, j, plan)):
            j += 1
        if j > hi or j in barrier:
            return
        u = body[j]
        if isinstance(value, tuple) and value[0] == "ternary" and j in plan.get("ternary", {}):
            return  # no conditional expression inside another one
        if u.operation in (Op.HLIL_LABEL, Op.HLIL_GOTO, Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_FOR) or \
                j in plan.get("skip", ()):
            return
        # the use must read var exactly once, in a place it can be evaluated (not on a conditional path)
        before, found = self.eval_nodes(u, var)
        if found is not True:
            return
        uses = sum(1 for i in self.eval_nodes(u)[0] if i.operation == Op.HLIL_VAR and i.var == var)
        if uses != 1:
            return
        if any(self.side_effect(i) for i in before):
            return  # a call / store would then run after the value instead of before it
        if not value_pure and any(self.reads_memory(i) for i in before):
            return  # the value is not pure and something read between could have changed what it reads
        (self.inline if self.inline is not None else plan.setdefault("inline", {}))[var] = value
        folded.add(k)
        if store is not None:
            folded.add(store)

    # --- x++ / ++x as a value (bncpp-11) ----------------------------------------------------------------

    def plan_incdec(self, body, k, plan):
        """`t = f; f = t + 1; use(t)` (post) / `t = f + 1; f = t; use(t)` (pre), f a local or a store target ->
        plan["incdec"][k] = (t, ("incdec", f as an lvalue, "+"/"-", pre, store index)); plan_fold then folds it
        into the use as f++ / ++f and drops the store with it. Native HLIL wraps a load / temporary in zx / sx /
        low_part / an offset-0 field (the register is wider than the value), so the matching strips those. t may
        be declared apart (`T t; .. t = f;`), and the post store may read f again (`f = f - 1`: t still equals f)."""
        if k + 1 > len(body) - 1:
            return
        s, st = body[k], body[k + 1]
        if k in plan.get("skip", ()) or k + 1 in plan.get("skip", ()):
            return
        if s.operation == Op.HLIL_VAR_INIT and self.def_count(s.dest) == 1:
            t, own = s.dest, 0
        elif s.operation == Op.HLIL_ASSIGN and s.dest.operation == Op.HLIL_VAR and self.declared(s.dest.var):
            t, own = s.dest.var, 1  # the assignment's own read of t
        else:
            return
        if t in self._addr_taken() or not self.foldable_var(t) or st.operation != Op.HLIL_ASSIGN:
            return
        dest, val = st.dest, st.src
        if self.var_count(t) - own - self.refs(st, t) != 1:
            return  # t is read once besides the store
        is_t = lambda e: _strip(e).operation == Op.HLIL_VAR and _strip(e).var == t
        # post: t = f ; f = t + 1 -- the definition copies f, the store writes f + 1 back (or f + 1 again)
        step = _unit_step(_strip(val), lambda e: is_t(e) or _same_lvalue(dest, e))
        if step is not None and _same_lvalue(dest, s.src):
            pre = False
        else:
            # pre: t = f + 1 ; f = t -- the definition is f + 1, the store copies it back to f
            step = _unit_step(_strip(s.src), lambda e: _same_lvalue(dest, e))
            if step is None or not is_t(val):
                return
            pre = True
        plan.setdefault("incdec", {})[k] = (t, ("incdec", dest, step, pre, k + 1, st))

    # --- c ? a : b (bncpp-9) ----------------------------------------------------------------------------

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


def _unit_step(e, is_base):
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

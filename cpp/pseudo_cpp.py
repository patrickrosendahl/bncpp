"""The "Pseudo Cpp" language representation.

Seed: every statement is rendered by Binary Ninja's built-in Pseudo C (BASE_LANGUAGE), so the view is a
pass-through. C++ rendering (try/catch from exception tables, readability passes) replaces that statement
by statement; anything it cannot render still falls back to emit_error (HLIL as a comment).

try/catch (bncpp-6, planned in cpp/eh_render.py): in a function with try regions the root block is printed
statement by statement, the statements of a region wrapped in `try { }` and followed by one `catch (T) { }` per
clause with the handler's code from the landing-pad function. The plan is made before anything is emitted; if
it fails, the function is printed as Pseudo C prints it.
"""
import re

from binaryninja import (BraceRequirement, HighLevelILOperation, LanguageRepresentationFunction,
                         LanguageRepresentationFunctionType, OperatorPrecedence, log_warn)

from ..constants import BASE_LANGUAGE, LANGUAGE_NAME
from ..shared.tokens import TT, TokenMixin, tok
from . import eh_comments, eh_render, eh_throw
from ..shared import regions as _regions
from ..shared.folding import FoldMixin
from ..shared.hlil import children, walk

Op = HighLevelILOperation
P = OperatorPrecedence
_DEREF_CAST = re.compile(r"^\*\s*\([\w:<> ]+\*\)$")  # '*(uint32_t*)' before a begin_catch
# a load / field / array read; cpp's reads_memory hook (folding.py: a value that is not pure cannot move past one)
_READS_MEM = (Op.HLIL_DEREF, Op.HLIL_DEREF_FIELD, Op.HLIL_ARRAY_INDEX, Op.HLIL_STRUCT_FIELD)
# a node that, evaluated, runs a call or writes memory; folding.py refuses to move a value past one
_SIDE_EFFECT = (Op.HLIL_CALL, Op.HLIL_TAILCALL, Op.HLIL_SYSCALL, Op.HLIL_ASSIGN, Op.HLIL_VAR_INIT,
                Op.HLIL_ASSIGN_UNPACK)


class PseudoCppFunction(FoldMixin, TokenMixin, LanguageRepresentationFunction):
    comment_start_string = "// "
    annotation_start_string = "/* "
    annotation_end_string = " */"
    language_label = LANGUAGE_NAME

    def base(self):
        """the built-in representation of the same function, used for everything not rendered here"""
        lr = getattr(self, "_base", None)
        if lr is None:
            lr = self._base = self.function.language_representation(BASE_LANGUAGE)
        return lr

    def perform_init_token_emitter(self, emitter):
        emitter.brace_requirement = BraceRequirement.OptionalBraces
        emitter.default_braces_on_same_line = True
        emitter.has_collapsable_regions = True

    def perform_begin_lines(self, instr, tokens):
        tokens.prepend_blank_collapse_indicator()
        tokens.append_open_brace()
        tokens.new_line()
        tokens.increase_indent()
        self.emit_eh_comments(tokens)

    def emit_eh_comments(self, tokens):
        """the function's exception table / landing-pad role as comments (bncpp-5)"""
        try:
            lines = eh_comments.lines(self.function.view, self.function.start)
        except Exception as ex:
            lines = ["[%s could not read the exception tables: %s: %s]" % (self.language_label, type(ex).__name__, ex)]
        for line in lines:
            self.note(tokens, "// " + line)
            tokens.new_line()
        if lines:
            tokens.scope_separator()

    def perform_end_lines(self, instr, tokens):
        tokens.decrease_indent()
        tokens.prepend_blank_collapse_indicator()
        tokens.append_close_brace()
        tokens.new_line()

    def perform_get_expr_text(self, instr, tokens, settings, precedence=P.TopLevelOperatorPrecedence,
                              statement=False):
        try:
            items = self.try_plan(instr) if statement else None
        except Exception as ex:
            log_warn("%s: try/catch plan failed at %#x: %r" % (self.language_label, instr.address, ex))
            items = None
        try:
            if items:
                self.emit_items(items, tokens)
            else:
                self.emit_base(instr, tokens, settings, precedence, statement)
        except Exception as ex:
            self.emit_error(instr, ex, tokens)

    # --- try/catch (bncpp-6) -------------------------------------------------------------------------------

    def try_plan(self, instr):
        """the root block as plan items (plan_list), or None without a placed region"""
        hlil = self.function.hlil
        if hlil is None or hlil.root is None or instr.expr_index != hlil.root.expr_index:
            return None
        regions = eh_render.regions(self.function)
        if not regions:
            return None
        self._unwind = {}  # id(region) -> [(pad function, statements run on unwinding before the dispatch)]
        self._frame = eh_render.owner_frame(self.function, regions[0].start)  # bncpp-68: the owner's stack slots
        self._fvars = {}  # pad start -> eh_render.frame_vars
        self._handlers = {id(r): self.plan_handlers(r) for r in regions}
        self._in_loop = set()  # regions placed inside a compound statement (handlers end at the continuation)
        self._zones = {}  # statement expr index -> the innermost try run it is printed in (folds stay in one)
        self._compound = set()  # statements printed around a planned body (their lines are cut up)
        self._runs = 0
        items = self.plan_block(instr, regions)  # a one-statement function's root is that statement
        if not _has_try(items):
            self._zones, self._compound = {}, set()
            return None
        return self.fold_items(items)

    def stmt_lines(self, block):
        """(statements of block, per statement Pseudo C's lines of it as [(tokens, instr index)]); a blank line goes
        with the statement before it, as Pseudo C prints the whole block"""
        stmts = eh_render.body(block)
        owner_of = {}
        for k, st in enumerate(stmts):
            for i in walk(st):
                owner_of.setdefault(i.instr_index, k)
        groups, cur = [[] for _ in stmts], 0
        for toks, key in self.throws(self.base().get_expr_text(block, None, P.TopLevelOperatorPrecedence, True)):
            idx = key[1] if key is not None else None
            cur = max(cur, owner_of.get(idx, cur))
            groups[cur].append((toks, idx))
        return stmts, groups

    def throws(self, lines, func=None, rewrite=True):
        """BN's lines of func (default: this function) as [(tokens, key)] with the ___cxa_throw sequences printed as
        `throw` statements (cpp/eh_throw.py); key: (function start, HLIL instruction index) or None"""
        func = func or self.function
        plans = getattr(self, "_throws", None)
        if plans is None:
            plans = self._throws = {}
        if func.start not in plans:
            plans[func.start] = eh_throw.plan(func)
        keyed = [(list(l.tokens), (func.start, l.il_instruction.instr_index) if l.il_instruction is not None
                  else None) for l in lines]
        return eh_throw.rewrite(keyed, {func.start: plans[func.start]}) if rewrite and plans[func.start] else keyed

    def plan_block(self, block, regions):
        stmts, groups = self.stmt_lines(block)
        return self.plan_list(stmts, groups, regions)

    def plan_list(self, stmts, groups, regions):
        """[("stmt", lines) | ("compound", segments) | ("try", items, handlers, blank after, unwind)]"""
        loops, rest = {}, []  # loops: statement index -> {body expr index: (body, [regions])}
        for r in regions:
            found = eh_render.compound_for(stmts, r, self.cont(r))
            if found is not None:
                k, b = found
                loops.setdefault(k, {}).setdefault(b.expr_index, (b, []))[1].append(r)
                self._in_loop.add(id(r))
            else:
                rest.append(r)
        pcs = [eh_render.call_addrs(st) or None for st in stmts]
        by_range = {(r.start, r.end): r for r in rest}
        runs = {i: (i, j, by_range[(g[0], g[1])])
                for i, j, g in _regions.try_runs(pcs, [(r.start, r.end, ()) for r in rest])}
        items, k = [], 0
        while k < len(stmts):
            if k not in runs:
                items.append(self.plan_stmt(stmts[k], groups[k], list(loops[k].values()) if k in loops else None))
                k += 1
                continue
            i, j, r = runs[k]
            self._runs += 1
            zone = self._runs
            for st in stmts[i:j + 1]:  # an inner run (planned below) overwrites it
                self._zones[st.expr_index] = zone
            inner = [x for x in regions if x is not r and r.start <= x.start and x.end <= r.end]
            sub = groups[i:j + 1]
            last = list(sub[-1])
            blank = False
            while last and not last[-1][0]:  # the blank line after the run goes after the catch
                last.pop()
                blank = True
            handlers = [(c, pf, pl[0 if id(r) in self._in_loop else 1] if isinstance(pl, tuple) else pl, note, cont)
                        for c, pf, pl, note, cont in self._handlers[id(r)]]
            items.append(("try", self.plan_list(stmts[i:j + 1], sub[:-1] + [last], inner), handlers, blank,
                          self._unwind.get(id(r))))
            k = j + 1
        return items

    def plan_stmt(self, st, lines, bodies):
        """a compound statement with try regions in some of its bodies [(body, [regions])]: ("compound", segments),
        Pseudo C's lines of it with each such body replaced by its plan -- ("lines", lines) and ("body", items,
        indent levels, closes) in turn (bncpp-64: loops, bncpp-67: if / else, switch cases)"""
        if not bodies:
            return ("stmt", lines)
        spans = []
        for body, regs in bodies:
            inner = {i.instr_index for b in eh_render.body(body) for i in walk(b)}
            at = [n for n, (_t, idx) in enumerate(lines) if idx in inner]
            if at:
                spans.append((at[0], at[-1], body, regs))
        spans.sort(key=lambda x: x[0])
        if not spans or any(spans[n][0] <= spans[n - 1][1] for n in range(1, len(spans))):
            return ("stmt", lines)
        segs, pos = [], 0
        for first, last, body, regs in spans:
            head = lines[pos:first]
            if head and _text(head[-1]) == "{":
                head = head[:-1]  # the body's brace is printed with the body
            segs.append(("lines", head))
            levels = max(1, _indent(lines[first]) // 4)
            pos = last + 1
            closes = False
            if pos < len(lines) and _text(lines[pos]) == "}":
                pos += 1
            else:
                closes = pos < len(lines) and _text(lines[pos]).startswith("}")  # do { } while (c);
            segs.append(("body", self.plan_block(body, regs), levels, closes))
        segs.append(("lines", lines[pos:]))
        self._compound.add(st.expr_index)
        return ("compound", segs)

    def cont(self, region):
        """where the region's handlers go on in this function's own code (the first clause's that does)"""
        return next((h[4] for h in self._handlers[id(region)] if h[4] is not None), None)

    def plan_handlers(self, region):
        """per clause (Clause, pad function | None, plumbing, note | None, continuation | None); plumbing: an
        eh_render.Plumbing, or (cut at the continuation, whole) when the handler goes on in this function"""
        bv = self.function.view
        out, shown, before = [], set(), []
        for clause, pad in region.clauses:
            pf = bv.get_function_at(pad)
            if pf is None:
                out.append((clause, None, None, "landing pad %#x is in no function (command: Create landing-pad "
                                                "functions)" % pad, None))
                before.append(None)
                continue
            on_pad = max(sum(c.kind == c.CATCH for c in cs.clauses) for cs in region.sites if cs.landing_pad == pad)
            h = eh_render.specialize(pf, clause.type_index, on_pad, self.function)
            if h is not None:
                # in a loop the handler ends where it goes on in the loop; elsewhere the pad's copy of the owner's
                # code after it stays (the owner may print nothing after the try: a return folded into it)
                cut = eh_render.plumbing(pf, h.stmts, eh_comments.type_name(clause.type))
                pre = {_key(s) for s in _cleanups(h.stmts[:h.before])}
                before.append((pf, [s for s in cut.stmts if _key(s) in pre]))
                if h.cont is not None:
                    full = eh_render.specialize(pf, clause.type_index, on_pad)
                    cut = (cut, eh_render.plumbing(pf, full.stmts, eh_comments.type_name(clause.type)))
                out.append((clause, pf, cut, None, h.cont))
            elif pad in shown:
                out.append((clause, pf, None, "selector #%d: the landing pad above" % clause.type_index, None))
            else:
                before.append(None)
                shown.add(pad)
                whole = list(eh_render.body(pf.hlil.root)) if pf.hlil is not None else []
                out.append((clause, pf, eh_render.Plumbing(whole, set(), {}),
                            "the whole landing pad %s: its dispatch on the selector was not found"
                            % pf.symbol.full_name, None))
        return self.split_unwind(region, out, before)

    def split_unwind(self, region, handlers, before):
        """the calls the landing pads run before their dispatch on the selector (bncpp-65): the destructors of the
        try block's locals, run while unwinding, not catch code -- kept in self._unwind as [(pad function,
        statements)], printed once before the catch list. Taken out of the catch bodies where every handler has the
        same ones (from one pad); the region's other pads (call sites later in the block, with more locals alive)
        add theirs."""
        unwind_all = self._other_unwind(region, {pf.start for pf, _st in (b for b in before if b)})
        if not before or any(b is None for b in before):
            self._unwind[id(region)] = unwind_all
            return handlers
        keys = {(pf.start, tuple(_key(s) for s in st)) for pf, st in before}
        if len(keys) != 1 or not before[0][1]:
            self._unwind[id(region)] = unwind_all
            return handlers
        pf, unwind = before[0]
        gone = {_key(s) for s in unwind}

        def strip(p):
            kept = [s for s in p.stmts if _key(s) not in gone]
            used = {(_key(s)[0], i.var) for s in kept for i in walk(s)
                    if i.operation == Op.HLIL_VAR and s.operation != Op.HLIL_VAR_DECLARE}
            # the declarations of what moved out with the cleanup
            kept = [s for s in kept if s.operation != Op.HLIL_VAR_DECLARE or (_key(s)[0], s.var) in used]
            return eh_render.Plumbing(kept, p.rethrow, p.names)

        out = []
        for c, f, pl, note, cont in handlers:
            if isinstance(pl, tuple):
                pl = (strip(pl[0]), strip(pl[1]))
            elif pl is not None:
                pl = strip(pl)
            out.append((c, f, pl, note, cont))
        self._unwind[id(region)] = [(pf, unwind)] + unwind_all
        return out

    def _other_unwind(self, region, done):
        """[(pad function, calls before its dispatch)] of the region's landing pads not in done"""
        out, bv = [], self.function.view
        clause = region.clauses[0][0]
        for pad in sorted({cs.landing_pad for cs in region.sites} - done):
            pf = bv.get_function_at(pad)
            if pf is None:
                continue
            on_pad = max(sum(c.kind == c.CATCH for c in cs.clauses) for cs in region.sites if cs.landing_pad == pad)
            h = eh_render.specialize(pf, clause.type_index, on_pad, self.function)
            # without the plumbing (a -O0 pad stores the exception pointer first)
            st = _cleanups(eh_render.plumbing(pf, h.stmts[:h.before], eh_comments.type_name(clause.type)).stmts) \
                if h is not None else []
            if st:
                out.append((pf, st))
        return out

    def fold_items(self, items):
        """the plan with its lines through fold_lines (bncpp-84): consecutive statements as one list (a conditional
        move's declaration and its if stay together), a compound statement's own lines piece by piece"""
        start, out, run = self.function.start, [], []

        def flush():
            if run:
                keyed = self.fold_lines([(t, (start, i) if i is not None else None) for t, i in run])
                out.append(("stmt", [(t, k[1] if k is not None else None) for t, k in keyed]))
                del run[:]
        for it in items:
            if it[0] == "stmt":
                run.extend(it[1])
                continue
            flush()
            if it[0] == "compound":
                out.append(("compound", [(s[0], self.fold_items([("stmt", s[1])])[0][1] if s[1] else s[1])
                                         if s[0] == "lines" else (s[0], self.fold_items(s[1])) + tuple(s[2:])
                                         for s in it[1]]))
            else:
                out.append((it[0], self.fold_items(it[1])) + tuple(it[2:]))
        flush()
        return out

    def emit_items(self, items, tokens):
        for it in items:
            if it[0] == "stmt":
                self.emit_token_lines([t for t, _ in it[1]], tokens, True)
            elif it[0] == "compound":
                self.emit_compound(it, tokens)
            else:
                self.emit_try(it, tokens)

    def emit_compound(self, item, tokens):
        """a compound statement printed around its bodies' plans: Pseudo C's other lines as they are, braces around
        each planned body always, at the body's own indentation (a switch case is two levels in)"""
        for seg in item[1]:
            if seg[0] == "lines":
                if seg[1]:
                    self.emit_token_lines([t for t, _ in seg[1]], tokens, True)
                continue
            _, items, levels, closes = seg
            for _ in range(levels - 1):
                tokens.increase_indent()
            tokens.append_open_brace()
            tokens.new_line()
            tokens.increase_indent()
            self.emit_items(items, tokens)
            tokens.decrease_indent()
            if not closes:
                tokens.append_close_brace()
                tokens.new_line()
            for _ in range(levels - 1):
                tokens.decrease_indent()

    def emit_try(self, item, tokens):
        _, items, handlers, blank, unwind = item
        self.kw(tokens, "try")
        self.open_block(tokens)
        self.emit_items(items, tokens)
        self.close_block(tokens)
        seen, lrs = set(), {}
        for pf, stmts in unwind or ():
            for s in stmts:
                if _key(s) in seen:  # the pads share a cleanup chain
                    continue
                seen.add(_key(s))
                f = s.function.source_function  # the pad, or the cleanup chain it jumps to
                lr = lrs.get(f.start) or lrs.setdefault(f.start, f.language_representation(BASE_LANGUAGE))
                for line in lr.get_expr_text(s, None, P.TopLevelOperatorPrecedence, True):
                    text = "".join(t.text for t in self.frame_tokens(list(line.tokens), pf, f)).rstrip()
                    if text.strip():
                        self.note(tokens, "// unwind: " + text)
                        tokens.new_line()
        for clause, pf, plumb, note, _cont in handlers:
            type_name = eh_comments.type_name(clause.type)
            var = eh_render.catch_var(type_name) if plumb is not None and not note else None
            self.kw(tokens, "catch")
            self.txt(tokens, " ")
            tokens.append_open_paren()
            self.type_tok(tokens, type_name)
            if var is not None:
                self.txt(tokens, "& e" if var == "&e" else " e")
            tokens.append_close_paren()
            self.open_block(tokens)
            if note:
                self.note(tokens, "// " + note)
                tokens.new_line()
            if plumb is not None and plumb.stmts:
                self.emit_catch_body(plumb, var, tokens, pf)
            self.close_block(tokens)
        if blank:
            tokens.scope_separator()

    def emit_catch_body(self, plumb, var, tokens, pad):
        """the statements of a catch body from the pad's (or the functions it tail-calls') Pseudo C lines; all lines
        first, so a throw's allocation and construction are seen with it (cpp/eh_throw.py). The readability passes
        run on each function's run of lines (bncpp-84) before the exception object and the owner's slots are named,
        so a folded value gets them too."""
        lrs, runs, plans = {}, [], {}  # runs: [(function, [statement], [(tokens, key)])], None for `throw;`
        for s in plumb.stmts:
            if _key(s) in plumb.rethrow:
                runs.append(None)
                continue
            f = s.function.source_function  # the pad, or a function its handler tail-calls (bncpp-64)
            lr = lrs.get(f.start) or lrs.setdefault(f.start, f.language_representation(BASE_LANGUAGE))
            lines = self.throws(lr.get_expr_text(s, None, P.TopLevelOperatorPrecedence, True), f, False)
            if runs and runs[-1] is not None and runs[-1][0].start == f.start:
                runs[-1][1].append(s)
                runs[-1][2].extend(lines)
            else:
                runs.append((f, [s], list(lines)))
            plans[f.start] = self._throws[f.start]
        keyed = []
        for run in runs:
            if run is None:
                keyed.append((None, None))  # `throw;`
                continue
            f, _stmts, lines = run
            for t, k in self.catch_folds(f, plumb).fold_lines(lines):
                t = self.frame_tokens(t, pad, f)
                keyed.append((self.catch_tokens(t, plumb.names, var) if var is not None else t, k))
        lines = []
        for t, _k in eh_throw.rewrite(keyed, plans):
            if t is None:
                if lines:
                    self.emit_token_lines(lines, tokens, True)
                    lines = []
                self.kw(tokens, "throw")
                tokens.append_semicolon()
                tokens.new_line()
            else:
                lines.append(t)
        if lines:
            self.emit_token_lines(lines, tokens, True)

    def catch_folds(self, func, plumb):
        """the fold plan for func's statements in a catch body (bncpp-84): only variables that are read and written
        nowhere else in func, not the exception's and not a throw's (eh_throw works on the lines unfolded)"""
        shown = {i.instr_index for s in plumb.stmts if _key(s) not in plumb.rethrow
                 and s.function.source_function.start == func.start for i in walk(s)}
        cache = getattr(self, "_catch_folds", None)
        if cache is None:
            cache = self._catch_folds = {}
        key = (func.start, frozenset(shown))
        if key not in cache:
            throw = set()
            for t in self._throws.get(func.start, {}).values():
                throw |= {t.at} | t.drop
            protect = set()
            for i in walk(func.hlil.root) if func.hlil is not None else ():
                v = i.var if i.operation in (Op.HLIL_VAR, Op.HLIL_VAR_DECLARE) else \
                    i.dest if i.operation == Op.HLIL_VAR_INIT else None
                if v is not None and (i.instr_index not in shown or i.instr_index in throw):
                    protect.add(v)
            protect |= {v for v in func.vars if v.name in plumb.names}
            # the hidden ___cxa_end_catch() ends the handler: C++ evaluates `return v;` before it, so v may move past
            end = {i.instr_index for i in walk(func.hlil.root) if i.instr_index not in shown and
                   i.operation == Op.HLIL_CALL and eh_render.callee(i) == "cxa_end_catch"} if func.hlil else set()
            cache[key] = _CatchFolds(func, protect, end)
        return cache[key]

    def frame_tokens(self, toks, pad, func):
        """a catch body line from func (the pad or a function it tail-calls) with the owner's stack slots it
        reaches through the frame pointer named as the owner names them (bncpp-68): `*(int32_t*)((char*)arg5 - 4)`
        -> var_c, `(char*)arg5 - 0x18` -> &var_20"""
        if self._frame is None or pad is None:
            return toks
        fv = self._fvars.get(pad.start)
        if fv is None:
            fv = self._fvars[pad.start] = (eh_render.frame_vars(pad), eh_render.pad_slots(pad, self._frame))
        fv, slots = fv
        if func.start == pad.start and slots:  # the pad's own stack slots in the owner's frame
            toks = [tok(TT.TextToken, slots[t.text]) if t.type == TT.LocalVariableToken and t.text in slots else t
                    for t in toks]
        names = fv.get(func.start)
        if not names or self._frame.fp is None:
            return toks
        alt = "|".join(re.escape(n) for n in sorted(names))
        deref = re.compile(r"\*\([\w ]+?\*+\)\(\(char\*\)(?:%s) - (0x[0-9a-f]+|\d+)\)" % alt)
        addr = re.compile(r"\(char\*\)(?:%s) - (0x[0-9a-f]+|\d+)\b" % alt)

        def name(m, prefix=""):
            n = eh_render.slot_name(self._frame, self._frame.fp - int(m.group(1), 0))
            return prefix + n if n else None
        toks = _replace_spans(toks, deref, name)
        return _replace_spans(toks, addr, lambda m: name(m, "&"))

    def catch_tokens(self, toks, names, var):
        """a catch body line with the exception object named (bncpp-7): a variable that held its address or value
        prints as '&e' / 'e'; an inline ___cxa_begin_catch(x) as '&e', and '*(T*)___cxa_begin_catch(x)' as 'e'
        when e is a scalar"""
        out, i = [], 0
        while i < len(toks):
            t = toks[i]
            if t.type == TT.LocalVariableToken and t.text in names:
                out.append(tok(TT.TextToken, self.catch_value(out, names[t.text], var)))  # plain text: no variable
                i += 1
                continue
            if t.text.lstrip("_") == "cxa_begin_catch" and i + 1 < len(toks) and toks[i + 1].text.startswith("("):
                depth, j = 0, i + 1
                while j < len(toks):
                    depth += toks[j].text.count("(") - toks[j].text.count(")")
                    if depth <= 0:
                        break
                    j += 1
                out.append(tok(TT.TextToken, self.catch_value(out, "&e", var)))
                i = j + 1
                continue
            out.append(t)
            i += 1
        return out

    @staticmethod
    def catch_value(out, text, var):
        """text ('&e' / 'e') for the exception object; '*(T*)&e' -> 'e' for a scalar e (drops the cast from out)"""
        if var == "e" and text == "&e":
            for k in range(1, min(len(out), 8) + 1):
                if _DEREF_CAST.match("".join(x.text for x in out[-k:])):
                    del out[-k:]
                    return "e"
        return text

    def open_block(self, tokens):
        """a brace on its own line, as Pseudo C sets an if's (the emitter's scopes print none here)"""
        tokens.new_line()
        tokens.append_open_brace()
        tokens.new_line()
        tokens.increase_indent()

    def close_block(self, tokens):
        tokens.decrease_indent()
        tokens.append_close_brace()
        tokens.new_line()

    # --- the built-in language -----------------------------------------------------------------------------

    def emit_base(self, instr, tokens, settings, precedence, statement):
        """instr as the built-in language prints it"""
        # BN passes settings with no option set here; handing them on drops Pseudo C's type casts
        lines = self.base().get_expr_text(instr, None, precedence, statement)
        keyed = self.throws(lines)
        hlil = self.function.hlil
        if statement and hlil is not None and hlil.root is not None and instr.expr_index == hlil.root.expr_index:
            keyed = self.fold_lines(keyed)  # readability passes on the whole function (bncpp-13)
        self.emit_token_lines([t for t, _k in keyed], tokens, statement)

    # --- readability passes (folding single-use temporaries, bncpp-13) -------------------------------------

    def side_effect(self, i):
        """FoldMixin hook: the node, evaluated, runs a call or writes memory"""
        return i.operation in _SIDE_EFFECT

    def reads_memory(self, i):
        """FoldMixin hook: the node reads memory"""
        return i.operation in _READS_MEM

    def foldable_var(self, var):
        """FoldMixin hook: a variable that may fold into its use. This function's own code has no exception
        temporaries to protect (they live in the landing-pad functions; their catch bodies fold through
        _CatchFolds, which does)."""
        return True

    def fold_candidate(self, body, k, plan):
        """FoldMixin: a conditional expression whose use would print too wide stays `T x = c ? a : b;` (bncpp-89)"""
        if k in plan.get("ternary", {}) and body[k].instr_index in getattr(self, "_wide_ternary", ()):
            return None
        return super().fold_candidate(body, k, plan)

    def value_parts(self, value):
        """FoldMixin hook: a ("lowbyte", ...) value evaluates its first value, then each operand (bncpp-85)"""
        return [value[2]] + [x for _op, x in value[3]] if value[0] == "lowbyte" else ()

    def _fold_plan(self):
        """{instruction index of a folded definition} for this function; fills self.inline (var -> value). A
        conditional expression folded into a line wider than _MAX_WIDTH is planned again unfolded (bncpp-89)."""
        cached = getattr(self, "_folded_idx", None)
        if cached is not None:
            return cached
        self._wide_ternary = set()
        for _ in range(4):
            folded_idx = self._plan_once()
            wide = self._wide_folds(folded_idx)
            if not wide - self._wide_ternary:
                break
            self._wide_ternary |= wide
            self._fold_counts = None
        return folded_idx

    def _wide_folds(self, folded_idx):
        """the if instruction indexes of the folded conditional expressions on a line wider than _MAX_WIDTH (the
        lines that stay, with the folded values substituted)"""
        ternaries = {v for v, x in self.inline.items() if isinstance(x, tuple) and x[0] == "ternary"}
        if not ternaries or self.function is None or self.function.hlil is None:
            return set()
        gone = set(folded_idx)
        for value, d, inner in self._ternary_stmt.values():
            if value is None:
                gone |= inner | {d}
        out = set()
        try:
            lines = self.base().get_expr_text(self.function.hlil.root, None, P.TopLevelOperatorPrecedence, True)
        except Exception:
            return out
        for line in lines:
            if line.il_instruction is not None and line.il_instruction.instr_index in gone:
                continue
            self._subst_log = set()
            text = "".join(t.text for t in self._subst_inline(list(line.tokens)))
            if len(text.rstrip()) > _MAX_WIDTH:
                out |= {self.inline[v][2].instr_index for v in self._subst_log & ternaries}
        self._subst_log = None
        return out

    def _plan_once(self):
        """Run per HLIL block so a temporary folds into its use within the same block, in order."""
        self.inline = {}
        self._ternary_stmt = {}  # if instr index -> (value, definition instr index, the if's instr indexes)
        folded_idx, names = set(), {}
        hlil = self.function.hlil
        zones, compound = getattr(self, "_zones", {}), getattr(self, "_compound", set())
        try:
            for body in self.fold_lists(hlil.root):  # a do-while's body ends in its condition (bncpp-12)
                plan = {}
                for k in range(len(body) - 1):  # x++ / ++x (bncpp-11), c ? a : b (bncpp-9): fold_candidate
                    self.plan_incdec(body, k, plan)  # reads plan["incdec"] / plan["ternary"]
                    self.plan_ternary(body, k, plan)
                self.plan_lowbyte(body, plan)
                # nothing moves into, out of or across a try run (bncpp-84): one fold plan per stretch of the body
                # in one run, or outside all of them
                zone = [zones.get(st.expr_index) for st in body]
                for k in [k for k in plan.get("incdec", {}) if zone[k] != zone[k + 1]]:
                    del plan["incdec"][k]
                for k in [k for k, c in plan.get("own", {}).items()
                          if len({zone[i] for i in c[3] | {k, k + 1}}) != 1]:
                    del plan["own"][k]
                for j in [j for j, d in plan.get("ternary_def", {}).items()
                          if zone[j] != zone[d] or body[j].expr_index in compound]:
                    del plan["ternary"][j], plan["ternary_def"][j]
                lo = 0
                for hi in range(len(body)):
                    if hi == len(body) - 1 or zone[hi + 1] != zone[hi]:
                        self.plan_folds(body, lo, hi, plan)
                        lo = hi + 1
                for k in plan.get("folded", ()):
                    folded_idx.add(body[k].instr_index)
                for j, (_x, value) in plan.get("ternary", {}).items():
                    d = body[plan["ternary_def"][j]].instr_index
                    inner = {i.instr_index for i in walk(body[j]) if i.instr_index < 1 << 63}  # (a NOP's is -1)
                    if j in plan["folded"]:  # the if's lines go, and `T x = b;` of a conditional move with them
                        self._ternary_stmt[body[j].instr_index] = (None, d, inner)
                    else:  # printed where the if was, as `T x = c ? a : b;`
                        self._ternary_stmt[body[j].instr_index] = (value, d, inner)
            # a folded variable declared apart from its assignment loses its declaration with it
            folded_idx.update(i.instr_index for i in walk(hlil.root)
                              if i.operation == Op.HLIL_VAR_DECLARE and i.var in self.inline)
        except Exception:
            self.inline = {}
            self._ternary_stmt = {}
            folded_idx = set()
        for var in self.inline:
            try:
                names[var.name] = var
            except Exception:
                pass
        self._fold_names = names  # display name -> variable, for the token splice
        self._folded_idx = folded_idx
        self._bool_lines = {}  # instr index -> its lines' `c ? 1 : 0` rewritten (bncpp-86), filled on use
        self._bool_rets = {}  # return instr index -> `return b;` (bncpp-10)
        try:
            for i in walk(hlil.root):
                if i.operation == Op.HLIL_RET:
                    line = self._bool_return(i, set())
                    if line is not None:
                        self._bool_rets[i.instr_index] = line
        except Exception:
            self._bool_rets = {}
        return folded_idx

    def plan_lowbyte(self, body, plan):
        """`T r; (uint8_t)r = c1; (uint8_t)r &= c2; return r;` (bncpp-85): x86_64 returns a bool in al, and BN writes
        it into the low byte of a wider result whose upper bytes the caller never reads. r declared apart and
        used nowhere else: the run before the return is one value ("lowbyte", r, first value, [(op, operand)]) that
        folds into the return like a temporary (`return c1 && c2;`), so a temporary of c1 can fold on into it."""
        for m, ret in enumerate(body):
            if ret.operation != Op.HLIL_RET or len(ret.src) != 1 or ret.src[0].operation != Op.HLIL_VAR or m == 0:
                continue
            r, k, ops, first = ret.src[0].var, m - 1, [], None
            if self.def_count(r) != 2 or r in self._addr_taken() or not self.foldable_var(r):
                continue
            while k >= 0 and k not in plan.get("skip", ()) and body[k].operation == Op.HLIL_ASSIGN and \
                    _low_byte(body[k].dest, r):
                v = body[k].src
                if v.operation in _LOW_OPS and _low_byte(v.left, r) and not self.refs(v.right, r):
                    ops.append((v.operation, v.right))
                    k -= 1
                    continue
                if not self.refs(v, r):
                    first = k
                break
            if first is None or self.var_count(r) != sum(self.refs(body[i], r) for i in range(first, m)) + 1:
                continue
            value = ("lowbyte", r, body[first].src, ops[::-1])
            plan.setdefault("own", {})[m - 1] = (r, value, all(self.pure(e) for e in self.value_parts(value)),
                                                 set(range(first, m - 1)))
            plan.setdefault("hidden_decls", set()).update(
                d for d in range(first) if body[d].operation == Op.HLIL_VAR_DECLARE and body[d].var == r)

    def fold_lines(self, keyed):
        """keyed [(tokens, key)] -> the lines with each folded definition dropped and each folded variable's one
        read replaced by its value, rendered through the base language and spliced in (recursively, so a chain of
        folds collapses). key: (function start, HLIL instruction index) or None."""
        folded = self._fold_plan()
        if not folded and not self.inline and not self._ternary_stmt and not self._bool_rets and \
                not self._has_bool_to_int():
            return keyed
        start = self.function.start
        own = lambda key: key[1] if key is not None and key[0] == start else None
        drop, repl = set(), {}  # repl: first line of an if -> (its last line, the `T x = c ? a : b;` line)
        empty = lambda ts: not "".join(t.text for t in ts).strip()
        for value, d, inner in self._ternary_stmt.values():
            # (a blank line carries the key of the statement before it: it stays)
            at = [n for n, (t, key) in enumerate(keyed) if own(key) in inner and not empty(t)]
            head = [n for n, (t, key) in enumerate(keyed) if own(key) == d and not empty(t)]
            if value is None:  # folded into its use: all its lines go (fold_lines keeps one blank separator)
                drop.update(n for n, (_t, key) in enumerate(keyed) if own(key) == d)
                lines = [n for n, (_t, key) in enumerate(keyed) if own(key) in inner]
                if lines:
                    drop.update(range(lines[0], lines[-1] + 1))
            elif at and len(head) == 1 and head[0] < at[0]:
                drop.update(n for n, (_t, key) in enumerate(keyed) if own(key) == d)
                repl[at[0]] = (at[-1], self._ternary_decl(keyed[head[0]][0], value))
        for idx, line in self._bool_rets.items():
            at = [n for n, (t, key) in enumerate(keyed) if own(key) == idx and not empty(t)]
            if len(at) == 1 and at[0] not in repl:
                toks = keyed[at[0]][0]
                indent = "".join(t.text for t in toks)
                indent = indent[:len(indent) - len(indent.lstrip())]
                repl[at[0]] = (at[0], ([tok(TT.TextToken, indent)] if indent else []) + line)
        out, blank = [], False
        n = -1
        while n + 1 < len(keyed):
            n += 1
            toks, key = keyed[n]
            if n in repl:
                n, toks = repl[n]
            elif n in drop or own(key) in folded:
                blank = blank or empty(toks)  # a folded definition: its value moved into a later statement
                continue
            else:
                toks = self._bool_line(toks, own(key))
            closing = "".join(t.text for t in toks).strip().startswith("}")
            if closing and out and empty(out[-1][0]):
                out.pop()  # no blank line left before a closing brace (the block's last statements folded away)
            elif blank and not empty(toks) and out and not empty(out[-1][0]) and not closing:
                out.append(([], None))  # the dropped lines' blank separator stays
            blank = False
            out.append((self._subst_inline(list(toks)), key))
        return out

    def _subst_inline(self, toks, seen=None):
        """replace each LocalVariableToken of a folded variable with its value's tokens (parenthesized unless
        atomic); seen guards against a (never expected) fold cycle"""
        if not self.inline:
            return toks
        seen = seen or set()
        out = []
        for n, t in enumerate(toks):
            var = self._fold_names.get(t.text) if t.type == TT.LocalVariableToken else None
            if var is None or var in seen or var not in self.inline:
                out.append(t)
                continue
            if getattr(self, "_subst_log", None) is not None:
                self._subst_log.add(var)
            # the whole value of a `return v;` / `x = v;` or a whole call argument needs no parentheses
            after = toks[n + 1].text.lstrip() if n + 1 < len(toks) else ""
            before = "".join(x.text for x in out[-2:])
            bare = (after.startswith(";") and re.search(r"(?:^|\s)(?:return|=)\s*$", before) is not None) or \
                (after[:1] in (")", ",") and before.rstrip()[-1:] in ("(", ","))
            out.extend(self._render_value(self.inline[var], seen | {var}, bare))
        return out

    def _expr_tokens(self, e, seen):
        """e as the base language prints it, with folded temporaries substituted"""
        lines = self.base().get_expr_text(e, None, P.TopLevelOperatorPrecedence, False)
        return self._subst_inline(eh_throw._flat([list(l.tokens) for l in lines]), seen)

    def _render_value(self, value, seen, bare=False):
        """a folded value as tokens: the base language's rendering of the expression, with nested folds
        substituted and parentheses added unless it is atomic (or bare: the whole of a statement's value). A
        synthetic ('incdec', ...) value (bncpp-11) renders as `f++` / `++f`, a ('ternary', ...) one (bncpp-9) as
        `c ? a : b`."""
        paren = lambda ts: ts if bare or _atomic(ts) else [tok(TT.TextToken, "(")] + ts + [tok(TT.TextToken, ")")]
        if isinstance(value, tuple) and value[0] == "incdec":
            _, lvalue, step, pre = value[:4]
            toks = self._expr_tokens(lvalue, seen)
            if len(toks) != 1:  # a memory lvalue `*(T*)addr` must be grouped: `(*(T*)addr)++`, not `*(T*)addr++`
                toks = [tok(TT.TextToken, "(")] + toks + [tok(TT.TextToken, ")")]
            op = tok(TT.OperationToken, "++" if step == "+" else "--")
            return [op] + toks if pre else toks + [op]
        if isinstance(value, tuple) and value[0] == "ternary":
            return paren(self._ternary_tokens(value, seen))
        if isinstance(value, tuple) and value[0] == "lowbyte":
            toks = self._lowbyte_bool(value, seen)
            if toks is None:
                toks = _group(self._expr_tokens(value[2], seen))
                for op, x in value[3]:
                    toks += [tok(TT.OperationToken, " %s " % _LOW_OPS[op])] + _group(self._expr_tokens(x, seen))
            return paren(toks)
        return paren(self._expr_tokens(value, seen))

    # --- booleans (bncpp-10): c ? 1 : 0 -> c, c ? x : 0 -> c && x, `return (uint64_t)b & 1;` -> `return b;` ----

    def _bool_tokens(self, e, seen, neg=False):
        """e (an HLIL expression or a folded ('ternary', ...) value) as a C boolean expression -- an int that is 0 or
        1 -- negated with neg; None when e's value is not known to be 0 / 1"""
        if isinstance(e, tuple):
            return self._ternary_bool(e, seen, neg) if e[0] == "ternary" else \
                self._lowbyte_bool(e, seen, neg) if e[0] == "lowbyte" else None
        o = e.operation
        if o == Op.HLIL_VAR and e.var in (self.inline or {}) and e.var not in seen:
            return self._bool_tokens(self.inline[e.var], seen | {e.var}, neg)
        if o in (Op.HLIL_ZX, Op.HLIL_SX, Op.HLIL_LOW_PART):  # widening a 0 / 1 keeps it
            return self._bool_tokens(e.src, seen, neg)
        if o == Op.HLIL_AND and e.right.operation == Op.HLIL_CONST and e.right.constant == 1:
            return self._bool_tokens(e.left, seen, neg)  # b & 1 of a boolean b
        if o == Op.HLIL_BOOL_TO_INT:
            return self._cond_tokens(e.src, seen, neg)
        if o == Op.HLIL_NOT and e.size == 0:
            return self._cond_tokens(e.src, seen, not neg)
        if o in _CMP or o in _FCMP or (o in (Op.HLIL_AND, Op.HLIL_OR) and e.size == 0):
            return self._cond_tokens(e, seen, neg)
        return None

    def _cond_tokens(self, c, seen, neg=False):
        """the condition c (of an if, a bool-to-int) as a 0 / 1 value, negated with neg"""
        if c.operation in (Op.HLIL_CMP_NE, Op.HLIL_CMP_E) and c.right.operation == Op.HLIL_CONST and \
                c.right.constant == 0:
            # Pseudo C prints `x != 0` as `x` and `x == 0` as `!x`: right only when x is 0 / 1 itself
            inner = self._bool_tokens(c.left, seen, neg == (c.operation == Op.HLIL_CMP_NE))
            if inner is not None:
                return inner
            if neg == (c.operation == Op.HLIL_CMP_E):  # x != 0, spelled out
                return self._cmp0(self._expr_tokens(c.left, seen), "!=")
        toks = self._expr_tokens(c, seen)
        boolean = c.operation in _CMP or c.operation in _FCMP or c.size == 0
        if not neg:
            return toks if boolean else self._cmp0(toks, "!=")
        swapped = _invert_cmp(toks) if c.operation in _CMP else None  # (not a float one: NaN)
        if swapped is not None:
            return swapped
        if not boolean:
            return self._cmp0(toks, "==")
        return [tok(TT.OperationToken, "!")] + (toks if _atomic(toks) and not toks[0].text.startswith("!") else
                                                 [tok(TT.TextToken, "(")] + toks + [tok(TT.TextToken, ")")])

    @staticmethod
    def _cmp0(toks, op):
        """`x != 0` / `x == 0`, x parenthesized unless it binds tighter than a comparison"""
        if not _atomic(toks):
            toks = [tok(TT.TextToken, "(")] + toks + [tok(TT.TextToken, ")")]
        return toks + [tok(TT.TextToken, " %s " % op), tok(TT.IntegerToken, "0")]

    def _ternary_bool(self, value, seen, neg=False):
        """c ? a : b with a or b a 0 / 1 constant and the other one boolean, as && / || / ! (else None)"""
        _, _x, iff, a, b = value
        ka, kb = (_bool_const(v) for v in (a, b))
        c = iff.condition
        if ka is not None and kb is not None:
            return None if ka == kb else self._cond_tokens(c, seen, neg != (ka == 0))  # c ? 1 : 0 / c ? 0 : 1
        if ka is None and kb is None:
            return None
        const, other, c_neg = (ka, b, ka == 0) if ka is not None else (kb, a, kb == 1)
        # c ? 1 : x -> c || x, c ? 0 : x -> !c && x, c ? x : 1 -> !c || x, c ? x : 0 -> c && x; negated by De Morgan
        is_or = (const == 1) != neg
        left = self._cond_tokens(c, seen, c_neg != neg)
        right = self._bool_tokens(other, seen, neg)
        if right is None:
            return None
        group = lambda ts: [tok(TT.TextToken, "(")] + ts + [tok(TT.TextToken, ")")] \
            if _top_op(ts, ("||",) if not is_or else ()) or _top_ternary(ts) else ts
        return group(left) + [tok(TT.OperationToken, " || " if is_or else " && ")] + group(right)

    def _lowbyte_bool(self, value, seen, neg=False):
        """a ("lowbyte", ...) value (bncpp-85) as a boolean expression: its first value and operands each 0 / 1, `&`
        / `|` of pure operands as && / || (`& 1` of a boolean is the boolean); else None"""
        _, _r, first, ops = value
        toks = self._bool_tokens(first, seen)
        for op, x in ops:
            if op == Op.HLIL_AND and _bool_const(x) == 1:
                if toks is None:
                    toks = _group(self._expr_tokens(first, seen)) + [tok(TT.OperationToken, " & "),
                                                                      tok(TT.IntegerToken, "1")]
                continue
            right = self._bool_tokens(x, seen) if op in (Op.HLIL_AND, Op.HLIL_OR) and self.pure(x) else None
            if toks is None or right is None:
                return None
            is_or = op == Op.HLIL_OR
            group = lambda ts: [tok(TT.TextToken, "(")] + ts + [tok(TT.TextToken, ")")] \
                if _top_op(ts, ("||",) if not is_or else ()) or _top_ternary(ts) else ts
            toks = group(toks) + [tok(TT.OperationToken, " || " if is_or else " && ")] + group(right)
        if toks is None or not neg:
            return toks
        return [tok(TT.OperationToken, "!"), tok(TT.TextToken, "(")] + toks + [tok(TT.TextToken, ")")]

    # --- c ? 1 : 0 inside a statement (bncpp-86) -------------------------------------------------------------

    def _has_bool_to_int(self):
        hit = getattr(self, "_any_b2i", None)
        if hit is None:
            try:
                hit = any(i.operation == Op.HLIL_BOOL_TO_INT for i in walk(self.function.hlil.root))
            except Exception:
                hit = False
            self._any_b2i = hit
        return hit

    def _bool_line(self, toks, idx):
        """a statement's line with each `c ? 1 : 0` (an HLIL_BOOL_TO_INT on it) printed as c: a C comparison is
        already 0 / 1, and ?: binds loosest, so c fits wherever the ?: was. An assignment whose whole value is the
        boolean (behind widenings / `& 1`) prints `x = c;`."""
        if idx is None or not self._has_bool_to_int():
            return toks
        try:
            st = self.function.hlil[idx]
        except Exception:
            return toks
        nodes = [i for i in _line_nodes(st) if i.operation == Op.HLIL_BOOL_TO_INT]
        if not nodes:
            return toks
        if st.operation in (Op.HLIL_ASSIGN, Op.HLIL_VAR_INIT) and \
                (st.operation == Op.HLIL_VAR_INIT or st.dest.operation == Op.HLIL_VAR):
            whole = self._bool_tokens(st.src, set())
            cut = next((n for n, t in enumerate(toks) if t.text.strip() == "="), None)
            if whole is not None and cut is not None and "".join(t.text for t in toks).rstrip().endswith(";"):
                space = [] if toks[cut].text.endswith(" ") else [tok(TT.TextToken, " ")]
                return toks[:cut + 1] + space + whole + [tok(TT.TextToken, ";")]
        for b in nodes:
            rep = self._bool_tokens(b, set())
            if rep is None:
                continue
            text = "".join(t.text for t in eh_throw._flat([list(l.tokens) for l in self.base().get_expr_text(
                b, None, P.TopLevelOperatorPrecedence, False)]))
            if text:
                toks = _replace_spans(toks, re.compile(re.escape(text)), lambda m, rep=rep: rep)
        return toks

    def _bool_return(self, ret, seen):
        """`return b;` for a return whose value is a boolean behind a widening / `& 1` (`return (uint64_t)var_1 & 1;`
        with var_1 = `c ? 1 : 0`), else None"""
        if len(ret.src) != 1:
            return None
        v = ret.src[0]
        while v.operation in (Op.HLIL_ZX, Op.HLIL_SX) or (v.operation == Op.HLIL_AND and
                                                          v.right.operation == Op.HLIL_CONST and v.right.constant == 1):
            v = v.src if v.operation != Op.HLIL_AND else v.left
        if not (v.operation == Op.HLIL_VAR and v.var in (self.inline or {})) and v.operation != Op.HLIL_BOOL_TO_INT:
            return None  # a plain variable / comparison: nothing is known to be 0 / 1 that Pseudo C does not show
        toks = self._bool_tokens(v, seen)
        if toks is None:
            return None
        return [tok(TT.KeywordToken, "return"), tok(TT.TextToken, " ")] + toks + [tok(TT.TextToken, ";")]

    def _ternary_tokens(self, value, seen):
        simple = self._ternary_bool(value, seen)
        if simple is not None:
            return simple
        _, _x, iff, a, b = value
        cond, a, b = (self._expr_tokens(e, seen) for e in (iff.condition, a, b))
        group = lambda ts: [tok(TT.TextToken, "(")] + ts + [tok(TT.TextToken, ")")] if _top_ternary(ts) else ts
        return group(cond) + [tok(TT.TextToken, " ? ")] + group(a) + [tok(TT.TextToken, " : ")] + b

    def _ternary_decl(self, head, value):
        """`T x = c ? a : b;` from the line declaring x (`T x;`) or initializing it (`T x = b;`)"""
        toks = list(head)
        cut = next((n for n, t in enumerate(toks) if t.text.strip() == "="), None)
        if cut is not None:
            toks = toks[:cut]
        while toks and toks[-1].text.strip() in ("", ";"):
            toks.pop()
        if toks and toks[-1].text.endswith(";"):
            toks[-1] = tok(toks[-1].type, toks[-1].text[:-1])
        return toks + [tok(TT.TextToken, " = ")] + self._ternary_tokens(value, set()) + [tok(TT.TextToken, ";")]

    def emit_token_lines(self, lines, tokens, statement):
        for i, line in enumerate(_brace_do(lines)):
            if i:
                tokens.new_line()
            if not line:
                tokens.scope_separator()  # the emitter drops empty lines; this is Pseudo C's blank line
                continue
            tokens.append(line)
        if statement:
            tokens.new_line()


_OPS = set("+ - * / % & | ^ << >> < > <= >= == != && || ? :".split())
_MAX_WIDTH = 100  # a line a folded conditional expression may make (bncpp-89)
_LOW_OPS = {Op.HLIL_AND: "&", Op.HLIL_OR: "|", Op.HLIL_XOR: "^"}  # compound stores into a low byte (bncpp-85)


def _group(toks):
    return toks if _atomic(toks) else [tok(TT.TextToken, "(")] + toks + [tok(TT.TextToken, ")")]


def _low_byte(e, r):
    """e is the low byte of variable r: `(uint8_t)r` (an offset-0 field or a low part of size 1)"""
    return e.size == 1 and e.operation in (Op.HLIL_STRUCT_FIELD, Op.HLIL_LOW_PART) and \
        getattr(e, "offset", 0) == 0 and e.src.operation == Op.HLIL_VAR and e.src.var == r


def _line_nodes(st):
    """the expressions printed on a statement's own lines: a compound statement's head (condition, a for's
    init / update), not its bodies"""
    o = st.operation
    if o in (Op.HLIL_IF, Op.HLIL_WHILE, Op.HLIL_DO_WHILE, Op.HLIL_SWITCH):
        roots = [st.condition]
    elif o == Op.HLIL_FOR:
        roots = [st.init, st.condition, st.update]
    elif o == Op.HLIL_BLOCK:
        roots = []
    else:
        roots = [st]
    out = []
    for r in roots:
        stack = [r]
        while stack:
            i = stack.pop()
            if i.operation == Op.HLIL_BLOCK:
                continue
            out.append(i)
            stack.extend(children(i))
    return out


def _atomic(toks):
    """the token sequence is a primary expression (a variable, constant, call, index, member access, a cast of
    one, or already fully parenthesized): it needs no parentheses when spliced into a larger expression. True when
    there is no binary / ternary operator at the top level (a leading unary at index 0 binds tight enough)."""
    depth = 0
    for i, t in enumerate(toks):
        s = t.text
        if 0 < i < len(toks) - 1 and depth == 0 and s.strip() in _OPS:
            return False
        for ch in s:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
    return True


_CMP = (Op.HLIL_CMP_E, Op.HLIL_CMP_NE, Op.HLIL_CMP_SLT, Op.HLIL_CMP_ULT, Op.HLIL_CMP_SLE, Op.HLIL_CMP_ULE,
        Op.HLIL_CMP_SGE, Op.HLIL_CMP_UGE, Op.HLIL_CMP_SGT, Op.HLIL_CMP_UGT)
_FCMP = (Op.HLIL_FCMP_E, Op.HLIL_FCMP_NE, Op.HLIL_FCMP_LT, Op.HLIL_FCMP_LE, Op.HLIL_FCMP_GE, Op.HLIL_FCMP_GT,
         Op.HLIL_FCMP_O, Op.HLIL_FCMP_UO)
_INVERSE = {"<": ">=", ">=": "<", ">": "<=", "<=": ">", "==": "!=", "!=": "=="}


def _invert_cmp(toks):
    """a comparison's tokens with its one top-level comparison operator inverted (`a <= b` -> `a > b`), keeping
    the operands as the base language printed them (casts included); None without exactly one"""
    at, depth = [], 0
    for n, t in enumerate(toks):
        if depth == 0 and t.text.strip() in _INVERSE:
            at.append(n)
        if depth == 0 and t.text.strip() in ("&&", "||", "?", ":"):
            return None
        depth += t.text.count("(") + t.text.count("[") - t.text.count(")") - t.text.count("]")
    if len(at) != 1:
        return None
    t = toks[at[0]]
    out = list(toks)
    out[at[0]] = tok(t.type, t.text.replace(t.text.strip(), _INVERSE[t.text.strip()]))
    return out


def _bool_const(v):
    """0 / 1 when v is that integer constant, else None"""
    if v.operation == Op.HLIL_CONST and v.constant in (0, 1):
        return v.constant
    return None


def _top_op(toks, ops):
    """one of ops (operator texts) occurs outside any parentheses"""
    depth = 0
    for t in toks:
        if depth == 0 and t.text.strip() in ops:
            return True
        depth += t.text.count("(") + t.text.count("[") - t.text.count(")") - t.text.count("]")
    return False


def _top_ternary(toks):
    """the tokens hold a ?: outside any parentheses"""
    depth = 0
    for t in toks:
        for ch in t.text:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "?" and depth == 0:
                return True
    return False


def _text(line):
    return "".join(t.text for t in line[0]).strip()


def _brace_do(lines):
    """token lines with each do-while of a one-statement body braced (bncpp-12): Pseudo C prints that body bare,
    `do` / `    x = f();` / ` while (c);` (the brace-less form, with a stray space before the while) -> `do` / `{` /
    `    x = f();` / `} while (c);`"""
    text = lambda l: "".join(t.text for t in l)
    width = lambda s: len(s) - len(s.lstrip())
    out, i = [], 0
    while i < len(lines):
        s = text(lines[i])
        if s.strip() != "do":
            out.append(lines[i])
            i += 1
            continue
        ind, j = width(s), i + 1
        while j < len(lines) and lines[j] and width(text(lines[j])) > ind + 1:
            j += 1
        if j == i + 1 or j >= len(lines) or width(text(lines[j])) != ind + 1 or \
                not text(lines[j]).lstrip().startswith("while ("):
            out.append(lines[i])
            i += 1
            continue
        pad = tok(TT.TextToken, " " * ind)
        close = list(lines[j])
        while close and not close[0].text.strip():
            close.pop(0)
        if close and close[0].text != close[0].text.lstrip():
            close[0] = tok(close[0].type, close[0].text.lstrip())
        out += [lines[i], [pad, tok(TT.BraceToken, "{")]] + list(lines[i + 1:j]) + \
            [[pad, tok(TT.BraceToken, "}"), tok(TT.TextToken, " ")] + close]
        i = j + 1
    return out


def _cleanups(stmts):
    """what a landing pad runs before its dispatch (destructors and the code around them), up to the catch
    plumbing: never ___cxa_begin_catch (a pad can take the exception before it tests), no declarations; nothing
    unless it calls something (a -O0 pad only copies the selector and the exception pointer)"""
    out = []
    for s in stmts:
        if any(eh_render.callee(i) in ("cxa_begin_catch", "cxa_end_catch", "cxa_rethrow") for i in walk(s)):
            break
        if s.operation != Op.HLIL_VAR_DECLARE:
            out.append(s)
    return out if any(i.operation in (Op.HLIL_CALL, Op.HLIL_TAILCALL) for s in out for i in walk(s)) else []


def _key(s):
    """a statement's key across functions (a catch body holds the pad's and the functions it tail-calls')"""
    return s.function.source_function.start, s.expr_index


def _replace_spans(toks, rx, fn):
    """toks with each match of rx in their text replaced by one text token fn(match), or the tokens when fn returns
    a list (None: kept); tokens cut by a match's edge keep their outside part as text"""
    text = "".join(t.text for t in toks)
    ms = [(m.start(), m.end(), fn(m)) for m in rx.finditer(text)]
    ms = [x for x in ms if x[2] is not None]
    if not ms:
        return toks
    starts, p = [], 0
    for t in toks:
        starts.append(p)
        p += len(t.text)

    def piece(a, b):
        out = []
        for t, s in zip(toks, starts):
            e = s + len(t.text)
            if e <= a or s >= b:
                continue
            out.append(t if a <= s and e <= b else tok(TT.TextToken, t.text[max(a, s) - s:min(b, e) - s]))
        return out
    out, cur = [], 0
    for a, b, rep in ms:
        out += piece(cur, a) + (list(rep) if isinstance(rep, list) else [tok(TT.TextToken, rep)])
        cur = b
    return out + piece(cur, len(text))


def _indent(line):
    """the width of a line's leading whitespace"""
    text = "".join(t.text for t in line[0])
    return len(text) - len(text.lstrip())


def _has_try(items):
    return any(it[0] == "try" or (it[0] == "compound" and any(s[0] == "body" and _has_try(s[1]) for s in it[1]))
               for it in items)


class _CatchFolds(PseudoCppFunction):
    """PseudoCppFunction's readability passes on a catch body's lines from func (the landing pad or a function its
    handler tail-calls), with no language representation of its own (bncpp-84); protect: the variables that must
    not fold; end_catch: the instruction indexes of the hidden ___cxa_end_catch() calls (nothing in between)"""
    function = hlil = None  # plain attributes here, not the API's properties

    def __init__(self, func, protect, end_catch):
        self.function, self.hlil, self._protect, self._end_catch = func, func.hlil, protect, end_catch

    def __del__(self):
        pass  # no core handle to free

    def foldable_var(self, var):
        return var not in self._protect

    def fold_transparent(self, body, j, plan):
        return body[j].instr_index in self._end_catch or super().fold_transparent(body, j, plan)


class PseudoCppFunctionType(LanguageRepresentationFunctionType):
    language_name = LANGUAGE_NAME

    def create(self, arch, owner, hlil):
        return PseudoCppFunction(self, arch, owner, hlil)

    def is_valid(self, view):
        try:
            return view.arch is not None and not view.arch.name.startswith("JVM")
        except Exception:
            return False


_registered = None


def register():
    global _registered
    if _registered is None:
        if LANGUAGE_NAME in LanguageRepresentationFunctionType:
            _registered = LanguageRepresentationFunctionType[LANGUAGE_NAME]
        else:
            _registered = PseudoCppFunctionType()
            _registered.register()
    return _registered


def representation(func):
    """the Pseudo Cpp LanguageRepresentationFunction of func"""
    try:
        lr = func.language_representation(LANGUAGE_NAME)
        if lr is not None:
            return lr
    except Exception:
        pass
    return PseudoCppFunction(register(), func.arch, func, func.hlil)


def render_function(func, language=LANGUAGE_NAME):
    """func's body in `language` as plain text lines (for dumps and comparisons)"""
    hlil = func.hlil
    if hlil is None or hlil.root is None:
        why = "analysis skipped: %s" % func.analysis_skip_reason.name if func.analysis_skipped else "no HLIL"
        return ["{", "    // " + why, "}"]
    lr = representation(func) if language == LANGUAGE_NAME else func.language_representation(language)
    return ["".join(t.text for t in line.tokens).rstrip() for line in lr.get_linear_lines(hlil.root)]

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
from ..shared.hlil import walk

Op = HighLevelILOperation
P = OperatorPrecedence
_DEREF_CAST = re.compile(r"^\*\s*\([\w:<> ]+\*\)$")  # '*(uint32_t*)' before a begin_catch


class PseudoCppFunction(TokenMixin, LanguageRepresentationFunction):
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
        items = self.plan_block(instr, regions)  # a one-statement function's root is that statement
        return items if _has_try(items) else None

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
        first, so a throw's allocation and construction are seen with it (cpp/eh_throw.py)"""
        lrs, keyed, plans = {}, [], {}
        for s in plumb.stmts:
            if _key(s) in plumb.rethrow:
                keyed.append((None, None))  # `throw;`
                continue
            f = s.function.source_function  # the pad, or a function its handler tail-calls (bncpp-64)
            lr = lrs.get(f.start) or lrs.setdefault(f.start, f.language_representation(BASE_LANGUAGE))
            for t, k in self.throws(lr.get_expr_text(s, None, P.TopLevelOperatorPrecedence, True), f, False):
                t = self.frame_tokens(t, pad, f)
                keyed.append((self.catch_tokens(t, plumb.names, var) if var is not None else t, k))
            plans[f.start] = self._throws[f.start]
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
        self.emit_token_lines([t for t, _k in self.throws(lines)], tokens, statement)

    def emit_token_lines(self, lines, tokens, statement):
        for i, line in enumerate(lines):
            if i:
                tokens.new_line()
            if not line:
                tokens.scope_separator()  # the emitter drops empty lines; this is Pseudo C's blank line
                continue
            tokens.append(line)
        if statement:
            tokens.new_line()


def _text(line):
    return "".join(t.text for t in line[0]).strip()


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
    """toks with each match of rx in their text replaced by one text token fn(match) (None: kept); tokens cut by
    a match's edge keep their outside part as text"""
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
        out += piece(cur, a) + [tok(TT.TextToken, rep)]
        cur = b
    return out + piece(cur, len(text))


def _indent(line):
    """the width of a line's leading whitespace"""
    text = "".join(t.text for t in line[0])
    return len(text) - len(text.lstrip())


def _has_try(items):
    return any(it[0] == "try" or (it[0] == "compound" and any(s[0] == "body" and _has_try(s[1]) for s in it[1]))
               for it in items)


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

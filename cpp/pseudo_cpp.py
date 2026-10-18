"""The "Pseudo Cpp" language representation.

Seed: every statement is rendered by Binary Ninja's built-in Pseudo C (BASE_LANGUAGE), so the view is a
pass-through. C++ rendering (try/catch from exception tables, readability passes) replaces that statement
by statement; anything it cannot render still falls back to emit_error (HLIL as a comment).

try/catch (bncpp-6, planned in cpp/eh_render.py): in a function with try regions the root block is printed
statement by statement, the statements of a region wrapped in `try { }` and followed by one `catch (T) { }` per
clause with the handler's code from the landing-pad function. The plan is made before anything is emitted; if
it fails, the function is printed as Pseudo C prints it.
"""
from binaryninja import (BraceRequirement, LanguageRepresentationFunction,
                         LanguageRepresentationFunctionType, OperatorPrecedence, log_warn)

from ..constants import BASE_LANGUAGE, LANGUAGE_NAME
from ..shared.tokens import TT, TokenMixin, tok
from . import eh_comments, eh_render
from ..shared import regions as _regions
from ..shared.hlil import walk

P = OperatorPrecedence
_DEREF_CAST = __import__("re").compile(r"^\*\s*\([\w:<> ]+\*\)$")  # '*(uint32_t*)' before a begin_catch


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
        self._handlers = {id(r): self.plan_handlers(r) for r in regions}
        self._in_loop = set()  # regions placed inside a loop (their handlers end at the continuation)
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
        for line in self.base().get_expr_text(block, None, P.TopLevelOperatorPrecedence, True):
            idx = line.il_instruction.instr_index if line.il_instruction is not None else None
            cur = max(cur, owner_of.get(idx, cur))
            groups[cur].append((list(line.tokens), idx))
        return stmts, groups

    def plan_block(self, block, regions):
        stmts, groups = self.stmt_lines(block)
        return self.plan_list(stmts, groups, regions)

    def plan_list(self, stmts, groups, regions):
        """[("stmt", lines) | ("loop", header, items, trailer) | ("try", items, handlers, blank after)]"""
        loops, rest = {}, []
        for r in regions:
            k = eh_render.loop_for(stmts, r, self.cont(r))
            if k is not None:
                loops.setdefault(k, []).append(r)
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
                items.append(self.plan_stmt(stmts[k], groups[k], loops.get(k)))
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
            items.append(("try", self.plan_list(stmts[i:j + 1], sub[:-1] + [last], inner), handlers, blank))
            k = j + 1
        return items

    def plan_stmt(self, st, lines, loop_regions):
        if not loop_regions:
            return ("stmt", lines)
        inner = {i.instr_index for b in eh_render.body(st.body) for i in walk(b)}
        at = [n for n, (_t, idx) in enumerate(lines) if idx in inner]
        if not at:
            return ("stmt", lines)
        header = [l for l in lines[:at[0]] if _text(l) != "{"]
        trailer = lines[at[-1] + 1:]
        if trailer and _text(trailer[0]) == "}":
            trailer = trailer[1:]  # the closing brace is printed with the body
            closes = False
        else:
            closes = bool(trailer) and _text(trailer[0]).startswith("}")  # do { } while (c);
        return ("loop", header, self.plan_block(st.body, loop_regions), trailer, closes)

    def cont(self, region):
        """where the region's handlers go on in this function's own code (the first clause's that does)"""
        return next((h[4] for h in self._handlers[id(region)] if h[4] is not None), None)

    def plan_handlers(self, region):
        """per clause (Clause, pad function | None, plumbing, note | None, continuation | None); plumbing: an
        eh_render.Plumbing, or (cut at the continuation, whole) when the handler goes on in this function"""
        bv = self.function.view
        out, shown = [], set()
        for clause, pad in region.clauses:
            pf = bv.get_function_at(pad)
            if pf is None:
                out.append((clause, None, None, "landing pad %#x is in no function (command: Create landing-pad "
                                                "functions)" % pad, None))
                continue
            on_pad = max(sum(c.kind == c.CATCH for c in cs.clauses) for cs in region.sites if cs.landing_pad == pad)
            h = eh_render.specialize(pf, clause.type_index, on_pad, self.function)
            if h is not None:
                # in a loop the handler ends where it goes on in the loop; elsewhere the pad's copy of the owner's
                # code after it stays (the owner may print nothing after the try: a return folded into it)
                cut = eh_render.plumbing(pf, h.stmts, eh_comments.type_name(clause.type))
                if h.cont is not None:
                    full = eh_render.specialize(pf, clause.type_index, on_pad)
                    cut = (cut, eh_render.plumbing(pf, full.stmts, eh_comments.type_name(clause.type)))
                out.append((clause, pf, cut, None, h.cont))
            elif pad in shown:
                out.append((clause, pf, None, "selector #%d: the landing pad above" % clause.type_index, None))
            else:
                shown.add(pad)
                whole = list(eh_render.body(pf.hlil.root)) if pf.hlil is not None else []
                out.append((clause, pf, eh_render.Plumbing(whole, set(), {}),
                            "the whole landing pad %s: its dispatch on the selector was not found"
                            % pf.symbol.full_name, None))
        return out

    def emit_items(self, items, tokens):
        for it in items:
            if it[0] == "stmt":
                self.emit_token_lines([t for t, _ in it[1]], tokens, True)
            elif it[0] == "loop":
                self.emit_loop(it, tokens)
            else:
                self.emit_try(it, tokens)

    def emit_loop(self, item, tokens):
        """a loop printed around its body's plan: Pseudo C's header and trailer lines, braces always (bncpp-64)"""
        _, header, items, trailer, closes = item
        if header:
            self.emit_token_lines([t for t, _ in header], tokens, True)
        tokens.append_open_brace()
        tokens.new_line()
        tokens.increase_indent()
        self.emit_items(items, tokens)
        tokens.decrease_indent()
        if not closes:
            tokens.append_close_brace()
            tokens.new_line()
        if trailer:
            self.emit_token_lines([t for t, _ in trailer], tokens, True)

    def emit_try(self, item, tokens):
        _, items, handlers, blank = item
        self.kw(tokens, "try")
        self.open_block(tokens)
        self.emit_items(items, tokens)
        self.close_block(tokens)
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
                lrs = {}
                for s in plumb.stmts:
                    f = s.function.source_function  # the pad, or a function its handler tail-calls (bncpp-64)
                    lr = lrs.get(f.start) or lrs.setdefault(f.start, f.language_representation(BASE_LANGUAGE))
                    if s.expr_index in plumb.rethrow:
                        self.kw(tokens, "throw")
                        tokens.append_semicolon()
                        tokens.new_line()
                        continue
                    lines = lr.get_expr_text(s, None, P.TopLevelOperatorPrecedence, True)
                    if var is not None:
                        lines = [self.catch_tokens(list(l.tokens), plumb.names, var) for l in lines]
                    else:
                        lines = [list(l.tokens) for l in lines]
                    self.emit_token_lines(lines, tokens, True)
            self.close_block(tokens)
        if blank:
            tokens.scope_separator()

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
        self.emit_lines(self.base().get_expr_text(instr, None, precedence, statement), tokens, statement)

    def emit_lines(self, lines, tokens, statement):
        self.emit_token_lines([list(line.tokens) for line in lines], tokens, statement)

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


def _has_try(items):
    return any(it[0] == "try" or (it[0] == "loop" and _has_try(it[2])) for it in items)


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

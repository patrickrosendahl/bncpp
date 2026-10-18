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
        """the root block as [("stmt", s) | ("try", Region, items, handlers)], or None without a placed region"""
        hlil = self.function.hlil
        if hlil is None or hlil.root is None or instr.expr_index != hlil.root.expr_index:
            return None
        regions = eh_render.regions(self.function)
        if not regions:
            return None
        items = self.plan_stmts(eh_render.body(instr), regions)  # a one-statement function's root is that statement
        return items if any(it[0] == "try" for it in items) else None

    def plan_stmts(self, stmts, regions):
        pcs = [eh_render.call_addrs(s) or None for s in stmts]
        by_range = {(r.start, r.end): r for r in regions}
        runs = {i: (i, j, by_range[(g[0], g[1])])
                for i, j, g in _regions.try_runs(pcs, [(r.start, r.end, ()) for r in regions])}
        items, k = [], 0
        while k < len(stmts):
            if k not in runs:
                items.append(("stmt", stmts[k]))
                k += 1
                continue
            i, j, r = runs[k]
            inner = [x for x in regions if x is not r and r.start <= x.start and x.end <= r.end]
            items.append(("try", r, self.plan_stmts(stmts[i:j + 1], inner), self.plan_handlers(r)))
            k = j + 1
        return items

    def plan_handlers(self, region):
        """per clause (Clause, pad function | None, eh_render.Plumbing | None, note | None); no Plumbing: the
        statements are shown as they are (the whole pad), in Plumbing-less form [statement]"""
        bv = self.function.view
        out, shown = [], set()
        for clause, pad in region.clauses:
            pf = bv.get_function_at(pad)
            if pf is None:
                out.append((clause, None, None, "landing pad %#x is in no function (command: Create landing-pad "
                                                "functions)" % pad))
                continue
            on_pad = max(sum(c.kind == c.CATCH for c in cs.clauses) for cs in region.sites if cs.landing_pad == pad)
            stmts = eh_render.specialize(pf, clause.type_index, on_pad)
            if stmts is not None:
                out.append((clause, pf, eh_render.plumbing(pf, stmts, eh_comments.type_name(clause.type)), None))
            elif pad in shown:
                out.append((clause, pf, None, "selector #%d: the landing pad above" % clause.type_index))
            else:
                shown.add(pad)
                whole = list(eh_render.body(pf.hlil.root)) if pf.hlil is not None else []
                out.append((clause, pf, eh_render.Plumbing(whole, set(), {}),
                            "the whole landing pad %s: its dispatch on the selector was not found"
                            % pf.symbol.full_name))
        return out

    def emit_items(self, items, tokens):
        for it in items:
            if it[0] == "stmt":
                self.emit_base(it[1], tokens, None, P.TopLevelOperatorPrecedence, True)
            else:
                self.emit_try(it, tokens)

    def emit_try(self, item, tokens):
        _, _region, items, handlers = item
        self.kw(tokens, "try")
        self.open_block(tokens)
        self.emit_items(items, tokens)
        self.close_block(tokens)
        for clause, pf, plumb, note in handlers:
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
                lr = pf.language_representation(BASE_LANGUAGE)
                for s in plumb.stmts:
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

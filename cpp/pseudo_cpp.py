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
from ..shared.tokens import TokenMixin
from . import eh_comments, eh_render
from ..shared import regions as _regions

P = OperatorPrecedence


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
        """per clause (Clause, pad function | None, [statement], note | None)"""
        bv = self.function.view
        out, shown = [], set()
        for clause, pad in region.clauses:
            pf = bv.get_function_at(pad)
            if pf is None:
                out.append((clause, None, [], "landing pad %#x is in no function (command: Create landing-pad "
                                                "functions)" % pad))
                continue
            on_pad = max(sum(c.kind == c.CATCH for c in cs.clauses) for cs in region.sites if cs.landing_pad == pad)
            stmts = eh_render.specialize(pf, clause.type_index, on_pad)
            if stmts is not None:
                out.append((clause, pf, stmts, None))
            elif pad in shown:
                out.append((clause, pf, [], "selector #%d: the landing pad above" % clause.type_index))
            else:
                shown.add(pad)
                out.append((clause, pf, list(eh_render.body(pf.hlil.root)) if pf.hlil is not None else [],
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
        for clause, pf, stmts, note in handlers:
            self.kw(tokens, "catch")
            self.txt(tokens, " ")
            tokens.append_open_paren()
            self.type_tok(tokens, eh_comments.type_name(clause.type))
            tokens.append_close_paren()
            self.open_block(tokens)
            if note:
                self.note(tokens, "// " + note)
                tokens.new_line()
            if stmts:
                lr = pf.language_representation(BASE_LANGUAGE)
                for s in stmts:
                    self.emit_lines(lr.get_expr_text(s, None, P.TopLevelOperatorPrecedence, True), tokens, True)
            self.close_block(tokens)

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
        for i, line in enumerate(lines):
            if i:
                tokens.new_line()
            if not line.tokens:
                tokens.scope_separator()  # the emitter drops empty lines; this is Pseudo C's blank line
                continue
            tokens.append(list(line.tokens))
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

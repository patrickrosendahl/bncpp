# shared with binary-jvm/pseudo_java.py (PseudoJavaFunction: kw / txt / op / type_tok / note, emit_error;
# synced at a01bc06); keep language-neutral
"""Token helpers and emit_error for a LanguageRepresentationFunction.

TokenMixin needs from the language class:
  language_label  -- str, the name printed in error comments ("Pseudo C++", "Pseudo Java")
  hlil_lines(s)   -- optional: the HLIL text of statement s as a list of lines (default: str(s))
"""
from binaryninja import InstructionTextToken, InstructionTextTokenType, log_warn

TT = InstructionTextTokenType


def tok(kind, text, **kw):
    return InstructionTextToken(kind, text, **kw)


class TokenMixin:
    language_label = "?"

    def kw(self, tokens, text):
        tokens.append(tok(TT.KeywordToken, text))

    def txt(self, tokens, text):
        tokens.append(tok(TT.TextToken, text))

    def op(self, tokens, text):
        tokens.append(tok(TT.OperationToken, text))

    def type_tok(self, tokens, text):
        tokens.append(tok(TT.TypeNameToken, text))

    def note(self, tokens, text):
        tokens.append(tok(TT.CommentToken, text))

    def hlil_lines(self, s):
        try:
            return [str(l) for l in s.lines] if hasattr(s, "lines") else str(s).split("\n")
        except Exception:
            return [str(s)]

    def emit_error(self, s, ex, tokens):
        """never lose a statement: if rendering fails, print its HLIL as a comment"""
        try:
            log_warn("%s: %s at %#x: %r" % (self.language_label, type(ex).__name__, s.address, ex))
        except Exception:
            pass
        tokens.new_line()
        self.note(tokens, "// [%s could not render this statement: %s]" % (self.language_label, type(ex).__name__))
        tokens.new_line()
        for line in self.hlil_lines(s):
            self.note(tokens, "// " + line)
            tokens.new_line()

# shared with binary-jvm: not yet (new here, bncpp-36); C-family source, keep language-neutral otherwise
"""Source side of the sloppy line mapping (bncpp-36): a tolerant scanner for C / C++ / Objective-C source that
finds the function definitions (name, line range) and, per line, what a binary can show of it:
  str     string literals (adjacent ones joined, escapes decoded)
  num     integer literals (decimal / hex / octal, suffixes dropped) other than 0 and 1
  call    identifiers called: name( -- including macros (assert, panic, ...)
  text    the argument text of a call whose name looks like an assertion / panic macro (ALL_CAPS or assert*),
          whitespace-normalised: #e stringises it into the binary
No preprocessor, no compiler: xnu does not compile standalone. Preprocessor lines are skipped (a #define body
is not code of the function it sits in); #if branches are all read (the binary has one of them).

  idx = index_file(path)            -> SourceFile: .functions [SourceFunction], .lines {line: [(kind, value)]}
  idx = index_tree(root, exts)      -> {path: SourceFile}   (lazy per file through SourceTree)
Pure Python, no Binary Ninja import.
"""
import os
import re

_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "catch", "alignof",
             "__attribute__", "__typeof__", "typeof", "decltype", "static_assert", "_Static_assert", "defined",
             "__builtin_expect", "__improbable", "__probable", "likely", "unlikely", "new", "delete", "throw",
             "__asm__", "asm", "__declspec", "offsetof", "__builtin_offsetof", "va_arg", "OS_EXPECT"}
_TYPE_SCOPES = {"struct", "class", "union", "enum"}
_ASSERTY = re.compile(r"^(?:[A-Z][A-Z0-9_]{2,}|assert\w*|panic\w*|\w*_assert\w*|require\w*)$")


class SourceFunction:
    __slots__ = ("name", "qualname", "file", "first", "last", "body_first", "inline")

    def __init__(self, name, qualname, file, first, last, body_first, inline=False):
        self.name, self.qualname, self.file = name, qualname, file
        self.first, self.last, self.body_first = first, last, body_first
        self.inline = inline     # declared inline: its code may live only inside its callers

    def __repr__(self):
        return "<SourceFunction %s %s:%d-%d>" % (self.qualname, os.path.basename(self.file), self.first, self.last)


class SourceFile:
    def __init__(self, path):
        self.path = path
        self.functions = []
        self.lines = {}      # line -> [(kind, value)]
        self.nlines = 0

    def function_at(self, line):
        best = None
        for f in self.functions:
            if f.first <= line <= f.last and (best is None or f.first >= best.first):
                best = f
        return best

    def features(self, f):
        """[(line, kind, value)] inside a function, in line order"""
        return [(ln, k, v) for ln in range(f.first, f.last + 1) for k, v in self.lines.get(ln, ())]


def _decode(s):
    """a C string literal's body -> its value (the common escapes; others kept as they are)"""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            m = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'", "a": "\a", "b": "\b",
                 "f": "\f", "v": "\v"}.get(n)
            if n == "x":
                h = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
                if h:
                    out.append(chr(int(h.group(0), 16)))
                    i += 2 + len(h.group(0))
                    continue
            if m is not None and not (n == "0" and i + 2 < len(s) and s[i + 2].isdigit()):
                out.append(m)
                i += 2
                continue
            out.append(n)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r\f\v]+) | (?P<nl>\n) | (?P<lc>//[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<str>(?:u8|u|U|L|@)?"(?:\\.|[^"\\\n])*") | (?P<chr>(?:u8|u|U|L)?'(?:\\.|[^'\\\n])*') |
    (?P<num>0[xX][0-9a-fA-F']+[uUlL]*|\d[\d']*(?:\.\d*)?(?:[eE][+-]?\d+)?[uUlLfF]*) |
    (?P<id>[A-Za-z_]\w*) | (?P<op>::|->|\S)
""", re.S | re.X)


def _tokens(text):
    """[(kind, value, line)]; preprocessor lines (with their continuations) dropped"""
    out, line = [], 1
    at_line_start = True
    pos, n = 0, len(text)
    while pos < n:
        if at_line_start:
            m = re.match(r"[ \t]*#", text[pos:pos + 200])
            if m:  # a directive: skip to the end of the line, following backslash continuations and comments
                j = pos
                while j < n:
                    k = text.find("\n", j)
                    if k < 0:
                        k = n
                    seg = text[j:k]
                    bc = seg.rfind("/*")
                    if bc >= 0 and seg.find("*/", bc) < 0:  # a block comment runs on
                        e = text.find("*/", j + bc)
                        e = n if e < 0 else e + 2
                        line += text.count("\n", j, e)
                        j = e
                        continue
                    if k < n and seg.rstrip().endswith("\\"):
                        line += 1
                        j = k + 1
                        continue
                    j = k
                    break
                pos = j
                continue
        m = _TOKEN.match(text, pos)
        if m is None:
            pos += 1
            continue
        k = m.lastgroup
        v = m.group(k)
        if k == "nl":
            line += 1
            at_line_start = True
        elif k in ("ws",):
            pass
        elif k in ("lc", "bc"):
            line += v.count("\n")
            if "\n" in v:
                at_line_start = True
        else:
            out.append((k, v, line))
            at_line_start = False
        pos = m.end()
    return out


def _num(v):
    v = v.replace("'", "").rstrip("uUlLfF")
    try:
        if v.lower().startswith("0x"):
            return int(v, 16)
        if "." in v or "e" in v.lower():
            return None
        if len(v) > 1 and v.startswith("0"):
            return int(v, 8)
        return int(v)
    except ValueError:
        return None


def index_text(text, path):
    sf = SourceFile(path)
    sf.nlines = text.count("\n") + 1
    toks = _tokens(text)
    # scopes: a stack of (kind, name): 'ns' / 'type' / 'func' / 'block'
    stack = []
    i, n = 0, len(toks)
    func_depth = None  # stack depth of the current function's body
    cur = None

    def add(line, kind, value):
        sf.lines.setdefault(line, []).append((kind, value))

    while i < n:
        k, v, ln = toks[i]
        if k == "op" and v == "{":
            kind, name = "block", None
            if func_depth is None:
                kind, name, start = _classify_brace(toks, i, stack)
                if kind == "func":
                    func_depth = len(stack)
                    quals = [s[1] for s in stack if s[0] in ("ns", "type") and s[1]]
                    qual = "::".join(quals + [name]) if quals and "::" not in name else name
                    start, inline = start
                    cur = SourceFunction(name.split("::")[-1], qual, path, start, ln, ln, inline)
            stack.append((kind, name))
            i += 1
            continue
        if k == "op" and v == "}":
            if stack:
                stack.pop()
            if func_depth is not None and len(stack) == func_depth:
                cur.last = ln
                sf.functions.append(cur)
                func_depth, cur = None, None
            i += 1
            continue
        if func_depth is not None:
            if k == "str":
                # adjacent literals join ("a" "b"); identifiers between them are macros (PRIu64): kept as a gap
                parts, j, first_ln = [], i, ln
                while j < n and (toks[j][0] == "str" or (toks[j][0] == "id" and j + 1 < n and toks[j + 1][0] == "str"
                                                         and parts)):
                    if toks[j][0] == "str":
                        body = toks[j][1]
                        body = body[body.index('"') + 1:-1]
                        parts.append(_decode(body))
                    else:
                        parts.append("\0")  # a macro piece we cannot expand
                    j += 1
                add(first_ln, "str", "".join(parts))
                i = j
                continue
            if k == "num":
                x = _num(v)
                if x is not None and x not in (0, 1):
                    add(ln, "num", x)
            elif k == "id" and i + 1 < n and toks[i + 1][1] == "(" and v not in _KEYWORDS:
                add(ln, "call", v)
                if _ASSERTY.match(v):
                    j, depth, parts = i + 2, 1, []
                    while j < n and depth:
                        t = toks[j][1]
                        if t == "(":
                            depth += 1
                        elif t == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        parts.append(t)
                        j += 1
                    txt = _join(parts)
                    if len(txt) >= 3:
                        add(ln, "text", txt)
        i += 1
    if cur is not None:  # an unbalanced file: keep what was open
        cur.last = toks[-1][2] if toks else cur.first
        sf.functions.append(cur)
    return sf


def _join(parts):
    """tokens back to text the way #e stringises them: one space between tokens where the source likely had one"""
    out = ""
    for t in parts:
        if out and (out[-1].isalnum() or out[-1] in "_)\"'") and (t[0].isalnum() or t[0] in "_\"'("):
            out += " "
        elif out and t not in ("(", ")", "[", "]", ".", "->", ",", ";") and out[-1] not in "([.!~" \
                and not (out.endswith("->")):
            out += " "
        out += t
    return out.replace(" ,", ",")


def _classify_brace(toks, i, stack):
    """what a '{' at token i opens: ('func', name, first line) for a function body, ('ns', name, _) for a
    namespace / extern "C" block, ('type', name, _) for a struct / class / union / enum body, else ('block', ..)"""
    if any(s[0] == "func" for s in stack):
        return "block", None, None
    j = i - 1
    # skip trailing qualifiers / attributes / initialiser lists: ') const noexcept override {' / ') : a(x), b(y) {'
    paren = 0
    while j >= 0:
        k, v, ln = toks[j]
        if v == ")":
            # find the matching '(' and look at what precedes it
            depth, m = 0, j
            while m >= 0:
                if toks[m][1] == ")":
                    depth += 1
                elif toks[m][1] == "(":
                    depth -= 1
                    if depth == 0:
                        break
                m -= 1
            if m <= 0:
                return "block", None, None
            pk, pv, pln = toks[m - 1]
            if pk == "id" and pv not in _KEYWORDS:
                # a constructor initialiser 'a(x)' after ':' or ',' -- keep walking back to the real parameter list
                q = m - 2
                if q >= 0 and toks[q][1] in (":", ",") and _initializer_list(toks, q):
                    j = q - 1
                    continue
                if pv in ("__attribute__", "__declspec", "alignas", "noexcept", "throw"):
                    j = m - 2
                    continue
                name, s = pv, m - 1
                while s >= 2 and toks[s - 1][1] == "::" and toks[s - 2][0] == "id":
                    name = toks[s - 2][1] + "::" + name
                    s -= 2
                if s >= 1 and toks[s - 1][1] == "~":
                    name = "~" + name
                    s -= 1
                if name.split("::")[-1].startswith("operator"):
                    pass
                return "func", name, (_decl_start(toks, s), _inline_before(toks, s))
            if pv == "operator" or (m >= 2 and toks[m - 2][1] == "operator"):
                return "func", "operator" + (pv if pv != "operator" else ""), (_decl_start(toks, m - 1),
                                                                              _inline_before(toks, m - 1))
            return "block", None, None
        if k == "id" and v in ("const", "override", "final", "noexcept", "volatile", "try", "mutable",
                               "OS_NOINLINE", "__attribute__"):
            j -= 1
            continue
        if v in ("&", "&&") or k == "id" and v.isupper():  # ref-qualifiers, attribute macros (OS_WARN_RESULT)
            j -= 1
            continue
        if k == "id" and j >= 1 and toks[j - 1][1] == "namespace":
            return "ns", v, None
        if v == "namespace":
            return "ns", None, None
        if k == "str" and j >= 1 and toks[j - 1][1] == "extern":
            return "ns", None, None
        # 'struct X {', 'class X : public Y {', 'enum E : int {'
        q = j
        while q >= 0 and toks[q][1] not in (";", "{", "}", ")", "="):
            if toks[q][1] in _TYPE_SCOPES:
                nm = toks[q + 1][1] if q + 1 < len(toks) and toks[q + 1][0] == "id" else None
                return "type", nm, None
            q -= 1
        return "block", None, None
    return "block", None, None


def _initializer_list(toks, q):
    """toks[q] is ':' or ',' of a constructor initialiser list (walk back over 'id(...)' / 'id{...}' items)"""
    while q >= 0:
        if toks[q][1] == ":":
            return q >= 1 and toks[q - 1][1] == ")"
        if toks[q][1] != ",":
            return False
        p = q - 1
        if p < 0 or toks[p][1] not in (")", "}"):
            return False
        close, open_ = toks[p][1], "(" if toks[p][1] == ")" else "{"
        depth = 0
        while p >= 0:
            if toks[p][1] == close:
                depth += 1
            elif toks[p][1] == open_:
                depth -= 1
                if depth == 0:
                    break
            p -= 1
        if p < 1 or toks[p - 1][0] != "id":
            return False
        q = p - 2
    return False


def _decl_start(toks, s):
    """the line a declaration starts on: walk back from its name over the return type / specifiers to the end of
    the previous statement or brace"""
    j = s - 1
    line = toks[s][2]
    while j >= 0 and toks[j][1] not in (";", "{", "}", ")") and toks[j][0] != "str":
        if toks[j][1] == ">":  # template<...>
            pass
        line = toks[j][2]
        j -= 1
    return line


def _inline_before(toks, s):
    """a declaration's specifiers before its name say inline (inline, __inline, always_inline,
    __header_always_inline ...; not noinline): walk back to the previous statement or brace"""
    j = s - 1
    while j >= 0 and s - j < 48 and toks[j][1] not in (";", "{", "}"):
        if toks[j][0] == "id":
            v = toks[j][1].lower()
            if "inline" in v and "noinline" not in v:
                return True
        j -= 1
    return False


def index_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return index_text(fh.read(), path)


SOURCE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hpp", ".s")


class SourceTree:
    """the files of a source tree, indexed on first use; inverted indexes for the anchors over the files indexed"""

    def __init__(self, root, exts=(".c", ".cc", ".cpp", ".cxx", ".m", ".mm")):
        self.root = os.path.abspath(root)
        self.paths = []
        for d, dirs, files in os.walk(self.root):
            dirs[:] = sorted(x for x in dirs if not x.startswith("."))
            for f in sorted(files):
                if f.endswith(exts):
                    self.paths.append(os.path.join(d, f))
        self._files = {}

    def file(self, path):
        if path not in self._files:
            self._files[path] = index_file(path)
        return self._files[path]

    def all(self):
        return [self.file(p) for p in self.paths]

    def by_suffix(self, name):
        """the files whose path ends with the given path / file name (a __FILE__ string)"""
        name = name.replace("\\", "/").lstrip("./")
        return [p for p in self.paths if p.endswith("/" + name) or p == name]

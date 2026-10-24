# from binary-jvm tests/bn_pseudo_java_compare.py (no-loss checks) and tests/vineflower_compare.py (counters,
# statements, dead_after_return, leaked_catch_var, --max gates); bncpp-8, 2026-10-17. Keep language-neutral:
# the language passes its regexes (counters, catch variables) and the names that may vanish.
"""Check a decompiler's output against a reference rendering of the same function, offline.

The reference is what must not be lost (binary-cpp: BN's Pseudo C, i.e. the HLIL as BN prints it): every called
name and every string literal in it must still be in the output, whitespace-insensitive. On top come
per-function flaw counters (regexes given by the language), structural checks (braces, truncation, dead code
after a jump, a catch variable used outside its catch) and statement counts; totals are gated with --max K=V.
"""
import re

# the renderers' marker for a function BN skipped (binary-cpp cpp/pseudo_cpp.py render_function, binary-jvm's
# dump): its output is no evidence either way, counted as 'skipped' instead of checked (bncpp-148, jvm-103)
SKIPPED = re.compile(r"//\s*analysis skipped\b")

KEYWORDS = {"if", "while", "for", "switch", "catch", "return", "sizeof", "do", "else", "case", "throw", "new",
            "delete", "synchronized", "super", "this"}


def split_functions(text, header):
    """[(key, header line, body lines)] of a dump in which each function starts with a line matching header
    (a compiled regex; its first group, or the whole line, is the key)"""
    out = []
    for line in text.splitlines():
        m = header.match(line)
        if m:
            out.append((m.group(1) if m.groups() else line, line, []))
        elif out:
            out[-1][2].append(line)
    for _key, _h, body in out:
        while body and not body[-1].strip():
            body.pop()
    return out


def strip_strings(text):
    return re.sub(r'"(\\.|[^"\\])*"', '""', text)


def _strip_offset_types(code):
    """code with the arguments of BN's pointer-into-a-struct type syntax `__offset(T, 0x14)` dropped: T is a
    type (`__func<pick_fn(int32_t const*), int32_t (int32_t)>`), its parentheses are no calls"""
    out, pos = [], 0
    for m in re.finditer(r"\b__offset\(", code):
        if m.start() < pos:
            continue
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[j], 0)
            j += 1
        out.append(code[pos:m.end()] + ")")
        pos = j
    return "".join(out) + code[pos:]


def strip_comments(text):
    """line comments and block comments removed (string literals kept)"""
    return re.sub(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", text, flags=re.S)


def string_literals(text):
    """the string literals, adjacent ones (wrapped across lines) joined, spaces removed"""
    flat = re.sub(r'"\s*\n\s*\+?\s*"', "", text)
    return {m.group(0).replace(" ", "") for m in re.finditer(r'"(\\.|[^"\\])*"', flat)}


def called_names(text, ignore=()):
    """the names written in front of '(' (the last component of a qualified name), keywords and ignore (names or
    a regex they fully match) dropped"""
    code = _strip_offset_types(strip_strings(text))
    names = set(re.findall(r"(?<![\w$])([A-Za-z_$~][\w$]*)\s*\(", code))
    drop = ignore.fullmatch if hasattr(ignore, "fullmatch") else ignore.__contains__
    return {n for n in names if n not in KEYWORDS and not drop(n)}


def statements(lines):
    """logical lines: comments dropped, wrapped continuation lines joined (a line that does not end with
    `;`, `{`, `}` or `:` continues on the next one), lines of only braces not counted"""
    out, cur = [], ""
    for l in lines:
        code = re.sub(r'("(?:\\.|[^"\\])*")|//.*', lambda m: m.group(1) or "", l).strip()
        if not code:
            continue
        cur = cur + " " + code if cur else code
        if code[-1] in ";{}:":
            out.append(cur)
            cur = ""
    if cur:
        out.append(cur)
    return [s for s in out if s.replace(" ", "") not in ("", "{", "}", "{}")]


def dead_after_return(lines):
    """a jump right after a jump at the same indentation (`return x; break;`)"""
    n = 0
    for a, b in zip(lines, lines[1:]):
        if re.match(r"^\s*(return\b.*|throw\b.*|break|continue);\s*$", a.strip() and a or "x") and \
                re.match(r"^\s*(return|break|continue|throw)\b", b) and \
                len(a) - len(a.lstrip()) == len(b) - len(b.lstrip()):
            n += 1
    return n


def leaked_catch_var(lines, catch_var):
    """lines that use a catch variable outside its catch block; catch_var: a regex whose group 1 is the
    variable of a catch header (Java `catch \\((?:[\\w.$]+\\s*\\|\\s*)*[\\w.$]+ (\\w+)\\)`)"""
    n, depth, stack = 0, 0, []
    names = sorted({m.group(1) for l in lines for m in [re.search(catch_var, l)] if m})
    for l in lines:
        code = re.sub(r"(\.|->)\s*[\w$]+", ".", strip_strings(re.sub(r"//.*", "", l)))  # members are not variables
        m = re.search(catch_var, code)
        if m:
            stack.append([m.group(1), depth - code[:m.start()].count("}"), False])
        for v in names:
            declared = re.search(r"^\s*[\w.$<>\[\]:*&]+ %s\b" % re.escape(v), code)
            if re.search(r"\b%s\b" % re.escape(v), code) and not declared and not any(s[0] == v for s in stack):
                n += 1
                break
        depth += code.count("{") - code.count("}")
        for s in stack:
            s[2] = s[2] or depth > s[1]  # its block opened (on the header line or, C style, the next one)
        while stack and stack[-1][2] and depth <= stack[-1][1]:
            stack.pop()
    return n


def check_function(body, ref_body=None, counters=None, distinct=(), ignore=(), catch_var=None):
    """{counter: n, lost_calls: [...], lost_strings: [...]} for one function's output lines (body) against the
    reference lines (ref_body; None: no no-loss check). counters: {name: compiled regex} counted over the text
    without string literals (comments kept: a render-error marker is a comment); distinct: the counters that
    count different matches (temporaries); ignore: names (or a regex) that may vanish (plumbing the output hides).
    skipped: 1 when BN skipped the function's analysis in the output or the reference (SKIPPED); then no no-loss
    lists, since a skipped side shows no code, not lost code"""
    text = "\n".join(body)
    code = strip_strings(text)
    r = {}
    for k, p in (counters or {}).items():
        r[k] = len(set(m.group(0) for m in p.finditer(code))) if k in distinct else len(p.findall(code))
    bare = strip_comments(code)
    r["unbalanced"] = int(bare.count("{") != bare.count("}"))
    r["truncated"] = int(not body or body[-1].strip() != "}")
    r["dead_code"] = dead_after_return(body)
    r["leaked_catch_var"] = leaked_catch_var(body, catch_var) if catch_var else 0
    stmts = statements(body)
    r["stmts"] = len(stmts)
    r["skipped"] = int(bool(SKIPPED.search(text) or ref_body and SKIPPED.search("\n".join(ref_body))))
    if ref_body is not None:
        ref = "\n".join(ref_body)
        r["ref_stmts"] = len(statements(ref_body))
        skip = r["skipped"]
        r["lost_calls"] = [] if skip else sorted(called_names(ref, ignore) - called_names(text))
        r["lost_strings"] = [] if skip else sorted(string_literals(ref) - string_literals(text))
    return r


def totals(rows, keys):
    """sums over the rows; list values (lost_*) count their entries; more_stmts / fewer_stmts vs the reference"""
    t = {k: sum(len(r.get(k, ())) if isinstance(r.get(k), list) else r.get(k, 0) for r in rows) for k in keys}
    matched = [r for r in rows if "ref_stmts" in r]
    t["functions"] = len(rows)
    t["more_stmts"] = sum(1 for r in matched if r["stmts"] > r["ref_stmts"])
    t["fewer_stmts"] = sum(1 for r in matched if r["stmts"] < r["ref_stmts"])
    return t


def gate(total, maxes):
    """the failed gates: ['K=n > V'] for every K=V in maxes (a dict or 'K=V' strings) that the totals exceed"""
    if not isinstance(maxes, dict):
        maxes = dict((kv.split("=")[0], int(kv.split("=")[1])) for kv in maxes)
    return ["%s=%d > %d" % (k, total.get(k, 0), v) for k, v in sorted(maxes.items()) if total.get(k, 0) > v]

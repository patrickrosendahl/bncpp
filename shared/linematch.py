# shared with binary-jvm: not yet (new here, bncpp-36); keep language-neutral
"""Sloppy address -> source line matching (bncpp-36). Lazy by design (optimised code never maps cleanly, so no
exact-line attempt, user 2026-10-14): anchors pin addresses where the binary carries source evidence, the code
between two anchors gets the source range between them.

Inputs are plain data, so this is pure Python and testable off BN:
  bin_funcs:  [{"start", "end", "name" (or None), "insns": [addr], "features": [(addr, kind, value)]}]
              kinds: str, num, call, bl (tests/ref_bin_features.py, or the BN extractor)
  src:        a source index (shared.srcindex.SourceTree / SourceFile) over the given tree
Output: a shared.linemap.LineMap with rows (ranges, confidence, provenance) and matched functions.

Pipeline:
  1. per binary function, the anchors its features give (a file:line from an assert/panic file-string + line-const
     pair; else source lines that carry the same rare string / number / call name)
  2. match a binary function to a source function by the anchors they share (a file-line anchor decides; else the
     best-scoring source function in the anchored file / by shared features), then fill its range
  3. inside the matched pair, the anchors pin their addresses; between consecutive anchors the row covers the
     source lines between them; before the first / after the last anchor, the function's remaining range
"""
import re

from .linemap import Function, LineMap, Row

CONF = {"file-line": 0.95, "string": 0.8, "const": 0.6, "call": 0.55, "between": 0.4, "function": 0.2}


def _file_line_anchors(feats):
    """(addr, file, line) where a feature window has a __FILE__-looking string and, nearby, the line constant:
    asserts pass both -- a string with a path/basename and a plain int in the same handful of instructions"""
    out = []
    strs = [(a, v) for a, k, v in feats if k == "str"]
    nums = [(a, v) for a, k, v in feats if k == "num"]
    for sa, sv in strs:
        fn = _looks_like_file(sv)
        if fn is None:
            continue
        near = [(abs(na - sa), nv) for na, nv in nums if 0 < nv < 100000 and abs(na - sa) <= 32]
        if near:
            near.sort()
            out.append((sa, fn, near[0][1]))
    return out


_FILE_RE = re.compile(r"([\w./+-]+\.(?:c|cc|cpp|cxx|m|mm|h|hpp|s))\b")


def _looks_like_file(s):
    """a file name inside a string (the whole string is a path, or a __FILE__ fragment inside an assert text)"""
    s = s.strip()
    m = _FILE_RE.search(s)
    if m and ("/" in m.group(1) or "." in m.group(1)):
        if m.group(0) == s or "/" in m.group(1) or len(s) < 80:
            return m.group(1)
    return None


def _rare(features):
    """the features worth matching on: strings (not tiny), numbers, call names"""
    out = []
    for a, k, v in features:
        if k == "str" and isinstance(v, str) and len(v.strip()) >= 4 and "\0" not in v:
            out.append((a, "str", v.strip()))
        elif k == "num":
            out.append((a, "num", v))
        elif k == "call":
            out.append((a, "call", v))
    return out


def _src_feature_index(sf):
    """{(kind, value): [line]} over a source function's lines (whole file lookups go through the tree)"""
    return sf  # SourceFile already exposes .lines; helpers below read it directly


def _file_index(sfile):
    """a per-file inverted index over its features (built once, cached on the file): exact (kind, value) ->
    [lines], and the string / assert-text values with their lines for the substring-tolerant str queries"""
    idx = getattr(sfile, "_feat_index", None)
    if idx is None:
        idx = {"exact": {}, "strings": []}
        for ln, feats in sfile.lines.items():
            for k, v in feats:
                idx["exact"].setdefault((k, v), []).append(ln)
                if k in ("str", "text") and isinstance(v, str):
                    idx["strings"].append((v, ln, k))
        sfile._feat_index = idx
    return idx


def _file_lines_for(sfile, kind, value):
    """the lines of a file whose features match (kind, value): same semantics as scanning its lines -- for a
    str, an equal or (with both >= 6 chars) containing source string, or an assert text that contains it;
    num / call match exactly. The scan ran per feature per source function, which crawled on the kernelcache
    (hundreds of features x hundreds of functions per file); here each file is read once"""
    if kind == "str" and isinstance(value, str):
        cache = sfile.__dict__.setdefault("_str_queries", {})
        if value not in cache:
            out = set(_file_index(sfile)["exact"].get(("str", value), []))
            for v, ln, k in _file_index(sfile)["strings"]:
                if k == "str" and _feat_eq("str", v, value) or k == "text" and value and value in v:
                    out.add(ln)
            cache[value] = sorted(out)
        return cache[value]
    return _file_index(sfile)["exact"].get((kind, value), [])


def _source_lines_for(tree, sfile, sfunc, kind, value):
    """the lines of a source function that carry a feature equal to value"""
    return [ln for ln in _file_lines_for(sfile, kind, value) if sfunc.first <= ln <= sfunc.last]


def _feat_eq(kind, a, b):
    if kind == "num":
        return a == b
    if kind == "str":
        return a == b or (a and b and (a in b or b in a) and min(len(a), len(b)) >= 6)
    return a == b


RARE_NUM_FILES = 4     # a constant in at most this many tree files counts as evidence for the function choice


def _anchors_in(sf, sfunc, rare, fl_hits, index=None):
    """the anchors a binary function's features give inside one source function, and their score. A constant
    found in many tree files (small ints, common masks) still pins a line inside the chosen function but hardly
    counts for the choice: on the kernelcache const-only picks were wrong (bncpp-36)"""
    anchors, score, strong = [], 0.0, False
    for sa, line in fl_hits:
        if sfunc.first <= line <= sfunc.last:
            anchors.append((sa, line, "file-line"))
            score += 3.0
            strong = True
    for a, k, v in rare:
        lines = _source_lines_for(None, sf, sfunc, k, v)
        if len(lines) == 1:
            anchors.append((a, lines[0], {"str": "string", "num": "const", "call": "call"}[k]))
            if k == "num":
                score += 0.7 if index is not None and index.num_files(v) <= RARE_NUM_FILES else 0.05
            else:
                score += {"str": 1.0, "call": 0.5}[k]
                strong = strong or k == "str"
        elif lines:
            score += 0.1
    return anchors, score, strong


INLINED_STATIC_SITES = 2     # LLVM inlines a static with one or two call sites (bncpp-75: 2 beat 1 held out)
_TEXT_REFS = {}     # (path, name) -> the name is used other than as a call


def inlined_static(sf, sfunc):
    """a static function the compiler must have inlined (bncpp-75: thread_call_setup_with_options, brecover_data
    had no binary function): file-local, at most INLINED_STATIC_SITES call sites in its file and its address
    never taken (every mention of the name is followed by '(' -- a call, a prototype, 'x()' in a comment)"""
    if not sfunc.static:
        return False
    sites = sum(1 for c in sf.functions if c is not sfunc
                for _, k, v in sf.features(c) if k == "call" and v == sfunc.name)
    if not 0 < sites <= INLINED_STATIC_SITES:
        return False
    key = (sf.path, sfunc.name)
    if key not in _TEXT_REFS:
        try:
            with open(sf.path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        _TEXT_REFS[key] = bool(re.search(r"\b%s\b(?!\s*\()" % re.escape(sfunc.name), text))
    return not _TEXT_REFS[key]


def match_function(bf, tree, want_file=None, index=None, taken=None):
    """pick the source function for a binary function; returns (SourceFile, SourceFunction, anchors) or None.
    anchors: [(addr, line, kind)] with kind file-line / string / const / call. index: a FileIndex over the tree
    (pass one when matching many functions -- without it every call builds its own). A pick needs a string or
    file-line anchor, or a score of rare constants worth two strings. taken: {SourceFunction} of source
    functions another binary function already is (by name); a pick that is taken, declared inline or an
    inlined_static is lifted to the caller that inlined it (lift_inlined)"""
    feats = bf["features"]
    fls = _file_line_anchors(feats)
    index = index or FileIndex(tree)
    # 1. a file:line anchor decides the file and gives a line inside the function
    cand_files = {}
    for sa, fn, line in fls:
        for p in tree.by_suffix(fn):
            cand_files.setdefault(p, []).append((sa, line))
    if not cand_files and want_file:
        for p in tree.by_suffix(want_file):
            cand_files.setdefault(p, [])
    # 2. score source functions: shared rare features + any file-line hits inside them
    rare = _rare(feats)
    best = None
    for p, fl_hits in (cand_files.items() if cand_files else [(p, []) for p in index.files(rare)]):
        sf = tree.file(p)
        for sfunc in sf.functions:
            anchors, score, strong = _anchors_in(sf, sfunc, rare, fl_hits, index)
            if anchors and (strong or score >= 2.0) and (best is None or score > best[0]):
                best = (score, sf, sfunc, anchors)
    if best is None:
        return None
    sf, sfunc, anchors = best[1], best[2], best[3]
    if sfunc.inline or taken and sfunc in taken or inlined_static(sf, sfunc):
        lifted = lift_inlined(sf, sfunc, anchors, rare, index, taken)
        if lifted is None:
            return None
        sfunc, anchors = lifted
    return sf, sfunc, _dedupe_anchors(anchors)


def lift_inlined(sf, sfunc, anchors, rare, index=None, taken=None, depth=2):
    """the caller a binary function really is when its anchors point into an inlined callee (bncpp-36: file-line
    anchors of xnu's *_inline helpers named the helper, not the function): the same file's functions that call
    it, scored by their own anchors; the callee's anchors move to the call line (the code is the callee's, inlined
    there). An inline caller lifts once more (depth). None when no caller or a tie"""
    best, tie = None, False
    for c in sf.functions:
        if c is sfunc:
            continue
        sites = [ln for ln, k, v in sf.features(c) if k == "call" and v == sfunc.name]
        if not sites:
            continue
        own, score, _ = _anchors_in(sf, c, rare, [], index)
        moved = [(a, sites[0], k) for a, _, k in anchors]
        cand = (score, c, own + moved)
        if (c.inline or inlined_static(sf, c)) and depth > 1:
            up = lift_inlined(sf, c, own + moved, rare, index, taken, depth - 1)
            if up is None:
                continue
            cand = (score, up[0], up[1])
        if taken and cand[1] in taken:
            continue
        if best is None or cand[0] > best[0]:
            best, tie = cand, False
        elif cand[0] == best[0]:
            tie = True
    if best is None or tie:
        return None
    return best[1], best[2]


class NameIndex:
    """the tree's source functions by qualified and by plain name (bncpp-36: a symbol name is stronger evidence
    than any anchor)"""

    def __init__(self, tree):
        self.by_qual, self.by_plain = {}, {}
        for sf in tree.all():
            for f in sf.functions:
                self.by_qual.setdefault(f.qualname, []).append(f)
                self.by_plain.setdefault(f.name, []).append(f)

    def lookup(self, name):
        """the source functions a binary name can be: the qualified name, else the plain one"""
        return self.by_qual.get(name) or self.by_plain.get(name.split("::")[-1], [])


# -- signatures (bncpp-78): a mangled name fixes the overload; compilation is deterministic, so a candidate whose
# parameter list cannot produce the binary's signature is not the source of that binary function

_PARAM_TOKEN = re.compile(r"\w+|::|&&|\.\.\.|[^\s\w]")
_PARAM_QUALS = {"const", "volatile", "struct", "class", "enum", "union", "typename", "restrict", "__restrict",
                "register", "__unused", "_Nonnull", "_Nullable", "__nonnull", "__nullable"}
_BUILTIN_TYPES = {"void", "char", "short", "int", "long", "unsigned", "signed", "float", "double", "bool",
                  "_Bool", "wchar_t", "__int128"}
_TYPEDEFS = {      # Darwin arm64 integer typedefs -> the words the demangler prints
    "uint8_t": "unsigned char", "int8_t": "signed char", "u_int8_t": "unsigned char", "UInt8": "unsigned char",
    "SInt8": "signed char", "Boolean": "unsigned char", "uint16_t": "unsigned short", "int16_t": "short",
    "u_int16_t": "unsigned short", "UInt16": "unsigned short", "SInt16": "short",
    "uint32_t": "unsigned int", "int32_t": "int", "u_int32_t": "unsigned int", "UInt32": "unsigned int",
    "SInt32": "int", "uint": "unsigned int", "u_int": "unsigned int", "IOOptionBits": "unsigned int",
    "IOReturn": "int", "kern_return_t": "int", "boolean_t": "int", "errno_t": "int",
    "uint64_t": "unsigned long long", "int64_t": "long long", "u_int64_t": "unsigned long long",
    "UInt64": "unsigned long long", "SInt64": "long long", "user_addr_t": "unsigned long long",
    "mach_vm_address_t": "unsigned long long", "mach_vm_size_t": "unsigned long long", "off_t": "long long",
    "size_t": "unsigned long", "ssize_t": "long", "uintptr_t": "unsigned long", "intptr_t": "long",
    "vm_size_t": "unsigned long", "vm_offset_t": "unsigned long", "vm_address_t": "unsigned long",
    "IOByteCount": "unsigned long", "IOVirtualAddress": "unsigned long", "AbsoluteTime": "unsigned long long",
}


def _split_top(s, sep=","):
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _param_key(p):
    """(type words, pointer depth, reference) of one parameter as written or demangled; the parameter name and
    a default argument are dropped. None for what this cannot read (function pointers)"""
    toks = _PARAM_TOKEN.findall(_split_top(p, "=")[0])
    if "(" in toks:
        return None
    array = "[" in toks      # 'char buf[16]': an array parameter is a pointer
    if array:
        toks = toks[:toks.index("[")]
    toks = [t for t in toks if t not in _PARAM_QUALS]
    # the name: a trailing identifier after a type (an identifier, '*', '&', '>')
    if len(toks) >= 2 and re.match(r"\w+$", toks[-1]) and toks[-1] not in _BUILTIN_TYPES \
            and (re.match(r"\w+$", toks[-2]) or toks[-2] in ("*", "&", "&&", ">")):
        toks = toks[:-1]
    if array:
        toks.append("*")
    words = []
    for i, t in enumerate(toks):
        if re.match(r"\w+$", t) and not (i + 1 < len(toks) and toks[i + 1] == "::"):
            words.extend(_TYPEDEFS.get(t, t).split())
        elif t == "...":
            words.append(t)
    return tuple(words), toks.count("*"), "&" in toks or "&&" in toks


def param_keys(params):
    """[_param_key] of a parameter list ('' and 'void' are none); None when the list is unknown"""
    if params is None:
        return None
    params = params.strip()
    if params in ("", "void"):
        return []
    return [_param_key(p) for p in _split_top(params)]


def _sig_score(bin_keys, src_keys):
    """how well a source parameter list fits the binary's demangled one: None when the arity differs (a default
    argument does not make a second binary function), else per parameter 2 for the same type words and 1 for
    the same pointer / reference shape"""
    if len(bin_keys) != len(src_keys):
        return None
    score = 0
    for b, s in zip(bin_keys, src_keys):
        if b is None or s is None:
            continue
        if _incompatible(b, s):
            return None
        score += 2 * (b[0] == s[0]) + (b[1:] == s[1:])
    return score


def _incompatible(b, s):
    """two parameter keys no typedef can reconcile: pointers to two different named types (OSString* vs
    OSSymbol*, char* vs OSSymbol*: the real overload is elsewhere, e.g. inline in a header) unless one of them
    looks like a typedef (_t, the table), a reference against a non-reference, or a plain integer against a
    pointer"""
    if b[2] != s[2] and b[0] and s[0]:
        return True
    if b[1] == s[1] >= 1 and len(b[0]) == len(s[0]) == 1 and b[0] != s[0] \
            and not any(w.endswith("_t") or w in _TYPEDEFS for w in b[0] + s[0]):
        return True
    for x, y in ((b, s), (s, b)):
        if x[1] == 0 and not x[2] and x[0] and set(x[0]) <= _BUILTIN_TYPES and y[1] >= 1:
            return True
    return False


def match_named(bf, name, names, tree, index=None):
    """the source function of a binary function with a known name: (SourceFile, SourceFunction, anchors) or
    None. Several candidates (overloads, a static function in several files, #if variants): bf["sig"] (the
    demangled parameter list, if any) keeps those that fit it best, then the anchors decide; a tie stays
    unmatched"""
    cands = names.lookup(name)
    if len(cands) > 1 and bf.get("sig") is not None:
        bk = param_keys(bf["sig"])
        fits = [(_sig_score(bk, param_keys(f.params)), f) for f in cands if f.params is not None]
        fits = [(s, f) for s, f in fits if s is not None]
        if fits:
            top = max(s for s, _ in fits)
            cands = [f for s, f in fits if s == top]
    if not cands:
        return None
    feats = bf["features"]
    rare = _rare(feats)
    fls = _file_line_anchors(feats)
    scored = []
    for sfunc in cands:
        sf = tree.file(sfunc.file)
        hits = [(sa, line) for sa, fn, line in fls if sf.path in tree.by_suffix(fn)]
        anchors, score, _ = _anchors_in(sf, sfunc, rare, hits, index)
        scored.append((score, sf, sfunc, anchors))
    scored.sort(key=lambda x: -x[0])
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None
    return scored[0][1], scored[0][2], _dedupe_anchors(scored[0][3])


# -- call-graph propagation (bncpp-36 point 2): a matched pair's calls name its unknown callees

def _src_calls(sf, sfunc, defined):
    """the plain names a source function calls, in line order, restricted to functions the tree defines"""
    return [v for _, k, v in sf.features(sfunc) if k == "call" and v in defined]


def _bin_calls(bf):
    """the calls of a binary function, in feature (structured HLIL) order: (target, None) for a direct call,
    (None, name) for a named one without a known target (an import, a builtin)"""
    out = []
    for _, k, v in bf["features"]:
        if k == "bl" and v is not None:
            out.append((v, None))
        elif k == "call" and (not out or out[-1] != (None, v)):
            out.append((None, v))
    return out


def align_calls(targets, names, known, taken, cap=400):
    """a monotone alignment (max-weight common subsequence) of a binary function's call targets against its
    source function's call names: a known target pairs only with its own name (3), an unknown one with any name
    not known elsewhere (1). targets: [(target, name)] (_bin_calls). Returns [(target, name, tight)] for the unknown
    targets; tight = the pair is the
    only one between two known pairs (or the sequence ends) on both sides"""
    b = [(t, name or known.get(t)) for t, name in targets]
    sset = set(names)
    b = [(t, n) for t, n in b if n is None or n in sset]   # a known callee the source does not call: inlined away
    if not b or not names or len(b) > cap or len(names) > cap:
        return []
    n, m = len(b), len(names)
    NEG = -1
    w = [[0] * m for _ in range(n)]
    for i, (t, kn) in enumerate(b):
        for j, s in enumerate(names):
            w[i][j] = 3 if kn == s else (1 if kn is None and s not in taken else NEG)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, nxt, wi = dp[i], dp[i + 1], w[i]
        for j in range(m - 1, -1, -1):
            best = nxt[j] if nxt[j] > row[j + 1] else row[j + 1]
            if wi[j] > 0 and nxt[j + 1] + wi[j] > best:
                best = nxt[j + 1] + wi[j]
            row[j] = best
    pairs, i, j = [], 0, 0
    while i < n and j < m:
        if w[i][j] > 0 and dp[i][j] == dp[i + 1][j + 1] + w[i][j]:
            pairs.append((i, j))
            i, j = i + 1, j + 1
        elif dp[i][j] == dp[i + 1][j]:
            i += 1
        else:
            j += 1
    out = []
    fixed = [(-1, -1)] + [(i, j) for i, j in pairs if b[i][1] is not None] + [(n, m)]
    for i, j in pairs:
        if b[i][1] is not None or b[i][0] is None:
            continue
        prev = max(f for f in fixed if f[0] < i)
        nxt = min(f for f in fixed if f[0] > i)
        out.append((b[i][0], names[j], nxt[0] - prev[0] == 2 and nxt[1] - prev[1] == 2))
    return out


def propagate(bin_funcs, pairs, names, tree, rounds=20, min_votes=2):
    """name the unknown callees of matched pairs from their source calls, until nothing changes.
    bin_funcs: {start: bf}; pairs: {start: (SourceFile, SourceFunction, anchors)} (the seeds -- named or
    anchored), extended in place. A target is accepted with min_votes agreeing votes and twice the runner-up,
    or one tight vote (the only call between two known ones on both sides) without a rival. Returns
    {start: (round, votes)} of the propagated pairs"""
    defined = set(names.by_plain)
    known = {a: p[1].name for a, p in pairs.items()}
    calls = {}
    out = {}
    for rnd in range(1, rounds + 1):
        votes = {}
        taken = set(known.values())
        for a, (sf, sfunc, _) in pairs.items():
            bf = bin_funcs.get(a)
            if bf is None:
                continue
            key = sfunc
            if key not in calls:
                calls[key] = _src_calls(sf, sfunc, defined)
            for t, name, tight in align_calls(_bin_calls(bf), calls[key], known, taken):
                if t in known or t not in bin_funcs:
                    continue
                v = votes.setdefault(t, {})
                c = v.setdefault(name, [0, 0])
                c[0] += 1
                c[1] += tight
        added = 0
        for t, v in votes.items():
            ranked = sorted(v.items(), key=lambda x: -x[1][0])
            (name, (nv, nt)), rival = ranked[0], (ranked[1][1][0] if len(ranked) > 1 else 0)
            if not (nv >= min_votes and nv >= 2 * rival or nt >= 1 and rival == 0):
                continue
            if name in known.values():
                continue
            res = match_named(bin_funcs[t], name, names, tree)
            if res is None:
                continue
            pairs[t] = res
            known[t] = name
            out[t] = (rnd, nv)
            added += 1
        if not added:
            break
    return out


# -- link order (bncpp-79): the linker keeps an object file's functions together and mostly in definition order

ORDER_MIN_SCORE = 0.5    # an anchor score that places a function inside a bracket (a string, a rare const, a call)
ORDER_MAX_GAP = 8        # a bracket's rest is assigned by position only when this short and the counts equal


def _order_align(gap, cands, sf, rare_of, fls_of, index):
    """a monotone alignment of a bracket's binary functions against its candidate source functions, by anchor
    score (>= ORDER_MIN_SCORE); then every stretch between two placed pairs (or the bracket's ends) whose counts
    are equal and at most ORDER_MAX_GAP is filled by position. Returns [(bf index, cand index, anchors, how)]"""
    n, m = len(gap), len(cands)
    w = [[None] * m for _ in range(n)]
    for i, bf in enumerate(gap):
        rare = rare_of(bf)
        hits = fls_of(bf)
        for j, c in enumerate(cands):
            anchors, score, _ = _anchors_in(sf, c, rare, hits, index)
            if anchors and score >= ORDER_MIN_SCORE:
                w[i][j] = (score, anchors)
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            best = max(dp[i + 1][j], dp[i][j + 1])
            if w[i][j] is not None:
                best = max(best, dp[i + 1][j + 1] + w[i][j][0])
            dp[i][j] = best
    placed, i, j = [], 0, 0
    while i < n and j < m:
        if w[i][j] is not None and dp[i][j] == dp[i + 1][j + 1] + w[i][j][0]:
            placed.append((i, j, w[i][j][1], "anchors"))
            i, j = i + 1, j + 1
        elif dp[i][j] == dp[i + 1][j]:
            i += 1
        else:
            j += 1
    out = list(placed)
    bounds = [(-1, -1)] + [(i, j) for i, j, _, _ in placed] + [(n, m)]
    for (i0, j0), (i1, j1) in zip(bounds, bounds[1:]):
        k = i1 - i0 - 1
        # a macro invocation's functions share one line and are emitted in an order of their own: never by position
        if 0 < k <= ORDER_MAX_GAP and j1 - j0 - 1 == k and not any(c.macro for c in cands[j0 + 1:j1]):
            out.extend((i0 + d, j0 + d, [], "position") for d in range(1, k + 1))
    return out


def link_order(bin_funcs, pairs, tree, index=None, rounds=10):
    """name unmatched binary functions from their matched neighbours: between two consecutive matched functions
    (by address) of one source file in definition order, the functions in between can only be that file's
    untaken source functions defined between the two that are not inline / inlined_static (_order_align places them). bin_funcs:
    {start: bf}; pairs extended in place, to a fixpoint. Returns {start: (round, how)}"""
    order = sorted(bin_funcs)
    taken = {sfunc for _, sfunc, _ in pairs.values()}
    defs = {}
    rare_cache, fl_cache = {}, {}

    def rare_of(bf):
        if bf["start"] not in rare_cache:
            rare_cache[bf["start"]] = _rare(bf["features"])
        return rare_cache[bf["start"]]

    def fls_of_for(path):
        def fls_of(bf):
            if bf["start"] not in fl_cache:
                fl_cache[bf["start"]] = _file_line_anchors(bf["features"])
            return [(sa, line) for sa, fn, line in fl_cache[bf["start"]] if path in tree.by_suffix(fn)]
        return fls_of

    def def_index(sf):
        if sf.path not in defs:
            fs = sorted(sf.functions, key=lambda f: f.first)
            defs[sf.path] = (fs, {f: k for k, f in enumerate(fs)})
        return defs[sf.path]

    out = {}
    for rnd in range(1, rounds + 1):
        added = 0
        matched = [a for a in order if a in pairs]
        pos = {a: k for k, a in enumerate(order)}
        for a, b in zip(matched, matched[1:]):
            gap = order[pos[a] + 1:pos[b]]
            if not gap:
                continue
            sfa, fa, _ = pairs[a]
            sfb, fb, _ = pairs[b]
            if sfa.path != sfb.path:
                continue
            fs, idx = def_index(sfa)
            ia, ib = idx.get(fa), idx.get(fb)
            if ia is None or ib is None or ib <= ia + 1:
                continue
            cands = [f for f in fs[ia + 1:ib]
                     if not f.inline and not inlined_static(sfa, f) and f not in taken]
            if not cands:
                continue
            gbf = [bin_funcs[g] for g in gap]
            for i, j, anchors, how in _order_align(gbf, cands, sfa, rare_of, fls_of_for(sfa.path), index):
                g, c = gap[i], cands[j]
                pairs[g] = (sfa, c, _dedupe_anchors(anchors))
                taken.add(c)
                out[g] = (rnd, how)
                added += 1
        if not added:
            break
    return out


_WORD = re.compile(r"\w{4,}")


class FileIndex:
    """the files a binary string can anchor in: an inverted index over the tree's str / assert-text features
    (bncpp-36). The direct scan would read every source file per binary function -- 142k functions against a
    1,799-file tree; here the tree is read once (lazily, on the first query), then answered from an exact-text
    index, with a word index (words of >= 4 chars) proposing candidates that a substring check verifies both ways
    (a string can be contained in a source text, or carry one). Per-string cached."""

    def __init__(self, tree):
        self.tree = tree
        self._texts = {}      # path -> [str / text values]
        self._exact = {}      # value -> [paths]
        self._words = {}      # word -> set(paths)
        self._cache = {}      # binary string -> [paths]
        self._nums = {}       # int constant -> number of files carrying it

    def _build(self):
        for p in self.tree.paths:
            sf = self.tree.file(p)
            texts = sorted({v for feats in sf.lines.values() for k, v in feats if k in ("str", "text")})
            self._texts[p] = texts
            for v in {v for feats in sf.lines.values() for k, v in feats if k == "num"}:
                self._nums[v] = self._nums.get(v, 0) + 1
            for t in texts:
                self._exact.setdefault(t, []).append(p)
                for w in set(_WORD.findall(t)):
                    self._words.setdefault(w, set()).add(p)

    def files_with(self, s):
        if not self._texts:
            self._build()
        if s in self._cache:
            return self._cache[s]
        out = list(self._exact.get(s, ()))
        words = set(_WORD.findall(s))
        cand = set()
        for w in words:
            cand.update(self._words.get(w, ()))
        if not words:
            cand.update(self._texts)   # nothing indexable in the query: verify against everything
        for p in cand:
            if p not in out and any(s in t or t in s for t in self._texts[p]):
                out.append(p)
        out.sort()
        self._cache[s] = out
        return out

    def num_files(self, v):
        """in how many tree files a constant appears"""
        if not self._texts:
            self._build()
        return self._nums.get(v, 0)

    def files(self, rare):
        """files that carry at least one of the rare strings (the cheap filter before scoring every function)"""
        out, seen = [], set()
        for a, k, v in rare:
            if k == "str":
                for p in self.files_with(v):
                    if p not in seen:
                        seen.add(p)
                        out.append(p)
        return out


def _dedupe_anchors(anchors):
    """at most one anchor per address (the strongest), sorted by address"""
    order = {"file-line": 3, "string": 2, "call": 1, "const": 0}
    by_addr = {}
    for a, line, kind in anchors:
        if a not in by_addr or order[kind] > order[by_addr[a][1]]:
            by_addr[a] = (line, kind)
    return sorted((a, l, k) for a, (l, k) in by_addr.items())


def rows_for_function(bf, sf, sfunc, anchors):
    """the rows of one matched function: anchors pin their addresses, between consecutive anchors the source range
    between them, the ends extended to the function's address range"""
    rows = []
    path = sf.path
    a = sorted(anchors)
    if not a:
        rows.append(Row(bf["start"], bf["end"], path, sfunc.first, sfunc.last, CONF["function"], "function"))
        return rows
    for i, (addr, line, kind) in enumerate(a):
        start = bf["start"] if i == 0 else a[i - 1][0]
        end = a[i + 1][0] if i + 1 < len(a) else bf["end"]
        # the anchor instruction itself pins its own line exactly; the code just before it (from the previous
        # anchor) covers the lines in between
        if i == 0 and start < addr:
            rows.append(Row(start, addr, path, sfunc.first, line, CONF["between"], "between"))
        rows.append(Row(addr, min(addr + 4, end) if addr < end else end, path, line, line, CONF[kind], kind))
        if addr + 4 < end:
            nxt_line = a[i + 1][1] if i + 1 < len(a) else sfunc.last
            lo, hi = sorted((line, nxt_line))
            rows.append(Row(addr + 4, end, path, lo, hi, CONF["between"], "between"))
    return rows


def build(bin_funcs, tree, binary=None, source=None, index=None):
    """match every binary function and return the LineMap"""
    m = LineMap(binary, source)
    index = index if index is not None else FileIndex(tree)
    for bf in bin_funcs:
        res = match_function(bf, tree, index=index)
        if res is None:
            continue
        sf, sfunc, anchors = res
        m.functions.append(Function(sfunc.qualname, bf["start"], bf["end"], sf.path, sfunc.first, sfunc.last,
                                    CONF["file-line"] if any(k == "file-line" for _, _, k in anchors)
                                    else CONF["string"] if anchors else CONF["function"],
                                    "%d anchors" % len(anchors)))
        for r in rows_for_function(bf, sf, sfunc, anchors):
            m.add(r)
    return m

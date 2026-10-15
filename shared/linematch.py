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


def match_function(bf, tree, want_file=None, index=None):
    """pick the source function for a binary function; returns (SourceFile, SourceFunction, anchors) or None.
    anchors: [(addr, line, kind)] with kind file-line / string / const / call. index: a FileIndex over the tree
    (pass one when matching many functions -- without it every call builds its own)"""
    feats = bf["features"]
    fls = _file_line_anchors(feats)
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
    files_to_try = cand_files or (index or FileIndex(tree)).files(rare)
    for p, fl_hits in (cand_files.items() if cand_files else [(p, []) for p in files_to_try]):
        sf = tree.file(p)
        for sfunc in sf.functions:
            anchors, score = [], 0.0
            for sa, line in fl_hits:
                if sfunc.first <= line <= sfunc.last:
                    anchors.append((sa, line, "file-line"))
                    score += 3.0
            for a, k, v in rare:
                lines = _source_lines_for(tree, sf, sfunc, k, v)
                if len(lines) == 1:
                    anchors.append((a, lines[0], {"str": "string", "num": "const", "call": "call"}[k]))
                    score += {"str": 1.0, "num": 0.7, "call": 0.5}[k]
                elif lines:
                    score += 0.1
            if anchors and (best is None or score > best[0]):
                best = (score, sf, sfunc, anchors)
    if best is None:
        return None
    return best[1], best[2], _dedupe_anchors(best[3])


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

    def _build(self):
        for p in self.tree.paths:
            sf = self.tree.file(p)
            texts = sorted({v for feats in sf.lines.values() for k, v in feats if k in ("str", "text")})
            self._texts[p] = texts
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

# shared with binary-jvm: not yet (new here, bncpp-37); keep language-neutral
"""Line maps: address <-> source line, sloppy (bncpp-36 / -37). The canonical format; .sym (bncpp-39) and dSYM
(bncpp-38) are lossy exports of it, BN shows it through the language view (bncpp-41).

A row maps an address range [start, end) to a source line RANGE first..last of one file (a single line: first ==
last), with a confidence 0..1 and its provenance:
  dwarf         from a real line table (ground truth, tests/ref_dwarf_lines.py)
  file-line     an anchor that carries file and line (assert / panic: __FILE__ string + __LINE__ constant)
  string, const, call      an anchor that matched one source line (or a few: the range covers them)
  between       the code between two anchors: the lines between theirs (optimised code is not in source order)
  function      only the function is known: its whole line range
Optional: alternative candidates [(file, first, last)], the function an inlined row comes from.

Functions: name, address range, source file and line range, confidence, evidence (free text). Pure Python, no
Binary Ninja import. JSON on disk (addresses as hex strings: kernel addresses do not fit a JSON double):
  {"format": "bncpp-linemap", "version": 1, "binary": {...}, "source": {...}, "files": [path],
   "functions": [{...}], "rows": [{"start": "0x..", "end": "0x..", "file": i, "first": n, "last": n,
                                   "conf": c, "src": kind, "alt": [[i, first, last]], "inlined": name}]}
"""
import bisect
import json

FORMAT, VERSION = "bncpp-linemap", 1


class Row:
    __slots__ = ("start", "end", "file", "first", "last", "conf", "src", "alt", "inlined")

    def __init__(self, start, end, file, first, last=None, conf=1.0, src="dwarf", alt=None, inlined=None):
        self.start, self.end, self.file = start, end, file
        self.first = first
        self.last = first if last is None else last
        self.conf, self.src, self.alt, self.inlined = conf, src, list(alt or []), inlined

    def covers(self, line):
        return self.first <= line <= self.last

    def __repr__(self):
        return "<Row %#x-%#x %s:%d%s %.2f %s>" % (self.start, self.end, self.file, self.first,
                                                  "" if self.last == self.first else "-%d" % self.last,
                                                  self.conf, self.src)


class Function:
    __slots__ = ("name", "start", "end", "file", "first", "last", "conf", "evidence")

    def __init__(self, name, start, end, file=None, first=None, last=None, conf=1.0, evidence=""):
        self.name, self.start, self.end = name, start, end
        self.file, self.first, self.last = file, first, last
        self.conf, self.evidence = conf, evidence

    def __repr__(self):
        return "<Function %s %#x-%#x %s:%s-%s>" % (self.name, self.start, self.end, self.file, self.first, self.last)


class LineMap:
    """rows sorted by start, not overlapping (add() cuts what a better row covers); file paths as strings"""

    def __init__(self, binary=None, source=None):
        self.binary = dict(binary or {})   # name, sha256, uuid, arch, base (the address the rows are relative to)
        self.source = dict(source or {})   # name (e.g. xnu-8796.141.3), root
        self.functions = []
        self._rows = []                    # sorted by start
        self._starts = []

    # rows
    def rows(self):
        return list(self._rows)

    def add(self, row):
        """insert; where it overlaps existing rows the one with the higher confidence keeps the addresses (a tie:
        the existing one)"""
        pieces = [(row.start, row.end)]
        for old in self._overlapping(row.start, row.end):
            if old.conf >= row.conf:
                pieces = [p for a, b in pieces for p in ((a, min(b, old.start)), (max(a, old.end), b)) if p[0] < p[1]]
            else:
                self._remove(old)
                for a, b in ((old.start, row.start), (row.end, old.end)):
                    if a < b:
                        self._insert(Row(a, b, old.file, old.first, old.last, old.conf, old.src, old.alt, old.inlined))
        for a, b in pieces:
            self._insert(Row(a, b, row.file, row.first, row.last, row.conf, row.src, row.alt, row.inlined))

    def at(self, addr):
        """the row covering an address, else None"""
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0 and self._rows[i].start <= addr < self._rows[i].end:
            return self._rows[i]
        return None

    def addresses_of(self, file, line):
        """[(start, end, row)] of the rows whose range covers file:line"""
        return [(r.start, r.end, r) for r in self._rows if r.file == file and r.covers(line)]

    def function_at(self, addr):
        return next((f for f in self.functions if f.start <= addr < f.end), None)

    def _overlapping(self, start, end):
        i = max(0, bisect.bisect_right(self._starts, start) - 1)
        out = []
        while i < len(self._rows) and self._rows[i].start < end:
            if self._rows[i].end > start:
                out.append(self._rows[i])
            i += 1
        return out

    def _insert(self, row):
        i = bisect.bisect_left(self._starts, row.start)
        self._rows.insert(i, row)
        self._starts.insert(i, row.start)

    def _remove(self, row):
        i = self._rows.index(row)
        del self._rows[i]
        del self._starts[i]

    # JSON
    def to_json(self):
        files = sorted(set(r.file for r in self._rows) | set(a[0] for r in self._rows for a in r.alt)
                       | set(f.file for f in self.functions if f.file is not None))
        fi = {f: i for i, f in enumerate(files)}
        rows = []
        for r in self._rows:
            d = {"start": "%#x" % r.start, "end": "%#x" % r.end, "file": fi[r.file], "first": r.first, "last": r.last,
                 "conf": round(r.conf, 3), "src": r.src}
            if r.alt:
                d["alt"] = [[fi[f], a, b] for f, a, b in r.alt]
            if r.inlined:
                d["inlined"] = r.inlined
            rows.append(d)
        funcs = [{"name": f.name, "start": "%#x" % f.start, "end": "%#x" % f.end,
                  "file": fi.get(f.file), "first": f.first, "last": f.last, "conf": round(f.conf, 3),
                  "evidence": f.evidence} for f in self.functions]
        return {"format": FORMAT, "version": VERSION, "binary": self.binary, "source": self.source,
                "files": files, "functions": funcs, "rows": rows}

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_json(), fh, indent=0, separators=(",", ":"))
            fh.write("\n")

    @classmethod
    def from_json(cls, d):
        if d.get("format") != FORMAT or d.get("version") != VERSION:
            raise ValueError("not a %s v%d file" % (FORMAT, VERSION))
        m, files = cls(d.get("binary"), d.get("source")), d["files"]
        for f in d["functions"]:
            m.functions.append(Function(f["name"], int(f["start"], 16), int(f["end"], 16),
                                        files[f["file"]] if f.get("file") is not None else None,
                                        f.get("first"), f.get("last"), f.get("conf", 1.0), f.get("evidence", "")))
        for r in d["rows"]:
            m._insert(Row(int(r["start"], 16), int(r["end"], 16), files[r["file"]], r["first"], r["last"],
                          r["conf"], r["src"], [(files[a[0]], a[1], a[2]) for a in r.get("alt", [])],
                          r.get("inlined")))
        return m

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(json.load(fh))


def same_file(a, b):
    """two paths name the same source file: equal, or one is a path suffix of the other (a build path vs a tree)"""
    if a == b:
        return True
    a, b = a.replace("\\", "/").split("/"), b.replace("\\", "/").split("/")
    n = min(len(a), len(b))
    return n > 0 and a[-n:] == b[-n:]


def score(truth, guess, addresses=None):
    """compare a guess with a ground-truth map, per instruction address (addresses: the instruction starts to score;
    default: each truth row's start). Counts: scored, covered (the guess has a row), file (right file), inside
    (true line within the guessed range), exact (range == the true line), width (sum of range widths, of covered
    rows in the right file), per provenance kind: inside / total; functions: truth functions whose start the
    guess puts in a function of the same name or the same source range"""
    out = {"scored": 0, "covered": 0, "file": 0, "inside": 0, "exact": 0, "width": 0, "by_src": {},
           "functions": len(truth.functions), "functions_hit": 0}
    if addresses is None:
        addresses = [r.start for r in truth.rows() if r.first > 0]
    for a in addresses:
        t = truth.at(a)
        if t is None or t.first <= 0:
            continue  # line 0: compiler-made code without a line
        out["scored"] += 1
        g = guess.at(a)
        if g is None:
            continue
        out["covered"] += 1
        k = out["by_src"].setdefault(g.src, [0, 0])
        k[1] += 1
        if not same_file(g.file, t.file):
            continue
        out["file"] += 1
        out["width"] += g.last - g.first + 1
        if g.covers(t.first):
            out["inside"] += 1
            k[0] += 1
            if g.first == g.last:
                out["exact"] += 1
    for tf in truth.functions:
        gf = guess.function_at(tf.start)
        if gf is not None and (gf.name == tf.name or (gf.file is not None and tf.file is not None
                                                       and same_file(gf.file, tf.file) and gf.first is not None
                                                       and tf.first is not None
                                                       and gf.first <= tf.first <= (gf.last or gf.first))):
            out["functions_hit"] += 1
    return out


def format_score(s):
    n = max(s["scored"], 1)
    return ("%d addresses: covered %.0f%%, right file %.0f%%, line inside the range %.0f%%, exact %.0f%%, "
            "mean width %.1f lines; functions %d/%d; by kind: %s" % (
                s["scored"], 100.0 * s["covered"] / n, 100.0 * s["file"] / n, 100.0 * s["inside"] / n,
                100.0 * s["exact"] / n, s["width"] / max(s["file"], 1), s["functions_hit"], s["functions"],
                ", ".join("%s %d/%d" % (k, v[0], v[1]) for k, v in sorted(s["by_src"].items()))))

# shared with binary-jvm/shared/regions.py (synced at binary-jvm d67a36e; group_try_entries is javac-shaped,
# unused here); keep language-neutral and pure Python (no Binary Ninja import: the offline checks use it)
"""Try regions: exception-table entries folded to try statements, and their placement on a block's statements."""


def group_try_entries(table):
    """Exception-table entries [[start, end, handler, type], ...] -> [(start, end, [(handler, type), ...])],
    one entry per Java try statement, sorted by start (outer first on ties).

    javac's try/catch/finally shapes are folded back into one statement:
      * a catch-all handler F (finally) protects the try range, every catch body (a range starting exactly at
        the catch handler) and its own store/rethrow code (a range starting at F); only the ranges before the
        first handler are the try body. Catches with the same first start whose body F covers (or with the
        same range) become the catch clauses of that try: try { } catch (T e) { } finally { }
      * a range split by inlined finally code (return inside try) is one region from the first start to
        the last end
      * typed handlers sharing the same ranges are the clauses of one try; a catch-all without a range before
        its own code (javac's self-covering entry) is not a try of its own.
      * one handler pc with several exception-table types is javac's catch (A | B e): the clause keeps
        them all (a tuple) and prints `catch (A | B e)` (jvm-84).
    """
    by_handler = {}  # handler pc -> ([catch types...], [(start, end), ...])
    order = []
    for start, end, handler, ctype in table:
        if handler not in by_handler:
            by_handler[handler] = [[], []]
            order.append(handler)
        if ctype and ctype not in by_handler[handler][0]:  # multi-catch: several types, one pc
            by_handler[handler][0].append(ctype)
        by_handler[handler][1].append((start, end))

    def clause_type(h):
        types = by_handler[h][0]
        return tuple(types) if len(types) > 1 else (types[0] if types else "")

    groups = []
    used = set()
    for f in order:
        types, ranges = by_handler[f]
        if any(types):  # a typed handler; catch-alls ("" only) are the finally candidates
            continue
        used.add(f)
        prim = [r for r in ranges if r[0] < f]
        if not prim:
            continue
        s0 = min(r[0] for r in prim)
        f_starts = {r[0] for r in ranges}
        catches = []
        for h in order:
            t, hr = by_handler[h]
            if not t or h in used or h > f or min(r[0] for r in hr) != s0:
                continue
            if h in f_starts or sorted(hr) == sorted(prim):
                catches.append(h)
        limit = min(catches + [f])
        prim = [r for r in prim if r[0] < limit] or prim
        used.update(catches)
        groups.append((s0, max(r[1] for r in prim), [(h, clause_type(h)) for h in catches] + [(f, "")]))
    rest = {}
    for h in order:
        if h in used:
            continue
        t, hr = by_handler[h]
        rest.setdefault(tuple(sorted(hr)), []).append((h, clause_type(h)))
    for hr, handlers in rest.items():
        groups.append((min(r[0] for r in hr), max(r[1] for r in hr), handlers))
    groups.sort(key=lambda g: (g[0], -g[1]))
    return groups


def try_runs(stmt_pcs, groups, active=()):
    """Place try ranges on one block's statements.

    stmt_pcs: per statement the list of pcs it covers (its own pc first), or None if unknown/neutral
    (labels, exception checks): those join a run between two inside statements but never start or end one.
    groups: from group_try_entries. Returns [(first, last, group)] for maximal runs of consecutive
    statements whose pcs all lie in the group's range and none of which is a handler of that group,
    largest ranges first, non-overlapping; groups in `active` (already open in an enclosing block) are skipped.
    """
    runs = []
    taken = set()
    for g in sorted(groups, key=lambda g: g[0] - g[1]):  # widest range first
        start, end, handlers = g
        if (start, end) in active:
            continue
        handler_pcs = {h for h, _ in handlers}
        inside = []  # True / False / None (neutral)
        for pcs in stmt_pcs:
            inside.append(None if not pcs else
                          all(start <= pc < end for pc in pcs) and pcs[0] not in handler_pcs)
        i = 0
        while i < len(inside):
            if inside[i] is not True:
                i += 1
                continue
            j = i
            k = i + 1
            while k < len(inside) and inside[k] is not False:
                if inside[k]:
                    j = k
                k += 1
            if not any(k in taken for k in range(i, j+1)):
                runs.append((i, j, g))
                taken.update(range(i, j+1))
            break  # one run per group: a try range is one region
        # (a second run of the same group would duplicate the catch clause)
    return sorted(runs, key=lambda r: r[0])

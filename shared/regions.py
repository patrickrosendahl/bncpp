# shared with binary-jvm/pseudo_java.py (try_runs; synced at e427b7e); keep language-neutral
"""Try regions on a block's statements."""


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

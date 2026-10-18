# shared with binary-jvm: not yet (new here, bncpp-22); keep language-neutral
"""The call graph of a view, from BN's analysis data (call sites and their resolved callees -- no IL is built):
~2 s per 2,000 functions on SynthV (edges_async: in a cancellable background task). Cached in the per-binary
cache (shared/bncache.py), section "callgraph".

  edges      [(caller start, call-site address, callee address or None)] -- None: BN could not resolve the
             target (indirect / virtual calls, unresolved jumps), one row per such site
  callers / callees      {address: [(site, address)]} built from the edges

Addresses only: names change (renames), addresses do not. A function created or deleted since the cache was
written is missing or stale -- delete the cache file to rebuild.
A function whose analysis BN skipped (too large / too slow) lists no call sites; its edges are read from its basic
blocks' instructions instead: direct calls, and jumps to another function's start (tail calls) -- v2.
"""
VERSION = 2


def build(bv, limit=None, task=None):
    """task: a BackgroundTaskThread to report progress to and to stop on cancel (returns None then)"""
    edges = []
    funcs = list(bv.functions)[:limit]
    for i, f in enumerate(funcs):
        if task is not None:
            if task.cancelled:
                return None
            if i % 1000 == 0:
                task.progress = "call graph: %d / %d functions" % (i, len(funcs))
        if f.analysis_skipped:
            edges += _scan(bv, f)
            continue
        for cs in f.call_sites:
            targets = bv.get_callees(cs.address, f)
            if targets:
                edges += [(f.start, cs.address, t) for t in targets]
            else:
                edges.append((f.start, cs.address, None))
    return edges


def _scan(bv, f):
    """the edges of a function BN skipped, from its blocks' instruction info (no IL is built)"""
    from binaryninja import BranchType
    out = []
    for bb in f.basic_blocks:
        a = bb.start
        while a < bb.end:
            info = bv.arch.get_instruction_info(bv.read(a, bv.arch.max_instr_length), a)
            if info is None or not info.length:
                break
            for b in info.branches:
                if b.type == BranchType.CallDestination or (
                        b.type == BranchType.UnconditionalBranch and b.target != f.start and
                        bv.get_function_at(b.target) is not None):
                    out.append((f.start, a, b.target))
            a += info.length
    return out


def edges(bv, cache):
    """the call graph from the cache, built (and stored) when missing"""
    s = cache.get("callgraph", VERSION)
    if s is None:
        s = {"edges": build(bv)}
        cache.put("callgraph", VERSION, s)
    return [tuple(e) for e in s["edges"]]


def edges_async(bv, cache, done=None):
    """as edges(), in a cancellable background task: done(edges) once there (at once from the cache); the
    started task, or None when the cache had it"""
    s = cache.get("callgraph", VERSION)
    if s is not None:
        if done is not None:
            done([tuple(e) for e in s["edges"]])
        return None
    from binaryninja import BackgroundTaskThread

    class _Task(BackgroundTaskThread):
        def run(self):
            e = build(bv, task=self)
            if e is None:
                return
            cache.put("callgraph", VERSION, {"edges": e})
            if done is not None:
                done(e)

    task = _Task("call graph", True)
    task.start()
    return task


def index(edges):
    """(callers, callees): {callee: [(site, caller)]}, {caller: [(site, callee or None)]}"""
    callers, callees = {}, {}
    for caller, site, callee in edges:
        callees.setdefault(caller, []).append((site, callee))
        if callee is not None:
            callers.setdefault(callee, []).append((site, caller))
    return callers, callees

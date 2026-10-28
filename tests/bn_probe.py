# A throwaway view for ad-hoc probe scripts ($B/bn, after tests/bn_engine.py setup), closed safely (bncpp-168):
#   import importlib.util as _u
#   _s = _u.spec_from_file_location("bn_probe", "/Users/patrick/dev/binary-cpp/tests/bn_probe.py")
#   _probe = _u.module_from_spec(_s); _s.loader.exec_module(_probe)
#   with _probe.probe_view(path, pads=True) as v:   # pads: cpp/landing_pads.recover (serial)
#       f = v.get_function_at(0x400774)
#       print(f.mlil.ssa_form)
# No Function of the view may outlive its close -- freed later (the namespace at the job's end, on a worker thread,
# or from an exception's traceback) BN crashed in BNFreeFunction / 'Function Destruction' (bncpp-102, BN report
# bncpp-158). On leaving the block, normally or by an exception:
#   - names the block bound (or rebound) to API objects -- Functions, IL, variables, containers of them -- are set
#     to None in the caller's namespace (module or function frame; names bound before the block stay);
#   - an exception is kept as text, its traceback's frames are cleared and its args dropped;
#   - gc.collect(), then the view closes; the exception comes out as a RuntimeError carrying the original text.
# The same order as tests/bn_dump.py's per-binary finally (834ccc9).
import enum, gc, importlib, sys, traceback, types

import binaryninja as _bn

_PLAIN = (types.ModuleType, type, enum.Enum, str, bytes, int, float, bool, type(None))


def _holds_api(v, depth=2):
    """v is an object of the binaryninja API, or a list / tuple / set / dict holding one (depth levels down)"""
    if isinstance(v, _PLAIN):
        return False
    if (type(v).__module__ or "").startswith("binaryninja"):
        return True
    if depth and isinstance(v, dict):
        return any(_holds_api(x, depth - 1) for kv in v.items() for x in kv)
    if depth and isinstance(v, (list, tuple, set, frozenset)):
        return any(_holds_api(x, depth - 1) for x in v)
    return False


class probe_view:
    """with probe_view(path, pads=False) as bv: ... -- binaryninja.load(path, **load_kw), closed safely"""

    def __init__(self, path, pads=False, **load_kw):
        self.path, self.pads, self.load_kw = path, pads, load_kw
        self.bv = self._frame = None
        self.dropped = []

    def __enter__(self):
        self._frame = sys._getframe(1)
        self._before = {k: id(v) for k, v in self._frame.f_locals.items()}
        self.bv = _bn.load(self.path, **self.load_kw)
        if self.pads:
            dev = getattr(_bn, "_cpp_dev", None)
            if dev is None or "pkgname" not in dev:
                self.__exit__(None, None, None)
                raise RuntimeError("pads=True: run tests/bn_dev_load.py first")
            try:
                importlib.import_module(dev["pkgname"] + ".cpp.landing_pads").recover(self.bv, serial=True)
            except BaseException:
                self.__exit__(*sys.exc_info())  # closes the view, raises the RuntimeError
        return self.bv

    def __exit__(self, et, e, tb):
        text = None
        if e is not None:
            text = "".join(traceback.format_exception(et, e, tb))
            traceback.clear_frames(tb)  # the frames below the block: their locals hold the view's objects
            e.__traceback__, e.args = None, ()
            e = tb = None
        ns = self._frame.f_locals
        self.dropped = sorted(k for k, v in list(ns.items()) if self._before.get(k) != id(v) and _holds_api(v))
        for k in self.dropped:
            ns[k] = None  # not del: a function frame's locals proxy can't delete (PEP 667)
        ns = self._frame = None
        bv, self.bv = self.bv, None
        gc.collect()
        bv.file.close()
        if text is not None:
            raise RuntimeError("probe_view(%s):\n%s" % (self.path, text)) from None
        return False

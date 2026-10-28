"""What did BN's own RTTI analysis (librtti: analysis.rtti.rttiAnalysis / vftAnalysis) produce in a view?

Read-only. Counts BN's vtable symbols and VTable types, then prints the classes whose names contain
any of the script arguments. Run on a cached view:
  BNDB=DB $B/bn --timeout 60 tests/bn_rtti_probe.py lazyloader renderblock
"""
import importlib.util as _eu, os as _eos  # the engine first, binaryninja after it (tests/bn_engine.py, bncpp-177)
_es = _eu.spec_from_file_location("bn_engine", _eos.path.join(globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp"),
                                                              "tests/bn_engine.py"))
_e = _eu.module_from_spec(_es)
_es.loader.exec_module(_e)
_e.setup(globals(), need_bv=True)
import collections, sys, time
from binaryninja import Settings

t0 = time.time()
names = sys.argv[1:]
for key in ("analysis.rtti.rttiAnalysis", "analysis.rtti.vftAnalysis"):
    try:
        print("%s = %s" % (key, Settings().get_bool(key, bv)))
    except Exception as e:
        print("%s: %s" % (key, e))

kinds = collections.Counter()
vt_syms = []
for s in bv.get_symbols():
    n = s.full_name
    if n.startswith("vtable_for_") or n.startswith("_vtable_for_"):
        vt_syms.append(s)
    elif n.startswith("typeinfo_for_") or n.startswith("_typeinfo_for_"):
        kinds["typeinfo symbols"] += 1
    elif n.startswith("typeinfo_name_for_"):
        kinds["typeinfo name symbols"] += 1
kinds["vtable symbols"] = len(vt_syms)
vt_types = [n for n in bv.types.keys() if str(n).endswith("::VTable")]
kinds["::VTable types"] = len(vt_types)
for k, v in sorted(kinds.items()):
    print("%-24s %d" % (k, v))
print("functions: %d" % len(bv.functions))

for want in names:
    for s in vt_syms:
        if want in s.full_name:
            dv = bv.get_data_var_at(s.address)
            print("\n%s  @ %#x  type %s" % (s.full_name, s.address, dv.type if dv else None))
            if dv is not None and dv.type is not None and dv.type.type_class.name == "StructureTypeClass":
                for mbr in list(dv.type.members)[:12]:
                    ptr = bv.read_pointer(s.address + mbr.offset)
                    f = bv.get_function_at(ptr)
                    print("   +%#04x %-28s -> %#x %s" % (mbr.offset, mbr.name, ptr, f.name if f else ""))
print("\n(%.1f s)" % (time.time() - t0))

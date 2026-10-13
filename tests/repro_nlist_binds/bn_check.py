"""Binary Ninja check for the repro: what became of the import binds and of the RTTI analysis?

Headless:  python3 bn_check.py classic classic-renamed chained chained-renamed
In the UI: open one of the files and run this script (Scripting console: exec(open(".../bn_check.py").read()))
"""
import sys

IMPORTS = ["__ZTVN10__cxxabiv117__class_type_infoE", "__ZTVN10__cxxabiv120__si_class_type_infoE",
           "__ZTVN10__cxxabiv121__vmi_class_type_infoE", "__ZdlPv", "__Znwm", "___cxa_bad_typeid", "___dynamic_cast"]
TYPEINFOS = [("__ZTI5Shape", "Shape"), ("__ZTI6Circle", "Circle"), ("__ZTI11NamedCircle", "NamedCircle"),
             ("__ZTI7Diamond", "Diamond"), ("__ZTI3BoxIiE", "Box<int32_t>")]


def check(bv):
    print("== %s (%s)" % (bv.file.original_filename, bv.view_type))
    ext = {s.raw_name for s in bv.get_symbols()
           if s.type.name in ("ExternalSymbol", "ImportedDataSymbol", "ImportAddressSymbol", "ImportedFunctionSymbol")}
    print("  import symbols named as in the dyld info: %d of %d" % (sum(n in ext for n in IMPORTS), len(IMPORTS)))
    print("  other import symbols: %s" % sorted(ext - set(IMPORTS) - {"dyld_stub_binder", "_printf"}))
    # word 0 of every typeinfo object is a bind to __cxxabiv1::__*_type_info's vtable + 16
    defined = {s.raw_name: s.address for s in bv.get_symbols() if s.type.name == "DataSymbol"}
    for name, cls in TYPEINFOS:
        # the nlist name, or the one BN's RTTI analysis gave the definition
        a = defined.get(name, defined.get("_typeinfo_for_" + cls))
        if a is None:
            print("  %-20s no symbol" % name)
            continue
        rel = [r.symbol.raw_name if r.symbol else None for r in bv.relocations_at(a)]
        print("  %-20s @ %#x  vptr slot: relocation %s, reads %#x" % (name, a, rel or "NONE", bv.read_pointer(a)))
    vt = [str(n) for n in bv.types.keys() if str(n).endswith("::VTable")]
    print("  ::VTable types from RTTI analysis: %d %s" % (len(vt), sorted(vt)[:4] + (["..."] if len(vt) > 4 else [])))


if "bv" in globals() and globals()["bv"] is not None:
    check(globals()["bv"])
else:
    import binaryninja
    for path in sys.argv[1:]:
        with binaryninja.load(path) as view:
            check(view)

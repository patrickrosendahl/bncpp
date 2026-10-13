#!/bin/sh
# bncpp-25: repro of the Binary Ninja Mach-O bug reported to Vector35 (report: wiki references.md attachment).
# Builds the four test binaries (x86_64 macOS executables, Apple clang):
#   classic          classic dyld info (LC_DYLD_INFO_ONLY), untouched                 -> BN fine
#   classic-renamed  same file, undefined LC_SYMTAB names replaced by hash strings    -> BN drops binds
#   chained          chained fixups (LC_DYLD_CHAINED_FIXUPS), untouched               -> BN fine
#   chained-renamed  same file, undefined LC_SYMTAB names replaced by hash strings    -> BN drops binds
# The renamed files are valid: re-signed ad hoc, they run and print the same as the originals (dyld binds by the
# names in the dyld info, never by the nlist names).
set -e
cd "$(dirname "$0")"
CXX="clang++ -arch x86_64 -std=c++17 -O1 -DREPRO_MAIN"
$CXX -mmacosx-version-min=10.11 -Wl,-no_fixup_chains -o classic rtti_repro.cpp
$CXX -Wl,-fixup_chains -o chained rtti_repro.cpp
RENAME="__ZTVN10__cxxabiv117__class_type_infoE __ZTVN10__cxxabiv120__si_class_type_infoE
        __ZTVN10__cxxabiv121__vmi_class_type_infoE __ZdlPv __Znwm ___cxa_bad_typeid ___dynamic_cast"
for f in classic chained; do
    codesign --remove-signature $f
    python3 rename_nlist.py $f $f-renamed $RENAME
    chmod +x $f-renamed
    codesign -f -s - $f && codesign -f -s - $f-renamed
    echo "$f: $(./$f)    $f-renamed: $(./$f-renamed)"
done

"""Rename symbols in a thin Mach-O's string table (LC_SYMTAB) in place, keeping the dyld bind opcodes untouched.

  python3 -I rename_nlist.py IN OUT NAME [NAME ...]
Each NAME is replaced by a same-length hex string (like an obfuscator's hash names).
"""
import hashlib, struct, sys

data = bytearray(open(sys.argv[1], "rb").read())
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
    off += size
for name in sys.argv[3:]:
    old = name.encode() + b"\0"
    pos = data.find(old, stroff, stroff + strsize)
    while pos > stroff and data[pos - 1] != 0:  # must start a string
        pos = data.find(old, pos + 1, stroff + strsize)
    assert pos > 0, name
    new = hashlib.sha256(old).hexdigest().encode()[:len(name)]
    data[pos:pos + len(name)] = new
    print("%s -> %s" % (name, new.decode()))
open(sys.argv[2], "wb").write(data)

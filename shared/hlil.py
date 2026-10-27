# shared with binary-jvm/shared/hlil.py (synced at binary-jvm d67a36e); keep language-neutral
"""HLIL walking: operands, pre-order walk, nested blocks, statements in source order."""
from binaryninja import HighLevelILInstruction, HighLevelILOperation

Op = HighLevelILOperation


def children(instr):
    """the HLIL operands of instr that are expressions (lists flattened)"""
    for o in instr.operands:
        if isinstance(o, HighLevelILInstruction):
            yield o
        elif isinstance(o, list):
            for x in o:
                if isinstance(x, HighLevelILInstruction):
                    yield x


def walk(instr):
    """instr and every expression below it, pre-order"""
    stack = [instr]
    while stack:
        i = stack.pop()
        yield i
        stack.extend(reversed(list(children(i))))


def child_blocks(instr):
    """the outermost HLIL_BLOCKs below instr (not below those)"""
    stack = list(reversed(list(children(instr))))
    while stack:
        i = stack.pop()
        if i.operation == Op.HLIL_BLOCK:
            yield i
            continue
        stack.extend(reversed(list(children(i))))


def stmts_preorder(block):
    """(block, index, statement) for every statement of every block below `block`, in source order"""
    if block.operation != Op.HLIL_BLOCK:
        yield block, 0, block
        for b in child_blocks(block):
            yield from stmts_preorder(b)
        return
    for idx, s in enumerate(block.body):
        yield block, idx, s
        for b in ([s] if s.operation == Op.HLIL_BLOCK else child_blocks(s)):
            yield from stmts_preorder(b)

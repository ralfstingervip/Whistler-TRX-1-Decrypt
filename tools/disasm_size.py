"""Disassemble around the 0x80000 immediates and nearby calls."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

def find_prologue(off: int) -> int:
    # search backward for 55 8B EC within 0x400 bytes, prefer the closest
    # that is not mid-instruction by also accepting CC padding before it
    window = d[max(0, off - 0x600):off]
    base = max(0, off - 0x600)
    best = None
    i = 0
    while True:
        j = window.find(b"\x55\x8B\xEC", i)
        if j < 0:
            break
        best = base + j
        i = j + 1
    return best if best is not None else off - 0x40

for hit in (0xB4D2, 0xB55F):
    start = find_prologue(hit)
    print(f"\n===== hit file {hit:#x} prologue {start:#x} va {0x400000+start:#x} =====")
    code = d[start:start + 0x180]
    for insn in md.disasm(code, 0x400000 + start):
        mark = " <<" if insn.address <= 0x400000 + hit < insn.address + insn.size else ""
        print(f"  {insn.address:#x}: {insn.mnemonic:8} {insn.op_str}{mark}")
        if insn.address > 0x400000 + hit + 0x30:
            break

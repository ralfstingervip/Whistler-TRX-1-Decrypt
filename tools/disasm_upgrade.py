"""Disassemble the function that references 'Upgrading CPU'."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def prologue_before(off: int) -> int:
    window_start = max(0x1000, off - 0x800)
    window = d[window_start:off]
    best = None
    i = 0
    while True:
        j = window.find(b"\x55\x8B\xEC", i)
        if j < 0:
            break
        best = window_start + j
        i = j + 1
    return best if best is not None else off

start = prologue_before(0x2966)
print(f"prologue file {start:#x} va {0x400000+start:#x}")
# print until ret after the string ref, cap 250 insns
code = d[start:start + 0x900]
n = 0
for insn in md.disasm(code, 0x400000 + start):
    mark = ""
    if insn.address == 0x400000 + 0x2966 or abs(insn.address - (0x400000 + 0x2966)) < 8:
        mark = " <<"
    # highlight immediates that point into the image
    print(f"  {insn.address:#x}: {insn.mnemonic:8} {insn.op_str}{mark}")
    n += 1
    if n > 220:
        break
    if insn.mnemonic == "ret" and insn.address > 0x400000 + 0x2A40:
        break

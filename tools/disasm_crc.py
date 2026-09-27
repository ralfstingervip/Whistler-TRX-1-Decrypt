"""Disassemble around the 0x1021 immediate."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)
# find prologue before 0xb801
window = d[0xB000:0xB801]
best = None
i = 0
while True:
    j = window.find(b"\x55\x8B\xEC", i)
    if j < 0:
        break
    best = 0xB000 + j
    i = j + 1
print("prologue", hex(best) if best else None)
start = best or 0xB700
code = d[start:start + 0x200]
for insn in md.disasm(code, 0x400000 + start):
    mark = " <<" if 0x400000 + 0xB7F0 <= insn.address <= 0x400000 + 0xB820 else ""
    print(f"  {insn.address:#x}: {insn.mnemonic:8} {insn.op_str}{mark}")
    if insn.address > 0x400000 + 0xB880:
        break

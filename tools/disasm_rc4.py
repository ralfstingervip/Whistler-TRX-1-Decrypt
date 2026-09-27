"""Linear-sweep the two RC4 functions from their real entry points."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)
for start, stop in ((0x1500, 0x15A3), (0x15B0, 0x1638)):
    print(f"\n===== {start:#x} =====")
    for insn in md.disasm(d[start:stop], 0x400000 + start):
        print(f"  {insn.address:#x}: {insn.bytes.hex():20} {insn.mnemonic:8} {insn.op_str}")

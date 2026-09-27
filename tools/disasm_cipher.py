"""Disassemble the three routines that transform the firmware before send."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

ranges = [
    (0x1490, 0x1800, "probe_401490"),
]
# print each function until ret, starting at known entries
entries = [0x1490, 0x1500, 0x15B0]
# also grab a bit after 0x15b0
end_limit = 0x1900
code = d[0x1490:end_limit]
for insn in md.disasm(code, 0x400000 + 0x1490):
    print(f"  {insn.address:#x}: {insn.mnemonic:8} {insn.op_str}")

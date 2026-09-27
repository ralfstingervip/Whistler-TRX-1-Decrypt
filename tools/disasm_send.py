"""Dump the firmware header globals and the send loop."""
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

off = 0x1A580
print("bytes", d[off:off + 0xA0].hex())
for rel in range(0, 0xA0, 4):
    v = struct.unpack_from("<I", d, off + rel)[0]
    print(f"  file {off+rel:#x} va {0x400000+off+rel:#x} = {v:#010x}")

print("\n===== send region =====")
start = 0x2800
code = d[start:start + 0x500]
for insn in md.disasm(code, 0x400000 + start):
    print(f"  {insn.address:#x}: {insn.mnemonic:8} {insn.op_str}")
    if insn.address > 0x402C80 and insn.mnemonic == "ret":
        break

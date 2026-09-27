"""Find code references to updater strings and to .rdata addresses."""
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
IMAGE = 0x400000
text = d[0x1000:0x1A000]
text_base = 0x1000

needles = [
    b"Upgrading CPU",
    b"This update utility contains version",
    b"Waiting for CPU approval",
    b"UPDATER VERSION",
    b"TRX-1",
    b"no CPU application",
    b"\\\\.\\COM%d",
]
print("--- string sites ---")
sites = []
for n in needles:
    i = d.find(n)
    print(f"  {n!r} file {i:#x} va {IMAGE+i:#x}" if i >= 0 else f"  {n!r} MISSING")
    if i >= 0:
        sites.append((n, i))

print("--- xrefs to those VAs (any alignment in .text) ---")
for n, i in sites:
    va = IMAGE + i
    pat = struct.pack("<I", va)
    idx = 0
    hits = []
    while True:
        j = text.find(pat, idx)
        if j < 0:
            break
        hits.append(text_base + j)
        idx = j + 1
    print(f"  {n[:40]!r} {len(hits)} {[hex(h) for h in hits[:8]]}")

# Count aligned dword pointers from .text into the high-entropy span 0x1C000..0x9A000
print("--- aligned pointers into blob span ---")
lo, hi = IMAGE + 0x1C000, IMAGE + 0x9A800
from collections import Counter
c = Counter()
for off in range(0, len(text) - 4, 1):
    v = struct.unpack_from("<I", text, off)[0]
    if lo <= v < hi:
        c[v] += 1
print("unique targets", len(c), "total refs", sum(c.values()))
for v, n in c.most_common(25):
    fo = v - IMAGE
    print(f"  va {v:#x} file {fo:#x} refs {n} head {d[fo:fo+8].hex()}")

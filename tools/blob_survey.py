"""Locate high-entropy runs and version-like strings in the updater."""
import math
import struct
from collections import Counter
from pathlib import Path

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()

def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

# .rdata file 0x1a000, size 0x86000 (548864)
base = 0x1A000
end = 0x1A000 + 0x86000
print(f"rdata {base:#x}-{end:#x}")
win = 4096
print("offset   ent")
for off in range(base, end, win):
    e = entropy(d[off:off + win])
    if e > 7.2 or e < 2.0:
        print(f"  {off:#08x} {e:5.2f}")

# search ascii version-ish
needles = [b"5.9", b"U5.9", b"TRX-1", b"TRX-2", b"CPU", b"Whistler", b"GRE"]
for n in needles:
    idx = 0
    hits = []
    while True:
        i = d.find(n, idx)
        if i < 0:
            break
        hits.append(i)
        idx = i + 1
        if len(hits) > 12:
            break
    print(n, [hex(h) for h in hits])

# pointer-sized values in .text that fall inside .rdata and look like blob starts
# scan dwords in .text
text = d[0x1000:0x1000 + 0x19000]
rdata_lo, rdata_hi = 0x401A000, 0x401A000 + 0x86000
counts = Counter()
for i in range(0, len(text) - 4, 1):
    v = struct.unpack_from("<I", text, i)[0]
    if rdata_lo <= v < rdata_hi:
        counts[v] += 1
print("--- top .rdata pointers from .text ---")
for v, n in counts.most_common(40):
    file_off = v - 0x400000
    head = d[file_off:file_off + 8].hex()
    print(f"  {v:#x} file {file_off:#x} refs {n} head {head}")

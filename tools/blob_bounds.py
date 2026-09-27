"""Find the firmware blob bounds and test a 512-byte XOR repeat."""
import struct
from pathlib import Path

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()

print("rdata head", d[0x1A000:0x1A040].hex())
print("at +0x428", d[0x1A428:0x1A468].hex())

# first low-entropy-ish run near the end of rdata: scan byte uniqueness in 256 windows
def uniq(buf):
    return len(set(buf))

print("--- uniqueness 256-byte windows from 0x98000 ---")
for off in range(0x98000, 0xA0000, 256):
    u = uniq(d[off:off + 256])
    if u < 200:
        print(f"  {off:#x} uniq {u} head {d[off:off+16].hex()}")

# CRC-16-CCITT table signature (poly 0x1021), little-endian first entries
sig = bytes.fromhex("0000211042206363")
idx = d.find(sig)
print("crc sig", hex(idx) if idx >= 0 else None)
# also reflected 0x8408 table often starts 00 00 08 84? or 00 00 89 11 depending
for sig in [bytes.fromhex("00002110"), bytes.fromhex("21104220"), bytes.fromhex("00000884"), bytes.fromhex("00002110")]:
    hits = []
    start = 0
    while True:
        i = d.find(sig, start)
        if i < 0 or len(hits) > 8:
            break
        hits.append(hex(i))
        start = i + 1
    print(sig.hex(), hits)

# autocorrelation of candidate blob 0x1B000..0x9E000 at lags
blob = d[0x1B000:0x9E000]
print("blob", len(blob))
for lag in (256, 512, 1024, 2048, 4096):
    same = sum(1 for i in range(0, min(len(blob) - lag, 65536)) if blob[i] == blob[i + lag])
    n = min(len(blob) - lag, 65536)
    print(f"  lag {lag} equal {same}/{n} {same/n:.4f}")

# look for dword size constants near 0x70000-0x90000 in .text
text = d[0x1000:0x1A000]
cands = {
    0x80000, 0x7FFE, 0x7FFF, 0x40000, 0x60000, 0x70000, 0x78000,
    0x8000, 0x10000, 0x20000, 0x84000, 0x82000, 0x81000,
    524288, 524286, 0x7FFFE, 0x3FFFF, 0xFFFF,
}
print("--- size immediates in .text ---")
found = {c: [] for c in cands}
for i in range(0, len(text) - 4):
    v = struct.unpack_from("<I", text, i)[0]
    if v in found and len(found[v]) < 6:
        found[v].append(hex(0x1000 + i))
for v, hits in sorted(found.items()):
    if hits:
        print(f"  {v:#x} {hits}")

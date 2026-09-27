"""Score RC4 variants and simple lengthened-CRC XOR unwraps."""
import math
import struct
from collections import Counter
from pathlib import Path

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
length = struct.unpack_from("<I", d, 0x1A61C)[0] & 0xFFFFFF
payload = d[0x1A620:0x1A620 + 64 + length]
static_keys = {
    "k660": d[0x9A660:0x9A6A0],
    "k620": d[0x9A620:0x9A660],
    "k6a0": d[0x9A6A0:0x9A6E0],
    "k6e0": d[0x9A6E0:0x9A720],
    "k720": d[0x9A720:0x9A760],
    "k760": d[0x9A760:0x9A7A0],
}
salt = payload[:64]
body = payload[64:]

def rc4(key: bytes, data: bytes, drop: int) -> bytes:
    S = list(range(256))
    j = 0
    mask = len(key) - 1
    for i in range(256):
        j = (j + S[i] + key[i & mask]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(data)
    for n in range(len(out)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] ^= S[(S[i] + S[j]) & 0xFF]
    return bytes(out)

def score(buf: bytes) -> tuple:
    # longest printable run, count of runs >= 8, zero-count in first 64k, ff-count
    best = cur = 0
    runs = 0
    for b in buf[:65536]:
        if 32 <= b < 127:
            cur += 1
            if cur == 8:
                runs += 1
            best = max(best, cur)
        else:
            cur = 0
    z = buf[:65536].count(0)
    f = buf[:65536].count(0xFF)
    return best, runs, z, f

def crc_table(poly: int, reflected: bool) -> bytes:
    tbl = []
    for i in range(256):
        if reflected:
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        else:
            crc = i << 8
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        tbl.append(crc & 0xFFFF)
    out = bytearray()
    for w in tbl:
        out += struct.pack("<H", w)
    return bytes(out)

cands = []
# RC4 variants on body
for name, key in static_keys.items():
    for drop in (0, 256, 512):
        mixed = bytes(a ^ b for a, b in zip(salt, key))
        for label, k in ((name, key), (name + "xor", mixed)):
            img = rc4(k, body, drop)
            cands.append((f"rc4 {label} drop{drop}", img))

# also cipher the whole payload with static key
for drop in (0, 256):
    cands.append((f"rc4 full k660 drop{drop}", rc4(static_keys["k660"], payload[:length], drop)))

print("=== rc4 scores (best, runs>=8, zeros, ff) first 64k ===")
ranked = sorted(((score(b), n, b) for n, b in cands), reverse=True)
for sc, n, b in ranked[:12]:
    print(f"  {sc} {n} head {b[:8].hex()}")

# lengthened CRC xor on the most likely wire image and on stored body
wire = rc4(bytes(a ^ b for a, b in zip(salt, static_keys["k660"])), body, 256)
tables = {
    "1021": crc_table(0x1021, False),
    "8408": crc_table(0x8408, True),
    "A001": crc_table(0xA001, True),
}
print("=== xor unwrap ===")
sources = {"stored": body, "wire": wire}
for sname, src in sources.items():
    for tname, tab in tables.items():
        variants = []
        x1 = bytes(src[i] ^ tab[i % 512] for i in range(len(src)))
        variants.append(("rep512", x1))
        x2 = bytes(src[i] ^ tab[i % 512] ^ ((i // 512) & 0xFF) for i in range(len(src)))
        variants.append(("rep512^blk", x2))
        x3 = bytes(src[i] ^ tab[i % 512] ^ ((i >> 8) & 0xFF) for i in range(len(src)))
        variants.append(("rep512^i8", x3))
        x4 = bytes(src[i] ^ tab[i % 256] ^ tab[(i // 256) % 512] for i in range(min(len(src), 80000)))
        # only score a prefix for the slower one by padding
        variants.append(("mix256", x4 + src[len(x4):]))
        for vname, img in variants:
            sc = score(img)
            if sc[0] >= 12 or sc[2] > 2000 or sc[3] > 2000:
                print(f"  HIT {sname} {tname} {vname} {sc} head {img[:16].hex()}")
print("done, top stored/wire entropy check")
# print whether version nibble appears at offset 2 or 4 after rep512 on wire
for tname, tab in tables.items():
    img = bytes(wire[i] ^ tab[i % 512] for i in range(64))
    print(tname, "wire^tab", img[:16].hex(), "b2", hex(img[2]), "b4", hex(img[4]))

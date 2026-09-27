"""Try CRC-derived keystreams on the stored body and the RC4 wire image."""
import struct
from pathlib import Path

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
length = struct.unpack_from("<I", d, 0x1A61C)[0] & 0xFFFFFF
payload = d[0x1A620:0x1A620 + 64 + length]
salt = payload[:64]
body = payload[64:]
static = d[0x9A660:0x9A6A0]
key = bytes(a ^ b for a, b in zip(salt, static))

def rc4(key, data, drop=256):
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

wire = rc4(key, body, 256)

def crc_step(crc, b, poly, reflected):
    if reflected:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        return crc & 0xFFFF
    crc ^= b << 8
    for _ in range(8):
        crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def longest(buf, limit=200000):
    best = cur = 0
    for b in buf[:limit]:
        if 32 <= b < 127:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best

def apply_stream(src, poly, reflected, init, mode):
    crc = init
    out = bytearray(len(src))
    # only first 80k for speed
    n = min(len(src), 80000)
    for i in range(n):
        if mode == "lo":
            k = crc & 0xFF
        elif mode == "hi":
            k = (crc >> 8) & 0xFF
        else:
            k = (crc ^ (crc >> 8)) & 0xFF
        out[i] = src[i] ^ k
        crc = crc_step(crc, i & 0xFF, poly, reflected)
    return bytes(out)

print("baselines", "stored", longest(body), "wire", longest(wire))
hits = []
for sname, src in (("stored", body), ("wire", wire)):
    for poly, refl in ((0x1021, False), (0x8408, True), (0xA001, True)):
        for init in (0, 0xFFFF, 0x1D0F):
            for mode in ("lo", "hi", "xor"):
                img = apply_stream(src, poly, refl, init, mode)
                L = longest(img)
                if L >= 16:
                    hits.append((L, sname, hex(poly), refl, hex(init), mode, img[:12].hex()))
print("hits", len(hits))
for h in sorted(hits, reverse=True)[:15]:
    print(h)

# model strings
print("--- strings near 0xA0190 ---")
chunk = d[0xA0190:0xA0280]
s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
print(s)

"""Recover the TRX-1 CPU image from CPUUpdater_TRX1_U5.9.exe.

The updater stores an 8-byte header at file 0x1A618, a 64-byte salt, then
RC4-drop256 ciphertext. The RC4 key is the salt XORed with the 64-byte
static key selected for platform byte 0xE3.
"""
import hashlib
import struct
from pathlib import Path

EXE = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe")
OUT = Path(r"D:\TRX\firmware")
OUT.mkdir(parents=True, exist_ok=True)

d = EXE.read_bytes()
platform = d[0x1A618]
version = d[0x1A619]
length = struct.unpack_from("<I", d, 0x1A61C)[0]
payload = d[0x1A620:0x1A620 + 64 + (length & 0xFFFFFF)]
static = d[0x9A660:0x9A660 + 64]
salt = payload[:64]
body = bytearray(payload[64:64 + (length & 0xFFFFFF)])
key = bytes(a ^ b for a, b in zip(salt, static))

def rc4_drop256(key: bytes, data: bytearray) -> None:
    S = list(range(256))
    j = 0
    mask = len(key) - 1
    for i in range(256):
        j = (j + S[i] + key[i & mask]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    for _ in range(256):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        data[n] ^= S[(S[i] + S[j]) & 0xFF]

rc4_drop256(key, body)

def strings(buf: bytes, n: int = 6):
    cur = []
    out = []
    for i, b in enumerate(buf):
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= n:
                out.append((i - len(cur), "".join(cur)))
            cur = []
    if len(cur) >= n:
        out.append((len(buf) - len(cur), "".join(cur)))
    return out

raw_path = OUT / "TRX1_CPU_U5.9.bin"
raw_path.write_bytes(body)
(OUT / "TRX1_CPU_U5.9.key").write_bytes(key)
(OUT / "TRX1_CPU_U5.9.salt").write_bytes(salt)
(OUT / "TRX1_CPU_U5.9.static_key").write_bytes(static)

printable = sum(1 for b in body[:4096] if 32 <= b < 127 or b in (0, 9, 10, 13))
strs = strings(body)
print(f"platform {platform:#x} version {version:#x} ({version>>4}.{version&0xf})")
print(f"length {length:#x} ({length})")
print(f"image {len(body)} sha256 {hashlib.sha256(body).hexdigest()}")
print(f"head {body[:64].hex()}")
print(f"printable in first 4k {printable}")
print(f"strings {len(strs)}")
for off, s in strs[:40]:
    print(f"  {off:#x} {s[:120]}")

# CRC-16/CCITT-FALSE and XMODEM over the image, and over image[2:]
def crc16(data: bytes, poly=0x1021, init=0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

if len(body) >= 4:
    c = struct.unpack_from("<H", body, 0)[0]
    print(f"first u16 {c:#06x}")
    print(f"crc xmodem rest {crc16(body[2:], init=0):#06x}")
    print(f"crc ccitt-false rest {crc16(body[2:], init=0xFFFF):#06x}")
    print(f"crc xmodem all {crc16(body, init=0):#06x}")

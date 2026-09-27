"""Search published GRE CRC-table XOR unwraps against stored and RC4 bodies."""
import struct
from pathlib import Path

d = Path(r"D:\TRX\CPUUpdater_TRX1_U5.9.exe").read_bytes()
LENGTH = struct.unpack_from("<I", d, 0x1A61C)[0] & 0xFFFFFF
stored = bytearray(d[0x1A620 + 64 : 0x1A620 + 64 + LENGTH])
salt = d[0x1A620 : 0x1A620 + 64]
static = d[0x9A660 : 0x9A6A0]
key = bytes(a ^ b for a, b in zip(salt, static))


def rc4_drop(data: bytes, key: bytes, drop: int) -> bytes:
    S = list(range(256))
    j = 0
    mask = len(key) - 1
    for i in range(256):
        j = (j + S[i] + key[i & mask]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
    out = bytearray(data)
    for n in range(len(out)):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out[n] ^= S[(S[i] + S[j]) & 255]
    return bytes(out)


wire = rc4_drop(stored, key, 256)


def crc_table(poly: int, reflected: bool):
    tbl = []
    for i in range(256):
        if reflected:
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        else:
            crc = i << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        tbl.append(crc & 0xFFFF)
    return tbl


def table_bytes(tbl, be=False):
    out = bytearray()
    for w in tbl:
        if be:
            out.append((w >> 8) & 0xFF)
            out.append(w & 0xFF)
        else:
            out.append(w & 0xFF)
            out.append((w >> 8) & 0xFF)
    return bytes(out)


def crc16(data: bytes, poly=0x1021, init=0xFFFF):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def score(buf: bytes):
    best = cur = runs = 0
    letters = 0
    for b in buf[:48]:
        if 32 <= b < 127:
            cur += 1
            best = max(best, cur)
            if 65 <= b <= 90 or 97 <= b <= 122:
                letters += 1
        else:
            if cur >= 4:
                runs += 1
            cur = 0
    if cur >= 4:
        runs += 1
    return best, runs, letters


def show(tag, buf):
    sc = score(buf)
    c_le = struct.unpack_from("<H", buf, 0)[0]
    c_be = struct.unpack_from(">H", buf, 0)[0]
    rest = bytes(buf[2:4096])
    checks = []
    for init in (0, 0xFFFF, 0x1D0F):
        v = crc16(rest, init=init)
        if v in (c_le, c_be):
            checks.append(f"crc init {init:#x} match {v:#06x}")
    ver = []
    for off in (2, 4, 5, 6):
        if off < len(buf) and buf[off] == 0x59:
            ver.append(off)
    if sc[0] >= 6 or ver or checks:
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in buf[:32])
        print(f"HIT {tag} score {sc} ver@{ver} {checks} {buf[:16].hex()} {text}")
        return True
    return False


tables = {}
for poly, ref, name in (
    (0x1021, False, "1021"),
    (0x8005, False, "8005"),
    (0x8408, True, "8408"),
    (0xA001, True, "a001"),
):
    t = crc_table(poly, ref)
    tables[name] = t
    tables[name + "le"] = table_bytes(t, False)
    tables[name + "be"] = table_bytes(t, True)

sources = {"stored": bytes(stored), "wire": wire}
N = 64  # score window; full buffer only on hit
hits = 0

# Precompute nothing; generate key byte on the fly for the window.
for sname, src in sources.items():
    window = src[:N]
    for tname, tbl in tables.items():
        if not tname.endswith(("le", "be")):
            continue
        tb = tbl
        # phase shifts of a plain 512 repeat, and a few lengtheners
        for phase in range(0, 512, 1):
            # only test a subset of phases first? all 512 is fine for N=64
            pass
        # vectorized-ish python for phase 0 plus lengthen families; phases in a second loop
        for phase in (0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 255, 511):
            variants = []
            # rep
            variants.append(("rep", bytes(window[i] ^ tb[(i + phase) % 512] for i in range(N))))
            variants.append(("blk", bytes(window[i] ^ tb[(i + phase) % 512] ^ ((i // 512) & 0xFF) for i in range(N))))
            variants.append(("i8", bytes(window[i] ^ tb[(i + phase) % 512] ^ ((i >> 8) & 0xFF) for i in range(N))))
            variants.append(("i16", bytes(window[i] ^ tb[(i + phase) % 512] ^ ((i >> 16) & 0xFF) for i in range(N))))
            variants.append(("tb2", bytes(window[i] ^ tb[(i + phase) % 512] ^ tb[(i // 512) % 512] for i in range(N))))
            for vname, img in variants:
                if show(f"{sname} {tname} p{phase} {vname}", img):
                    hits += 1

    # word-mix families using the 256-word table
    base = tname_base = None
    for base_name in ("1021", "8005", "8408", "a001"):
        T = tables[base_name]
        for adj in (0, 1, 2, 3, 4, 0x10, 0x20, 0x59, 0xE3, 0xFF):
            imgs = {k: bytearray(N) for k in ("xorlo", "xorhi", "alt", "sumlo", "idx")}
            for i in range(N):
                lo = i & 0xFF
                hi = (i >> 8) & 0xFF
                mid = (i >> 16) & 0xFF
                w = T[lo] ^ T[(hi + adj) & 0xFF] ^ T[mid]
                w2 = T[(lo + adj) & 0xFF] ^ T[hi] ^ T[mid]
                imgs["xorlo"][i] = window[i] ^ (w & 0xFF)
                imgs["xorhi"][i] = window[i] ^ ((w >> 8) & 0xFF)
                imgs["alt"][i] = window[i] ^ ((w2 >> 8) & 0xFF if i & 1 else w2 & 0xFF)
                imgs["sumlo"][i] = window[i] ^ ((w + w2) & 0xFF)
                imgs["idx"][i] = window[i] ^ (T[(lo + hi + adj) & 0xFF] & 0xFF)
            for k, img in imgs.items():
                if show(f"{sname} {base_name} adj{adj:#x} {k}", bytes(img)):
                    hits += 1

print("window hits", hits)

# autocorrelation on full buffers, selected lags
def zero_rate(buf, lag, step=1):
    n = (len(buf) - lag) // step
    z = 0
    for i in range(0, n * step, step):
        if buf[i] == buf[i + lag]:
            z += 1
    return z / n

lags = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144]
print("--- autocorrelation P(equal) ---")
for sname, src in (("stored", bytes(stored)), ("wire", wire)):
    print(sname)
    for lag in lags:
        if lag >= len(src) - 1000:
            continue
        # sample every 4th byte for speed
        z = zero_rate(src, lag, step=4)
        mark = " <<" if z > 0.008 else ""
        print(f"  lag {lag:7d} {z:.5f}{mark}")
print("done")

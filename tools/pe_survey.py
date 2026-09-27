"""Survey CPUUpdater_TRX1_U5.9.exe: sections, resources, and candidate blobs."""
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1] if len(sys.argv) > 1 else r"D:\TRX\CPUUpdater_TRX1_U5.9.exe")
d = p.read_bytes()
pe = struct.unpack_from("<I", d, 0x3C)[0]
machine, nsec, ts, symptr, nsym, optsz, chars = struct.unpack_from("<HHIIIHH", d, pe + 4)
opt = pe + 24
magic, = struct.unpack_from("<H", d, opt)
print(f"file {p.name} size {len(d)} magic {magic:#x} sections {nsec} opt {optsz}")
num_dd, = struct.unpack_from("<I", d, opt + 92)
dd_off = opt + 96
names = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCH", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND", "IAT",
    "DELAY", "CLR", "RESERVED",
]
image_base, = struct.unpack_from("<I", d, opt + 28)
print(f"image_base {image_base:#x} num_dd {num_dd}")
for i in range(min(num_dd, 16)):
    rva, sz = struct.unpack_from("<II", d, dd_off + i * 8)
    if rva or sz:
        label = names[i] if i < len(names) else "?"
        print(f"  {i:2} {label}: rva={rva:#x} size={sz}")

sec_off = opt + optsz
sections = []
print("--- sections ---")
for i in range(nsec):
    name, vsz, va, rsz, raw, rel, ln, nrel, nln, ch = struct.unpack_from(
        "<8sIIIIIIHHI", d, sec_off + i * 40
    )
    nm = name.split(b"\x00", 1)[0].decode("ascii", "replace")
    sections.append((nm, va, vsz, raw, rsz))
    print(f"  {nm:8} va={va:#x} vsz={vsz} raw={raw:#x} rsz={rsz} ch={ch:#x}")


def rva_to_off(rva: int) -> int:
    for nm, va, vsz, raw, rsz in sections:
        span = max(vsz, rsz)
        if va <= rva < va + span:
            return raw + (rva - va)
    raise ValueError(f"rva {rva:#x} not in a section")


res_rva, res_sz = struct.unpack_from("<II", d, dd_off + 2 * 8)
res_off = rva_to_off(res_rva)
print(f"--- resources at file {res_off:#x} rva {res_rva:#x} size {res_sz} ---")


def read_dir(off: int, level: int, path: str) -> None:
    # IMAGE_RESOURCE_DIRECTORY
    chars, tstamp, maj, minv, nnamed, nid = struct.unpack_from("<IIHHHH", d, off)
    entries = nnamed + nid
    ent = off + 16
    for i in range(entries):
        name_or_id, offset = struct.unpack_from("<II", d, ent + i * 8)
        if name_or_id & 0x80000000:
            noff = res_off + (name_or_id & 0x7FFFFFFF)
            nlen, = struct.unpack_from("<H", d, noff)
            nstr = d[noff + 2:noff + 2 + nlen * 2].decode("utf-16le", "replace")
            label = nstr
        else:
            label = str(name_or_id)
        child = path + "/" + label
        if offset & 0x80000000:
            read_dir(res_off + (offset & 0x7FFFFFFF), level + 1, child)
        else:
            data_off = res_off + offset
            data_rva, size, cp, reserved = struct.unpack_from("<IIII", d, data_off)
            file_off = rva_to_off(data_rva)
            head = d[file_off:file_off + 16].hex()
            print(f"  {child}  size={size} file={file_off:#x} cp={cp} head={head}")


read_dir(res_off, 0, "")

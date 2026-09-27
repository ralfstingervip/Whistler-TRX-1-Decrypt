"""IDA batch: decompile the TRX-1 updater cipher and send path."""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idp
import ida_lines
import idc

OUT = r"D:\TRX\ida\out\hexrays.txt"
TARGETS = [
    (0x401490, "key_select"),
    (0x401500, "rc4_setup"),
    (0x4015B0, "rc4_prga"),
    (0x402520, "send"),
]

def ensure_func(ea):
    f = ida_funcs.get_func(ea)
    if f:
        return f
    idc.create_insn(ea)
    if ida_funcs.add_func(ea):
        return ida_funcs.get_func(ea)
    return None

def dump_disasm(ea, end, fh):
    cur = ea
    n = 0
    while cur < end and cur != idc.BADADDR and n < 8000:
        fh.write("  %s\n" % idc.generate_disasm_line(cur, 0))
        nxt = idc.next_head(cur, end)
        if nxt == idc.BADADDR or nxt <= cur:
            break
        cur = nxt
        n += 1

ida_auto.auto_wait()
fh = open(OUT, "w", encoding="utf-8", errors="replace")
fh.write("processor %s\n" % ida_idp.get_idp_name())
ok = ida_hexrays.init_hexrays_plugin()
fh.write("hexrays %s\n" % ok)

for ea, name in TARGETS:
    idc.set_name(ea, "trx_" + name, idc.SN_NOWARN)
    f = ensure_func(ea)
    fh.write("\n\n########## %s %08X ##########\n" % (name, ea))
    if not f:
        fh.write("NO FUNCTION\n")
        continue
    fh.write("func %08X-%08X size %d\n" % (f.start_ea, f.end_ea, f.end_ea - f.start_ea))
    fh.write("--- disasm ---\n")
    dump_disasm(f.start_ea, f.end_ea, fh)
    fh.write("\n--- hexrays ---\n")
    if not ok:
        fh.write("hexrays unavailable\n")
        continue
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            fh.write("decompile returned None\n")
        else:
            fh.write(str(cfunc))
            fh.write("\n")
    except Exception as exc:
        fh.write("EXC %r\n" % (exc,))

# raw header and selected key, as IDA sees them
fh.write("\n\n########## bytes ##########\n")
fh.write("hdr %s\n" % ida_bytes.get_bytes(0x41A618, 8).hex())
fh.write("salt %s\n" % ida_bytes.get_bytes(0x41A620, 64).hex())
fh.write("key %s\n" % ida_bytes.get_bytes(0x49A660, 64).hex())
fh.close()
idc.qexit(0)

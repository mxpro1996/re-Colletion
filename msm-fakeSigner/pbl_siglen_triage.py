"""
pbl_siglen_triage.py -- run inside IDA Pro, on any Qualcomm boot ROM dump.

Answers one question: does this PBL size its PKCS#1 v1.5 window from the
MODULUS (fixed) or from the IMAGE HEADER (vulnerable, MSM8612 class)?

It does not try to be clever. It finds the two shape constants that appear in
every copy of this verifier, follows the xrefs to the functions that use them,
and then prints every instruction in those functions that computes an index
shift -- so you can read the bound's provenance with your own eyes.

    vulnerable (MSM8612)      0xfc01f390  LDR R0,[R4,#0x1C]     ; sig_len
                              0xfc01f394  ADD R1,R1,R0,LSR#2    ; (sig_len>>2)-1

    fixed (MSM8916)           0x110048    LDR R0,[SP,#var_8A0]  ; mod word count
                              0x11004c    SUB R1,R0,#1          ; mod_words-1

Usage, from the IDAPython console:

    exec(open(r"C:\\path\\to\\pbl_siglen_triage.py").read())

or File > Script file... and pick this file.
"""

import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import idc

# 00 FF FF FF right after the digest, and the 00 01 FF FF top word.
SENTINELS = (0xFFFFFF00, 0x0001FFFF)
SENTINEL_NAMES = {0xFFFFFF00: "00 FF FF FF (shape)", 0x0001FFFF: "00 01 FF FF (top word)"}

# A legacy MBN image starts with these; finding them tells us the packaging.
MBN_CODEWORD = 0x844BDCD1
MBN_MAGIC = 0x73D71034

INTERESTING = ("LSR#2", "LSR #2", ", #1", "LDR", "ADD", "SUB", "CMN", "CMP")


def out(s=""):
    print(s)
    ida_kernwin.msg(s + "\n")


def segments():
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg:
            yield seg


def find_sentinel_data():
    """Word-scan the image for the sentinel constants. Cheap and version-safe."""
    hits = {v: [] for v in SENTINELS}
    for seg in segments():
        ea = seg.start_ea
        end = seg.end_ea
        while ea + 4 <= end:
            v = ida_bytes.get_dword(ea)
            if v in hits:
                hits[v].append(ea)
            ea += 4
    return hits


def baseline():
    """Guess the packaging: legacy MBN vs ELF."""
    notes = []
    mbn = 0
    for seg in segments():
        ea = seg.start_ea
        end = seg.end_ea
        while ea + 8 <= end:
            if (ida_bytes.get_dword(ea) == MBN_CODEWORD
                    and ida_bytes.get_dword(ea + 4) == MBN_MAGIC):
                mbn += 1
                if mbn <= 3:
                    notes.append("  legacy MBN header candidate @0x%x" % ea)
            ea += 4
    elf = 0
    for s in idautils.Strings():
        t = str(s)
        if "pbl_elf_loader" in t:
            elf += 1
        if "pbl_auth" in t:
            notes.append("  auth source string: %s" % t)
    if elf:
        notes.append("  ELF loader strings present -> ELF-based SBL baseline")
    if mbn:
        notes.append("  MBN codeword+magic present -> legacy MBN packaging")
    return notes


def index_instructions(func_ea, before=2, after=4):
    """Only the lines around an index shift -- that is where the bound is computed.

    Prints a window around every `...,LSR#2` so you can see what feeds the shift
    and what the shift is then subtracted from.
    """
    rows = []
    for ea in idautils.FuncItems(func_ea):
        text = idc.GetDisasm(ea)
        if text:
            rows.append((ea, text))

    shown = set()
    picked = []
    for i, (ea, text) in enumerate(rows):
        if "LSR#2" in text or "LSR #2" in text:
            for j in range(max(0, i - before), min(len(rows), i + after + 1)):
                if j not in shown:
                    shown.add(j)
                    picked.append((j, rows[j][0], rows[j][1]))
    picked.sort()
    return [(ea, text) for _j, ea, text in picked]


def main():
    out("=" * 78)
    out("PBL signature-window triage")
    out("=" * 78)

    notes = baseline()
    out("[+] packaging")
    if notes:
        for n in notes:
            out(n)
    else:
        out("  no MBN codeword and no ELF loader strings found (stripped dump?)")

    hits = find_sentinel_data()
    out("")
    out("[+] shape constants")
    found_any = False
    candidates = []
    for v in SENTINELS:
        out("  %s  (0x%08x): %d occurrence(s)" % (SENTINEL_NAMES[v], v, len(hits[v])))
        for ea in hits[v][:8]:
            out("      @0x%x" % ea)
            for xr in idautils.XrefsTo(ea, 0):
                f = ida_funcs.get_func(xr.frm)
                fname = ida_funcs.get_func_name(f.start_ea) if f else "?"
                out("        xref from 0x%x in %s" % (xr.frm, fname))
                if f and f.start_ea not in candidates:
                    candidates.append(f.start_ea)
        if hits[v]:
            found_any = True

    if not found_any:
        out("")
        out("[-] neither sentinel appears as a data word. This copy probably builds")
        out("    the constants with MOVW/MOVT, so there is nothing to anchor on.")
        out("    Fall back to: search immediate 0x0001FFFF, then read the bound.")
        return

    out("")
    out("[+] candidate verifier functions: %d" % len(candidates))
    for fea in candidates:
        f = ida_funcs.get_func(fea)
        out("")
        out("-" * 78)
        out("function %s @0x%x  (%d bytes)"
            % (ida_funcs.get_func_name(fea), fea, f.end_ea - f.start_ea if f else -1))
        out("-" * 78)
        for ea, text in index_instructions(fea):
            out("  0x%08x  %s" % (ea, text))
        out("")
        out("  ^ Look for the padding-scan bound:")
        out("      ADD Rn, Rm, Rk,LSR#2   then  SUB bound, <that>, #1")
        out("    - if Rk came from a header field (e.g. [Rx,#0x1C]) -> VULNERABLE")
        out("    - if the bound is the word count of the modulus bignum -> FIXED")

    out("")
    out("[i] This is a reading aid, not a verdict. Confirm the data flow by hand:")
    out("    the question is only ever *what sizes the window*.")


if __name__ == "__main__":
    main()

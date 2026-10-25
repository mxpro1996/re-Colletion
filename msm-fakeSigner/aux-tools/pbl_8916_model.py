#!/usr/bin/env python3
"""
Does MSM8916's PBL have the same short-signature bug as MSM8612?  No -- and this
script shows exactly where the two verifiers diverge.

Both verifiers share the same skeleton (the 0x36 / 0x5C keyed digest chain, the
00 FF FF FF shape check, the 0xFF run, the 00 01 FF FF top word, the digest
compare). They differ in ONE quantity: where the padding scan stops.

  MSM8612  (auth_verify_signature @ 0xfc01ed50)
      0xfc01f390  LDR R0,[R4,#0x1C]      ; sig_len, from the image header
      0xfc01f394  ADD R1,R1,R0,LSR#2     ; bound = (sig_len>>2) - 1     <-- BUG

  MSM8916  (sub_10FA1C @ 0x110000 region)
      0x110044    ADD R2,R8,R0,LSR#2     ; start = (hash_len>>2) + 1
      0x110048    LDR R0,[SP,#var_8A0]   ; v50[128] = word count of the MODULUS
      0x11004c    SUB R1,R0,#1           ; bound = mod_words - 1        <-- FIXED

Because the bound comes from the modulus, declaring a short signature no longer
narrows the window: the top word that must read 00 01 FF FF sits at
result[mod_words-1], which a short s can never reach.

Usage:  python pbl_8916_model.py [image.mbn] [sw_id] [hw_id]
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "m", os.path.join(HERE, "mbn_fakesign.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def mod_words(n_bytes):
    """Word count the way sub_110294() computes it: ceil(len/4) minus zero words."""
    j = (len(n_bytes) + 3) >> 2
    w = [int.from_bytes(n_bytes[4 * k:4 * k + 4].ljust(4, b"\x00"), "little")
         for k in range(j)]
    while j > 1 and w[j - 1] == 0:
        j -= 1
    return j


def verify_8916(n_bytes, e_bytes, sig_bytes, digest):
    """Model of sub_10FA1C: identical checks, but every bound comes from the modulus."""
    hl = len(digest)
    mw = mod_words(n_bytes)
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    s = int.from_bytes(sig_bytes, "big")

    x = pow(s, e, n)
    buf = x.to_bytes(mw * 4, "little")          # little-endian words, width = modulus
    w = [int.from_bytes(buf[4 * k:4 * k + 4], "little") for k in range(mw)]

    # 0x1100xx: result[hl & ~3] must be 00 FF FF FF
    if w[(hl & 0xFFFFFFFC) >> 2] != 0xFFFFFF00:
        return 1129, mw
    # 0x11005c: scan the 0xFF run, from (hl>>2)+1 up to mod_words-1
    start, end = (hl >> 2) + 1, mw - 1
    if start < end:
        k = start
        while w[k] == 0xFFFFFFFF:
            k += 1
            if k >= end:
                break
        else:
            return 1148, mw
    # 0x1100a0: top word, indexed by the MODULUS word count
    if w[mw - 1] != 0x0001FFFF:
        return 1156, mw
    # 0x1100e0: digest compare, hl bytes
    if buf[:hl] != digest[::-1]:
        return 12, mw
    return 0, mw


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "firehose_signed.mbn"
    sw = sys.argv[2] if len(sys.argv) > 2 else "0000000000000003"
    hw = sys.argv[3] if len(sys.argv) > 3 else "008150E100150017"

    buf = open(path, "rb").read()
    hdr = m.MbnHeader.read(buf)
    certs = m.extract_certs(buf, hdr)
    n, e = m.x509_pubkey(certs[0])
    code = buf[hdr.file_off(hdr.load_addr):][:hdr.code_size]
    sig = buf[hdr.file_off(hdr.sig_addr):][:hdr.sig_len]
    algo = m.detect_hash(certs[0])
    d3 = m.image_digest(hdr.raw, code, bytes.fromhex(sw), bytes.fromhex(hw), algo)[2]

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8 or 1, "big")
    mw = mod_words(n_bytes)

    print("image          : %s" % path)
    print("modulus        : %d bits = %d bytes = %d words" % (n.bit_length(), len(n_bytes), mw))
    print("exponent       : e = %d" % e)
    print("signature      : %d bytes declared in the header" % len(sig))
    print("digest (D3)    : %s" % d3.hex()[:16] + "...")
    print()

    ok8612, rc8612 = m.pbl_verify_signature(n_bytes, e_bytes, sig, d3)
    rc8916, _ = verify_8916(n_bytes, e_bytes, sig, d3)

    print("MSM8612 model  bound = (sig_len>>2)-1 = %d" % ((len(sig) >> 2) - 1))
    print("               -> %s" % ("ACCEPTED" if ok8612
                                  else "rejected %d %s" % (rc8612, m.FAIL.get(rc8612, ""))))
    print("MSM8916 model  bound = mod_words-1   = %d" % (mw - 1))
    print("               -> %s" % ("ACCEPTED" if rc8916 == 0
                                  else "rejected %d" % rc8916))
    print()

    s = int.from_bytes(sig, "big")
    print("why: s is %d bits, s^%d is %d bits." % (s.bit_length(), e, (s.bit_length()) * e))
    print("     The result is written into a %d-byte window (the modulus width)." % (mw * 4))
    print("     Word [%d] of that window must read 00 01 FF FF." % (mw - 1))
    print("     A %d-byte signature leaves words [%d..%d] at zero -- the check can never pass."
          % (len(sig), (len(sig) >> 2), mw - 1))
    print()
    print("Same forged image, same genuine cert chain, same digest: the only change")
    print("is which value sizes the window.")


if __name__ == "__main__":
    main()

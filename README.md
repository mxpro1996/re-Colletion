# Qualcomm PBL short-signature forgery (legacy MBN)

A pure-Python research toolkit that reproduces, and demonstrates end to end, the
Qualcomm **Primary Boot Loader (PBL) short-signature flaw**: the PBL takes the
signature length from the image header (attacker controlled) and never requires
it to equal the RSA modulus length. When any certificate in the chain carries
public exponent **e = 3**, that is enough to forge a signature over an arbitrary
image with no private key at all.

Everything here is standard library only -- no `pycryptodome`, no `openssl`, no
vendor tooling.

---

## What is in the box

| file | what it does |
|---|---|
| `mbn_fakesign.py` | the actual tool: `info` / `sign` / `verify` / `selftest` |
| `pbl_siglen_poc.py` | faithful Python reimplementation of `auth_verify_signature()` + `rsa_mod_exp_driver()` as they appear in `msm8612.bootrom.bin` |
| `pkcs1_primer.py` | teaches the crypto: why a *narrower window* turns e=3 from safe into forgeable |
| `pbl_siglen_intuition.py` | three controlled experiments (window width, the `s^3 < n` dead line, why L=256 is hopeless) |
| `l_sweep.py` | sweeps the usable range of `L` against a real image and reports why each value passes or fails |
| `docs/vulnerability.md` | the bug, the IDA evidence, the exact PBL checks |
| `docs/hardware-evidence.md` | the on-device validation log (MSM8612, Sahara/firehose) |
| `docs/mbn-format.md` | legacy MBN header layout, address arithmetic, digest chain |
| `CREDIT.md` | references and acknowledgements |

## Quick start

```bash
# 1) no hardware needed -- self-contained end-to-end demo (generates its own e=3 key)
python mbn_fakesign.py selftest

# 2) inspect a real image: header, cert chain, leaf exponent, forgeable L range
python mbn_fakesign.py info --mbn MPRG8x10.mbn

# 3) forge: re-sign an image with its own (genuine) certificate chain
python mbn_fakesign.py sign --payload-mbn prog_emmc_firehose_8x10.mbn \
        --out firehose_signed.mbn --sw-id 0000000000000003 --hw-id 008150E100150017

# 4) re-verify from disk only -- re-derives everything, trusts the signing run for nothing
python mbn_fakesign.py verify --mbn firehose_signed.mbn \
        --sw-id 0000000000000003 --hw-id 008150E100150017
```

Transplanting code from one image into another is the same command
with an explicit donor:

```bash
# take the code from payload.mbn, sign it with the chain from donor.mbn
python mbn_fakesign.py sign --donor MPRG8x10.mbn --payload-mbn prog_emmc_firehose_8x10.mbn \
        --out out.mbn --sw-id ... --hw-id ...
```

`sign` rewrites every header field that has to move -- `BodySize`, `CodeSize`,
`SignatureAddress`, `SignatureLength`, `CertificateStoreAddress` -- and `verify`
audits them independently. See `docs/mbn-format.md`.

## The bug in one paragraph

The PBL computes `EM' = s^e mod n`, then checks that `EM'` looks like a PKCS#1
v1.5 block. Two independent quantities are sized from the **header's**
`SignatureLength` instead of the modulus: the padding scan stops at
`(sig_len >> 2) - 1`, and the window the digest is compared against is `L` bytes
wide. Declare `L = 60` against a 256-byte modulus and the PBL validates 60 bytes
and ignores the other 196. With `e = 3` and `s^3 < n`, no modular reduction ever
happens, so the attacker only needs

```
s^3 == T  (mod 2^(8L))      and      s^3 < n
```

and cubing is a *bijection* on the odd residues mod `2^(8L)`, so `s` is a single
modexp away: `s = T^d mod 2^(8L)` where `d = 3^(-1) mod 2^(8L-1)`. No factoring,
no private key, no brute force -- about 0.2 ms.

The certificate chain is never forged. You reuse a genuine, OEM-signed chain
whose leaf happens to be `e = 3`; shipped firmware is full of them.

## How far `L` can be pushed

```
e * 8L < log2(n)
```

| key | 2048-bit modulus |
|---|---|
| e = 3 | `L < 85.33` -- measured usable band **L = 40 .. 85** |
| e = 65537 | `L < 0.0039` -- no solution; rotating the key seals it |

Two secondary constraints bite in practice (see `l_sweep.py`):

* **the digest must be odd**, or no cube root exists mod `2^k`. Roughly two
  thirds of `L` values are rejected on this ground -- the digest covers the
  header, which contains `L`, so you just try the next `L`.
* **the PBL demands only five `0xFF` padding bytes**, not PKCS#1's eight, so
  `L = 40` already works. `mbn_fakesign.py` sweeps from 44 (RFC 8017's floor)
  and `--L 40` squeezes further.

## Affected silicon

Confirmed by disassembling the boot ROMs:

| target | state | source |
|---|---|---|
| APQ8064 PBL | vulnerable | oscardagrach, first-hand |
| APQ8084 PBL | vulnerable | oscardagrach, first-hand |
| **MSM8974 PBL** | **vulnerable** | oscardagrach, first-hand; digest construction for MSM8974 also documented by TalAloni (Note 3) |
| **MSM8612 PBL** | **vulnerable** | this repository -- IDA confirmed **and** validated on real hardware |

The PBL is mask ROM. There is no update path and no fuse that changes the
routine, so "vulnerable" is a permanent property of the silicon, not of a
firmware build. The same routine is duplicated in SBL1 and TrustZone; those
copies live in flash and were corrected at some point, which hardens the *stock*
chain but does not rescue the PBL -- a forged SBL1 is just a file, and whoever
can boot one can strip its signature checks first.

## On-device validation (MSM8612)

Full log in `docs/hardware-evidence.md`. Summary:

* `OEM_PK_HASH` read from the fuses is non-zero, so signature verification is
  live and forging is genuinely required.
* `SHA-256` of the **entire root certificate DER** equals the fused
  `OEM_PK_HASH` byte for byte -- confirming TalAloni's Note 2 and pinning the
  root of trust.
* `firehose_signed.mbn` (L = 60) was accepted by Sahara on a real device: the
  "did not receive hello packet" error disappeared and the programmer came up
  (`logbuf@0xF8020CC0 fh@0xF801DB28`).

## Corrections to the usual write-ups

Working from the actual disassembly turned up four places where the common
description of this bug is imprecise. They are spelled out in
`docs/vulnerability.md`:

1. **The modulus is never truncated.** `n` stays a full 2048 bits. What changes
   is how many bytes of the *result* are inspected.
2. **No expected block is compared.** The PBL checks a handful of shape
   constraints plus 32 bytes of bare digest; there is no "expected EM" to match
   against, and the window is anchored at the *bottom* of the result.
3. **Cube roots mod `2^k` need no bit-by-bit lifting.** It is one modular
   exponentiation, because cubing is a bijection there.
4. **`L` need not be a multiple of 4**, and the padding floor is 5 bytes, not 8.

## Scope and ethics

This is for security research on hardware you own or are authorised to test. The
tool does not help you obtain a certificate chain, bypass a fused device that has
no `e = 3` chain available, or defeat anti-rollback. It exists so that the flaw
can be verified, measured, and argued about with evidence rather than assertion.

## References

See `CREDIT.md`.

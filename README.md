# Qualcomm PBL short-signature forgery (legacy MBN)

A pure-Python research toolkit that reproduces, and demonstrates end to end, the
Qualcomm **Primary Boot Loader (PBL) short-signature flaw**: on affected parts
the PBL takes the signature length from the image header (attacker controlled)
and never requires it to equal the RSA modulus length. When any certificate in
the chain carries public exponent **e = 3**, that is enough to forge a signature
over an arbitrary image with no private key at all.

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
| `pbl_8916_model.py` | MSM8916's verifier modelled side by side with MSM8612's -- shows the fix, on the same forged image |
| `pbl_siglen_triage.py` | IDA script: run it on any boot ROM to see whether the window is sized from the modulus or the header |
| `docs/vulnerability.md` | the bug, the IDA evidence, the exact PBL checks, and the MSM8916 comparison |
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
| **MSM8916 PBL** | **not vulnerable** | this repository -- IDA confirmed: the window is sized from the modulus, not the header |

MSM8916 is worth calling out because it is the control case. It moved to an
ELF-based SBL (`pbl_elf_loader.c`), but the verification math is unchanged --
same `0x36`/`0x5C` digest chain, same shape checks. The only difference is that
the padding scan and the top-word check are indexed by the **modulus** word count
(`0x110048 LDR R0,[SP,#var_8A0]` / `0x11004c SUB R1,R0,#1`) instead of by
`sig_len` (`0xfc01f390 LDR R0,[R4,#0x1C]` / `0xfc01f394 ADD R1,R1,R0,LSR#2`).
That single change is sufficient: the same 60-byte forged signature that MSM8612
accepts is rejected `1148` on the MSM8916 model. See the appendix of
`docs/vulnerability.md`.

Notably MSM8916 still does **not** enforce `sig_len == mod_len` -- it relies
entirely on sizing the window from the key, which is a live demonstration that
either defence alone is enough.

The PBL is mask ROM. There is no update path and no fuse that changes the
routine, so "vulnerable" is a permanent property of the silicon, not of a
firmware build. The same routine is duplicated in SBL1 and TrustZone; those
copies live in flash and were corrected at some point, which hardens the *stock*
chain but does not rescue the PBL -- a forged SBL1 is just a file, and whoever
can boot one can strip its signature checks first.

## Guessing about other parts

Do not sort parts by model number or by release date -- sort them by **boot ROM
code line**, which is visible in the dump:

| code line | packaging | what to expect |
|---|---|---|
| MSM8960 / MSM8974 / APQ8084 family (Krait, 2012-2014) | legacy MBN, `auth_verify_signature` | the vulnerable form; APQ8064, APQ8084 and MSM8974 are confirmed |
| MSM8916 and later A53 parts | ELF SBL, `pbl_elf_loader.c` | MSM8916 confirmed fixed; the rest of the line very likely follows |

`MSM8930` and `MSM8939` differ by one digit and belong to different lines
entirely: 8930 is an MSM8960-family Krait part (same generation as the confirmed
APQ8064), while 8939 is an A53 part from the 8916 line. Sorting by number gets
this exactly backwards.

The only real answer is a dump. `pbl_siglen_triage.py` runs inside IDA on any
boot ROM and prints the one window that decides it:

```
python (in IDA):  exec(open(r"...\pbl_siglen_triage.py").read())
```

It finds the `00 01 FF FF` / `00 FF FF FF` sentinels, follows the xrefs, and
shows the lines around every `...,LSR#2`. On MSM8916 that is:

```
0x110040  MOV R1, #0xFFFFFFFF
0x110044  ADD R2, R8, R0,LSR#2        ; start = (hash_len>>2)+1
0x110048  LDR R0, [SP,#var_8A0]       ; word count of the MODULUS
0x11004c  SUB R1, R0, #1              ; bound = mod_words-1     <- fixed
```

On MSM8612 the same window reads `LDR R0,[R4,#0x1C]` (a header field) followed by
`ADD R1,R1,R0,LSR#2` -- no `SUB ... #1` from a bignum, because the bound *is* the
header value. That difference is the whole verdict.

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

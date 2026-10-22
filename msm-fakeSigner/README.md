# legacy-fakeSigner
**Templated by AI, with the progress of interpreting, I will restruct it.**\
The legacy PBL is blinded by the `sign_len` from the image header and never requires it to equal the RSA modulus length. \
When any certificate in the chain carries
public exponent **e = 3**, that is enough to forge a signature over an arbitrary
image with no private key at all.

---

## Affected range

Confirmed first-hand, by disassembling the boot ROMs:

| target | state |
|---|---|
| APQ8064 PBL | vulnerable |
| APQ8084 PBL | vulnerable |
| MSM8974 PBL | vulnerable |
| MSM8x10 PBL | vulnerable |
| MSM8x26 PBL | vulnerable |


## Quick start

```bash
# 1) inspect a real image
mbn_fakesign.py info --mbn MPRG8x10.mbn

# 2) forge: self re-sign an image
mbn_fakesign.py sign --payload-mbn prog_emmc_firehose_8x10.mbn \
        --out firehose_signed.mbn

# 3) Derive: Sign payload with donor's chain
mbn_fakesign.py sign --donor MPRG8x10.mbn --payload-mbn prog_emmc_firehose_8x10.mbn \
        --out out.mbn

# 4) no hardware needed -- self-contained end-to-end demo (generates its own e=3 key)
mbn_fakesign.py selftest
# 5) re-verify from disk only -- re-derives everything, trusts the signing run for nothing
mbn_fakesign.py verify --mbn firehose_signed.mbn
```

## Scope

This is for security research on hardware you own or are authorised to test.\
It exists so that the flaw
can be verified and measured.

## Credit
**Ryan** --
[`qualcomm_pbl_siglen_bug`](https://github.com/oscardagrach/qualcomm_pbl_siglen_bug)

**Tal Aloni** --
[`QualcommSecureBoot-SecondaryExecutableVerifier`](https://github.com/TalAloni/QualcommSecureBoot-SecondaryExecutableVerifier)

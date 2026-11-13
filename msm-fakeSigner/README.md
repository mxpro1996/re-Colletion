# legacy-fakeSigner

The legacy PBL is blinded by the `sign_len` field from the MBN-header and never requires it to equal the RSA modulus length. 
When any certificate in the chain carries a public exponent of:```e = 3```\
It's sufficient to forge a signature over an arbitrary image with no private key at all.

Given the boot-related function table is reused during:```pbl -> sbl -> down_stream```\
the actually affected verification range is:

- `pbl -> sahara (eHostDL)` 
- `pbl -> sbl` 
- `pbl -> sbl -> Image (aboot..)` 


## Influenced
Confirmed first-hand, by disassembling the boot ROMs: \
Legacy-msm often share the "DNA" between series, it's not rare to see these

| target | alias | state |
|---|---|---|
| MSM8x10 | SDM200 | vulnerable |
| MSM8x26 | SDM400 | vulnerable |
| APQ8064 | SDM600- | vulnerable |
| MSM8974 | SDM800 | vulnerable |
| APQ8084 | SDM805 | vulnerable |


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

**HY4** -- one AI


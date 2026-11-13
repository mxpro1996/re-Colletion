# legacy-fakeSigner

The legacy PBL is blinded by the `sign_len` field from the MBN-header and never requires it to equal the RSA modulus length. 
When any certificate in the chain carries a public exponent of:```e = 3```\
It's sufficient to forge a signature over an arbitrary image with no private key at all.

Given the boot-related function table is reused during:```pbl -> sbl -> down_stream```\
the actually affected verification range is:

- `pbl -> sahara (eHostDL)` 
- `pbl -> sbl` 
- `pbl -> sbl -> Image` 


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

## Appendix
```c
MSM8974/8612 Bootrom laystack
f8002000 - app bootrom struct
fc000000-fc002c28 - RPM bootrom
fc004000-fc010000 - Modem bootrom
fc010000-fc02f800 - APP bootrom
fc02f800-fc02fa08 - RPM bootrom part2
fc100080 - bootrom error stack
There is a event log buffer at 0xFC102144, and a fatal error buffer at 0xFC102084 which can be interrogated using the sahara protocol.
# Refer from https://nlitsme.github.io/2019/11/msm-8974-bootrom/
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


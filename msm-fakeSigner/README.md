# legacy-fakeSigner
**Templated by AI, with the progress of interpreting, I will restruct it.**\
The legacy PBL is blinded by the signature length from the image header and never requires it to equal the RSA modulus length. \
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

## Scope and ethics

This is for security research on hardware you own or are authorised to test. The
tool does not help you obtain a certificate chain, bypass a fused device that has
no `e = 3` chain available, or defeat anti-rollback. It exists so that the flaw
can be verified, measured, and argued about with evidence rather than assertion.

## Credit
**Ryan** --
[`qualcomm_pbl_siglen_bug`](https://github.com/oscardagrach/qualcomm_pbl_siglen_bug)

**Tal Aloni** --
[`QualcommSecureBoot-SecondaryExecutableVerifier`](https://github.com/TalAloni/QualcommSecureBoot-SecondaryExecutableVerifier)

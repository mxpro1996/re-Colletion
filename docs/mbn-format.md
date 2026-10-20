# Legacy MBN format

Transcribed from TalAloni's
[`QualcommSecureBoot-SecondaryExecutableVerifier`](https://github.com/TalAloni/QualcommSecureBoot-SecondaryExecutableVerifier)
notes and confirmed against real MSM8612 firmware.

## Overall layout

```
header (0x50) || code || signature || certificate store
```

The header describes the rest in **memory** addresses; the file offset of a
memory address is

```
file_off = base + header_size + addr - load_addr
```

where `base` is 0 for a plain image and `0x2800` when `ImageType` is
`5A 43 0B 7D` (little-endian `0x7D0B435A`), which means the real header sits
further in and the leading bytes are preserved as-is.

## Header -- 80 bytes, little-endian

| off | field | notes |
|---|---|---|
| `0x00` | CodeWord | `D1 DC 4B 84` |
| `0x04` | Magic | `34 10 D7 73` (read as u32: `0x73D71034`) |
| `0x08` | ImageType | `0x0D` = eHostDL (Sahara programmer), `0x15` = SBL1, `5A 43 0B 7D` = header at `0x2800` |
| `0x14` | HeaderSize | always `0x50` in practice |
| `0x18` | LoadingAddress | where the body is loaded / executed |
| `0x1C` | BodySize | `CodeSize + SigLen + CertLen` |
| `0x20` | CodeSize | |
| `0x24` | SignatureAddress | memory address |
| `0x28` | SignatureLength | **attacker controlled; the bug lives here** |
| `0x2C` | CertificateStoreAddress | memory address |
| `0x30` | CertificateStoreLength | |

Invariants the PBL relies on, and that `mbn_fakesign.py verify` audits:

```
BodySize            == CodeSize + SignatureLength + CertificateStoreLength
SignatureAddress    == LoadingAddress + CodeSize
CertificateAddress  == SignatureAddress + SignatureLength
```

Getting these wrong is the single most common failure when transplanting code
between images, which is why `verify` re-derives them from disk rather than
trusting the signing run.

## Certificate store

A sequence of DER-encoded X.509 certificates (`30 82 ...`), optionally followed
by padding. The store must be copied **verbatim** -- re-joining the parsed certs
silently drops the trailing padding and changes the file, even though the padding
does not enter any digest.

The last certificate is the root. Its SHA-256 over the **entire DER** is compared
against `OEM_PK_HASH` in QFPROM.

## Image digest (TalAloni Note 3)

The PBL signs the **bare digest**, with no DigestInfo wrapper -- unlike the
certificate-chain signatures, which do carry one.

```
D1 = H(header || code)
D2 = H((SW_ID XOR 0x36 repeated) || D1)
D3 = H((HW_ID XOR 0x5c repeated) || D2)
```

`H` is SHA-1 or SHA-256, selected by the leaf certificate's subject OU
(`OU = 07 0000 SHA1`, `OU = 07 0001 SHA256`); with no OU entry the PBL falls back
to SHA-1.

Keys: `i_key = SW_ID` (XOR `0x36`, inner), `o_key = HW_ID` (XOR `0x5c`, outer),
both 8 bytes for MSM8x26 / MSM8x60 / MSM8974 and MSM8612. Other parts use
different constructions and lengths (8 or 64 bytes). The values the PBL feeds in
come from `tz_get_region_range()`, not from the certificate OU strings; the OU
strings tell you what to expect.

Consequences worth keeping in mind:

* the digest covers the **header**, so changing `SignatureLength` changes `D3`.
  This is what makes the `L` sweep possible: each candidate `L` is a different
  digest, and you need one whose last byte is odd.
* `--code-pad N` appends N zero bytes to the code, which nudges `D3` when every
  `L` in range yields an even digest.

## Practical notes

* Code length is rounded up to a multiple of 4 by `mbn_fakesign.py sign`.
* When transplanting, the load address matters: the code was linked for its
  original address. `sign` warns when the payload's own load address differs from
  the one being used, and `--load-addr` / `--load-addr-from` control it.
* Sahara image id for a programmer (`eHostDL`) is `0x0D`.

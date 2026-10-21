# Credits

This repository stands entirely on other people's work. The bug is not ours, the
format documentation is not ours, and the on-device protocol handling is not
ours. What is ours is the Python reimplementation, the forgery tool, and the
corrections listed at the end.

## Primary references

**Ryan Anthony / [@oscardagrach](https://github.com/oscardagrach)** --
[`qualcomm_pbl_siglen_bug`](https://github.com/oscardagrach/qualcomm_pbl_siglen_bug)

Wrote the clear, first-hand account of the flaw: that the PBL takes the signature
length from the attacker-controlled image header without requiring it to match
the modulus length, and that an `e = 3` leaf turns this into plain forgery. His
affected-silicon table (APQ8064 / APQ8084 / **MSM8974**, confirmed by
disassembling the boot ROMs), the argument for vendor awareness from key
rotation, and the guidance section are the backbone of this project's framing.
His description of the Saharan programmer as the practical attack surface is what
made the hardware validation worth attempting.

**Tal Aloni** --
[`QualcommSecureBoot-SecondaryExecutableVerifier`](https://github.com/TalAloni/QualcommSecureBoot-SecondaryExecutableVerifier)

Reverse-engineered and published the legacy MBN format that every tool here
parses: the 80-byte header layout, the `header || code || signature || cert
store` arrangement, the memory-address to file-offset arithmetic, the SHA-256
over the whole root certificate compared against `OEM_PK_HASH`, and -- most
importantly -- **Note 3**, the keyed image digest:

```
D1 = H(header || code)
D2 = H((SW_ID XOR 0x36 repeated) || D1)
D3 = H((HW_ID XOR 0x5c repeated) || D2)
```

with the explicit MSM8x26 / MSM8x60 / **MSM8974** case (`o_key = HW_ID`,
`i_key = SW_ID`, both 8 bytes). `image_digest()` in `mbn_fakesign.py` is a direct
transcription of that note, and it reproduces the real hardware result.

**[@Resery](https://github.com/Resery)** --
[`qualcomm_pbl_siglen_bug`](https://github.com/Resery/qualcomm_pbl_siglen_bug)

Mirror / companion fork of the analysis used during this work.

## Tooling

* **Hex-Rays IDA Pro**, driven through the IDA MCP server, for the disassembly
  that confirmed the flaw at instruction level in `msm8612.bootrom.bin`.
* **[@bkerler](https://github.com/bkerler)**'s `emmcdl` for the Sahara / firehose
  host-side tooling used to load images and read `OEM_PK_HASH` from real
  hardware.

## Analysis assistance

* **DeepSeek** -- for the long-form reasoning work: working through the
  `mod 2^k` root argument, pressure-testing the "why is 256 too wide" question,
  and sanity-checking the algebraic framing until it survived being written down.
* **HY4** -- for the reverse-engineering and verification work behind this
  repository: the IDA-level confirmation in `msm8612.bootrom.bin`, the Python
  model of `auth_verify_signature()`, the forgery tool, the `L` sweep against
  real firmware, and the on-device validation on MSM8612.

## Where this repository departs from the references

Recorded here rather than buried, because they are claims about other people's
descriptions:

1. **The digest keys come from `tz_get_region_range()`, not from the leaf
   certificate's OU fields.** The `[SW_ID]` / `[HW_ID]` OU strings do identify
   the target values, but the `0x36` / `0x5c` keys the PBL actually feeds into
   the digest are fetched from the fuse-derived region, and the PBL does not
   compare them. `auth_verify_signature()` reads only `entry[60..63]` from the
   leaf; `auth_match_cert_entry()`'s OU comparisons run only between a child
   certificate and its parent, never for the image being verified. A mismatch
   between a transplanted image's size and a chain's `SW_SIZE` therefore does
   not stop anything.
2. **The usable range of `L` is wider than usually stated, but with an
   alignment condition the published accounts miss.** Measured against real
   MSM8612 firmware: `L = 40 .. 85` (not 44..72), and the PBL enforces five
   `0xFF` padding bytes rather than PKCS#1's eight. However the signature-window
   checks tolerating any `L` is not the whole constraint:
   `CertStoreAddress = SigAddress + SigLength` and the cert store is parsed
   word-wise, so `L` that is not a multiple of 4 leaves the store unaligned and
   the device rejects the image before verification ever runs. Practically the
   band is **multiples of 4 in 44..84**. See `docs/vulnerability.md`.
3. **Cube roots modulo `2^(8L)` are one modexp, not a few hundred iterations of
   Hensel-style bit lifting.** `gcd(3, 2^(k-1)) = 1`, so cubing is a bijection on
   the odd residues and `s = T^d mod 2^k` with `d = 3^(-1) mod 2^(k-1)` closes
   it. Measured at ~0.2 ms.
4. **`n` is never truncated.** The published phrasing can read as though the
   256-byte modulus is shortened to `L` bytes. It is not: the PBL still reduces
   mod the full `n`. What is shortened is the number of result bytes that are
   inspected, which is a different and much weaker claim -- and the reason the
   attack works is that `s^3 < n` makes the reduction a no-op.

## Thanks

To anyone who has dumped a boot ROM and published what they found. Mask ROM does
not change, so a single careful disassembly is a permanent contribution.

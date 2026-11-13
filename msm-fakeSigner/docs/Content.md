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

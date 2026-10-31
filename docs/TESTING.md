# Testing the release candidate

## 1. Build and unit tests

```
dotnet build
dotnet test
```

All tests use fake keys and synthetic ROMs from `tests/fixtures`. If you change the reference logic, regenerate them:

```
python3 -I reference/python/gen_fixtures.py tests/fixtures      # needs: pip install cryptography
```

The generator also self-checks:
- decrypting gives back the original plaintext
- converted files pass all internal hash checks
- CCI → CIA → CCI preserves the partitions

## 2. Real-file checklist

Run these with the CLI (`dotnet run --project tools/NoIntrovert.Ctr.Cli -- ...`). Put your `boot9.bin`, `aes_keys.txt` and `seeddb.bin` in `%APPDATA%/NoIntrovert/keys`, or pass `--keys-dir`.

| # | Do | Expect |
|---|---|---|
| 1 | `keys` | "Retail ready: yes" and the files you expect listed |
| 2 | `info` on an encrypted cart dump | Correct title, product code, region, "7.x (0x25)" or "Original (0x2C)" crypto, trimmed/untrimmed state |
| 3 | `verify` an untouched cart dump `--dat "...(Encrypted).dat"` | `Verified`, or `VerifiedUntrimmed` if trimmed; all internal checks pass |
| 4 | `decrypt` that dump, then `verify` the output `--dat "...(Decrypted).dat"` | **Key question:** does it match No-Intro's decrypted DAT? Report the result either way |
| 5 | Boot the decrypted .3ds in Azahar | Runs |
| 6 | `convert --to cia` the cart dump, then install it in Azahar (and FBI on CFW if you like) | Installs and runs; the manual opens from the HOME Menu |
| 7 | `decrypt` an eShop CIA (including a seed-crypto title), then install it in Azahar | Runs |
| 8 | `convert --to cci` an eShop CIA, then boot it in Azahar | Runs; `verify` gives `IntactNotInDat` with a serial match |
| 9 | `convert --to cia --keep-encryption`, then `info` | NCCH still encrypted; installs in Azahar |
| 10 | `trim` / `untrim` a dump, then `verify` | Untrimmed output matches the DAT; trimmed output gives `VerifiedUntrimmed` |
| 11 | `rename roms/ --dat ...` | The dry-run plan looks right; then `--apply` |
| 12 | Try an update CIA and a DLC CIA with `convert --to cci` | Clear error. `decrypt` still works on them |

When something fails, send the CLI output plus `info` output for the input file. `info` prints the encryption type, content layout and any missing key name.

## 3. Things most likely to need attention

- **First compile.** The code was desk-checked, not compiled.
- **Decrypted-DAT matching.** See SPEC.md → Known limitations. If No-Intro's decrypted hashes differ, the likely cause is header bytes: NCSD 0x1100 copy flags, or which flags[7] bits get cleared. That is a one-line change in `NcchHeader.ApplyDecryptedFlags` / `CtrConverter.BuildDecryptedCciView`.
- **Console installs of CIAs made from carts.** These need a real certificate chain (`--certs-from some.cia`) and signature patches (Luma3DS).

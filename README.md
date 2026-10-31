# NoIntrovert.Formats — 3DS module (release candidate 0.9.0-rc1)

Pure C# (.NET 8, no NuGet dependencies) libraries for NoIntrovert:

| Project | What it does |
|---|---|
| `NoIntrovert.Core` | Streaming primitives: windowed/concatenated/overlay streams, random-access AES-CTR and AES-CBC, CRC32 + MD5/SHA-1/SHA-256 in one pass, atomic output files, progress. Reusable by the Switch and Xbox modules. |
| `NoIntrovert.Dat` | Console-agnostic DAT support: Logiqx XML and ClrMamePro parsing (No-Intro, Redump), hash/serial index, file-name templates, rename plans. |
| `NoIntrovert.Ctr` | Nintendo 3DS: key loading, decryption, CCI ↔ CIA conversion, trim/untrim, inspection, verification, renaming. |
| `ni3ds` (tools/) | Command-line harness so you can test everything without touching the UI. |
| Tests (tests/) | xUnit tests against synthetic fixtures whose expected outputs come from the Python reference implementation in `reference/python`. |

## Supported operations

| Input | Decrypt | → CCI (.3ds) | → CIA | Trim / untrim | Verify / rename |
|---|---|---|---|---|---|
| CCI (.3ds, .cci) | ✓ (stays trimmed/untrimmed) | ✓ decrypt + trim/pad | ✓ | ✓ | ✓ |
| CIA (.cia) | ✓ (title-key + NCCH layers) | ✓ game titles only | — | — | ✓ (TMD hashes) |
| CXI / CFA | ✓ | — | — | — | ✓ |

Encryption types: original (0x2C), 7.x (0x25), New 3DS 9.3 (0x18) and 9.6 (0x1B), seed crypto (seeddb), fixed zero key and fixed system key, CIA title-key (common keys 0–5).

Conversions decrypt by default (what Azahar and CFW want). `Decrypt = false` keeps NCCH encryption and only changes the container.

## Keys (nothing is bundled)

NoIntrovert ships no key material. Users provide their own files, which `KeyLocator` finds automatically:

| File | Provides | Where to get it |
|---|---|---|
| `boot9.bin` (or `boot9_prot.bin`) | KeyX 0x2C, KeyX 0x3D | Dumped from the user's own console with GodMode9 |
| `aes_keys.txt` | KeyX 0x25/0x18/0x1B, `common0`–`common5`, optional `fixedSystemKey` | The same file Azahar/Citra use |
| `seeddb.bin` | Seeds for seed-encrypted eShop titles | GodMode9 / Azahar |
| a CIA the user owns (optional) | CIA certificate chain for CCI→CIA | `CtrKeyStore.LoadCertificateChainFromCia` |

Search order: explicit folders → `%APPDATA%/NoIntrovert/keys` → Azahar and Citra `sysdata` folders (Windows, macOS, Linux/XDG) → `~/.3ds`, `~/3ds` → `keys/` next to the executable. `aes_keys.txt` can also carry `slot0x2CKeyX`/`slot0x3DKeyX` if the user has no boot9.

`boot9.bin` is checked against the SHA-256 of a retail dump. `KeyStoreStatus.IsRetailReady` tells the UI whether typical carts and eShop CIAs will work.

## Using it from NoIntrovert

Reference `src/NoIntrovert.Ctr` (it pulls in Core and Dat), or copy the three projects into your solution.

```csharp
using NoIntrovert.Core.IO;
using NoIntrovert.Ctr;
using NoIntrovert.Ctr.Keys;
using NoIntrovert.Ctr.Operations;
using NoIntrovert.Ctr.Verification;
using NoIntrovert.Dat;

// once at startup (and again if the user picks a key folder in settings)
var keys = KeyLocator.LoadDefault(out var keyErrors, extraDirectories: settings.KeyFolders);
KeyStoreStatus status = keys.GetStatus();          // show in a settings page

// convert / decrypt — safe to await on the UI thread; work runs on the thread pool
var converter = new CtrConverter(keys);
var progress = new Progress<OperationProgress>(p => { Progress = p.Fraction; Status = p.Stage; });
try
{
    CtrOperationResult r = await converter.ConvertAsync(inputPath, outputPath, CtrOutputFormat.Cia,
        new CtrConvertOptions { Decrypt = true }, progress, cancellationToken);
    foreach (var w in r.Warnings) Log(w);
}
catch (MissingKeyException ex) { ShowKeyHelp(ex.KeyName); }   // e.g. "common1", "seed:0004000000123400"
catch (CtrFormatException ex) { ShowError(ex.Message); }

// metadata for a file list / details pane (fast, no full read)
CtrFileInfo info = CtrInspector.Inspect(path, keys);   // title, title ID, product code, region, trimmed?, encryption

// verification + renaming against No-Intro DATs the user imported
var dats = DatIndex.FromFiles(settings.DatFiles);
var verifier = new CtrVerifier(keys, dats);
CtrVerifyReport report = await verifier.VerifyAsync(path, progress: progress, ct: cancellationToken);
// report.Verdict: Verified / VerifiedUntrimmed / IntactNotInDat / Unknown / Bad

var renamer = new CtrRenameService(verifier);
var (reports, plan) = await renamer.PlanAsync(files, new RenameOptions());   // dry run: show plan in a grid
var failures = RenamePlanner.Apply(plan);                                     // after the user confirms
```

Notes for the UI:
- Every operation writes to `output.nointrovert.tmp` and moves it into place only on success. Cancelling or failing leaves no partial file. Existing outputs are never overwritten unless `Overwrite = true`.
- Memory use is a few MiB regardless of file size.
- `Progress<T>` marshals to the UI thread. The library reports at most every 8 MiB.
- `CtrFile.Extensions` lists the extensions for file pickers. `CtrFile.Detect` sniffs content, so wrongly named files still work.

## Verification and renaming

- **Redump does not cover 3DS.** Use No-Intro's *Nintendo 3DS (Encrypted)*, *(Decrypted)* and digital DATs. The DAT layer itself is generic, so your Xbox (Redump) and Switch modules can share it.
- No-Intro hashes cartridges at full card size. Trimmed images are therefore also hashed as if padded with 0xFF (`VerifiedUntrimmed`) in the same single read.
- CIA→CCI conversions can never match a cart dump: the real card header, unique ID and InitialData are not in a CIA. They show up as `IntactNotInDat`, with internal hashes checked, and are still identified by product code (a `Serial` match) for renaming.
- Internal checks: the TMD SHA-256 of every CIA content, plus the NCCH extended header, logo, ExeFS superblock, every ExeFS file and the RomFS superblock.
- Rename templates support `{name}` (DAT game name), `{romname}`, `{title}`, `{longtitle}`, `{publisher}`, `{region}`, `{serial}`, `{titleid}`, `{version}`. Empty `()`/`[]` groups are dropped. Defaults: `{name}` when verified, `{title} ({region}) [{serial}]` otherwise.

## CLI harness

```
dotnet run --project tools/NoIntrovert.Ctr.Cli -- keys
dotnet run --project tools/NoIntrovert.Ctr.Cli -- info  "Game.3ds"
dotnet run --project tools/NoIntrovert.Ctr.Cli -- decrypt "Game.3ds"                 # -> Game.decrypted.3ds
dotnet run --project tools/NoIntrovert.Ctr.Cli -- convert "Game.3ds" --to cia
dotnet run --project tools/NoIntrovert.Ctr.Cli -- convert "Game.cia" --to cci --no-trim
dotnet run --project tools/NoIntrovert.Ctr.Cli -- verify  roms/ --dat "Nintendo - Nintendo 3DS (Encrypted).dat"
dotnet run --project tools/NoIntrovert.Ctr.Cli -- rename  roms/ --dat "...dat"        # dry run; add --apply
```

Run `ni3ds --help` for all options (`--keys-dir`, `--boot9`, `--aes-keys`, `--seeddb`, `--certs-from`, `--keep-encryption`, …).

## Build and test

```
dotnet build
dotnet test
```

The tests use fake keys and synthetic ROMs, so they run anywhere. See [docs/TESTING.md](docs/TESTING.md) for the real-file checklist and [docs/SPEC.md](docs/SPEC.md) for the exact byte layouts and design decisions.

## Status of this release candidate

This code was written and checked without access to a .NET SDK or to real 3DS files:
- The crypto and format logic was implemented twice: in C#, and as the Python reference, which was run and self-checked here. The xUnit tests assert that the C# output is byte-identical to the Python output.
- The C# was desk-checked but **not compiled**. Expect a handful of compile fixes on the first build.
- Behaviour on real dumps is unverified. Please run the checklist in docs/TESTING.md.

See docs/SPEC.md → "Known limitations" for what is intentionally out of scope (re-encryption, Z3DS compressed formats, DSiWare SRL internals, full RomFS IVFC verification).

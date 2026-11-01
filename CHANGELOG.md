# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); while the version is 0.x, minor versions may change the API.

## 0.10.0

### Added
- **CDN → CIA.** Pass a CDN folder (`tmd`, `cetk` and content files, or NUSspli-style names) to `ConvertAsync(..., CtrOutputFormat.Cia)` or `DecryptAsync`, or to the CLI's `convert` and `decrypt`. Contents are verified against the TMD before writing (`VerifyContents`), partial DLC is allowed, and ticket/TMD title-version mismatches are reported (`MatchTicketVersionToTmd` fixes them).
- **Packaging:** NuGet packages for `NoIntrovert.Core`, `NoIntrovert.Dat` and `NoIntrovert.Ctr`, targeting `net8.0` and `net10.0`, marked trim- and AOT-compatible, with source link and symbol packages.
- **`ni3ds` CLI:** installable as a `dotnet tool` (`NoIntrovert.Ctr.Cli`); standalone binaries for Windows, Linux and macOS (x64 and Arm64) come with each release.
- **CI:** tests on Windows, Linux and macOS (.NET 8 and .NET 10), plus a trimmed Android app build.
- Samples: `QuickStart` (the README's code) and `AndroidSmoke`.

### Fixed
- Region detection for DLC and update product codes with a suffix (e.g. `CTR-M-AXCE-00` now gives USA instead of unknown).
- CIA output (decrypting a CIA, CCI → CIA) reports progress while it hashes the result, instead of sitting at 100%. `MultiHasher.HashStream` takes an optional `ProgressTracker`.

### Changed
- Licensed under MIT.

## 0.9.0-rc1

First release candidate: decryption of CCI, CIA, CXI and CFA (all retail crypto types and seeds), CCI ↔ CIA conversion, trim/untrim, inspection, No-Intro DAT verification and renaming, and the `ni3ds` test harness.

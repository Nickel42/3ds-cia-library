# Contributing

Issues and pull requests are welcome.

## Building and testing

```bash
dotnet build
dotnet test
```

You need the .NET 10 SDK. Install the .NET 8 runtime too, to run the net8.0 tests. To build the Android sample:

```bash
dotnet workload install android
dotnet build samples/AndroidSmoke -c Release
```

## Guidelines

- **No keys or copyrighted files.** Never commit real keys, certificates, game files or CDN downloads, not even in tests. Tests use the fake keys and synthetic files in `tests/fixtures`.
- **Byte layouts:** changes to the formats should come with a test, and an entry in `docs/SPEC.md` when they change a layout or design decision.
- **Fixtures:** when output changes, update the Python reference (`reference/python`) and regenerate the fixtures, so the C# and Python implementations keep agreeing.
- **Warnings:** keep the build free of warnings, including the trim and AOT analyzers.

## Releasing

1. Update `CHANGELOG.md` and `VersionPrefix` in `Directory.Build.props`.
2. Tag the commit and push the tag:
   ```bash
   git tag v0.11.0
   git push origin v0.11.0
   ```
3. The **Release** workflow tests and packs everything with that version, builds the standalone `3ds` binaries, and creates a GitHub release with all of them attached.
4. If the repository has a `NUGET_API_KEY` secret (an API key from nuget.org scoped to the `3ds-cia-library*` packages), the workflow also pushes the packages to nuget.org.

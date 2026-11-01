// The examples from the README, as a program CI compiles on every change.
// usage: QuickStart <keys-folder> <file-or-cdn-folder> [output-folder] [dat-file]
using NoIntrovert.Core.IO;
using NoIntrovert.Ctr;
using NoIntrovert.Ctr.Keys;
using NoIntrovert.Ctr.Ncch;
using NoIntrovert.Ctr.Operations;
using NoIntrovert.Ctr.Verification;
using NoIntrovert.Dat;

if (args.Length < 2)
{
    Console.WriteLine("usage: QuickStart <keys-folder> <file-or-cdn-folder> [output-folder] [dat-file]");
    return 1;
}
string keysFolder = args[0], input = args[1];
string outputFolder = args.Length > 2 ? args[2] : Path.GetTempPath();
string? datFile = args.Length > 3 ? args[3] : null;

var keys = LoadKeys(keysFolder);
Inspect(input, keys);
await Convert(input, Path.Combine(outputFolder, "quickstart.cia"), keys);
await Verify(input, keys, datFile);
return 0;

// --- Load keys ----------------------------------------------------------------------------
static CtrKeyStore LoadKeys(string keysFolder)
{
    // Searches keysFolder first, then the Azahar/Citra sysdata folders and ~/.3ds.
    var keys = KeyLocator.LoadDefault(out var errors, extraDirectories: [keysFolder]);
    foreach (var e in errors) Console.WriteLine($"key file problem: {e}");

    KeyStoreStatus status = keys.GetStatus();
    Console.WriteLine($"Retail ready: {status.IsRetailReady}, seeds: {status.SeedCount}");
    return keys;
}

// --- Inspect a file (fast: reads headers only) ---------------------------------------------
static void Inspect(string path, CtrKeyStore keys)
{
    if (Directory.Exists(path)) return; // CDN folders are converted, not inspected
    CtrFileInfo info = CtrInspector.Inspect(path, keys);
    Console.WriteLine($"{info.Type}: {info.Titles?.ShortTitle} [{info.ProductCode}] {info.Region}, title {info.TitleId:X16} v{info.TitleVersion}");
    foreach (var ncch in info.Ncchs)
        Console.WriteLine($"  [{ncch.Index}] {ncch.Role}: {ncch.Crypto}{(ncch.CanDecrypt ? "" : $" (missing {ncch.MissingKey})")}");
}

// --- Convert / decrypt ---------------------------------------------------------------------
static async Task Convert(string input, string output, CtrKeyStore keys)
{
    var converter = new CtrConverter(keys);
    var progress = new Progress<OperationProgress>(p => Console.Write($"\r{p.Stage}: {p.Fraction:P0}   "));
    try
    {
        // A .3ds/.cci, a .cia or a CDN folder → a decrypted CIA. Use CtrOutputFormat.Cci for a .3ds.
        CtrOperationResult result = await converter.ConvertAsync(input, output, CtrOutputFormat.Cia,
            new CtrConvertOptions { Overwrite = true }, progress);
        Console.WriteLine($"\nWrote {result.OutputPath} (SHA-256 {result.OutputHashes?.Sha256})");
        foreach (var w in result.Warnings) Console.WriteLine($"  note: {w}");
    }
    catch (MissingKeyException ex)
    {
        Console.WriteLine($"\nMissing key: {ex.KeyName}");
    }
    catch (CtrFormatException ex)
    {
        Console.WriteLine($"\nCannot convert: {ex.Message}");
    }
}

// --- Verify against a No-Intro DAT -----------------------------------------------------------
static async Task Verify(string path, CtrKeyStore keys, string? datFile)
{
    if (Directory.Exists(path)) return;
    DatIndex? dats = datFile is null ? null : DatIndex.FromFiles([datFile]);
    var verifier = new CtrVerifier(keys, dats);
    CtrVerifyReport report = await verifier.VerifyAsync(path);
    Console.WriteLine($"{report.Verdict}: {report.Match.Rom?.Game.Name ?? "(not in DAT)"}, "
                      + $"{report.Checks.Count(c => c.Status == CheckStatus.Pass)} internal check(s) passed");
}

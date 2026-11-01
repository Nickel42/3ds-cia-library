// The examples from the README, as a program CI compiles on every change.
// usage: QuickStart <keys-folder> <file-or-cdn-folder> [output-folder]
using ThreeDsCiaLibrary;
using ThreeDsCiaLibrary.IO;
using ThreeDsCiaLibrary.Keys;
using ThreeDsCiaLibrary.Ncch;
using ThreeDsCiaLibrary.Operations;
using ThreeDsCiaLibrary.Verification;

if (args.Length < 2)
{
    Console.WriteLine("usage: QuickStart <keys-folder> <file-or-cdn-folder> [output-folder]");
    return 1;
}
string keysFolder = args[0], input = args[1];
string outputFolder = args.Length > 2 ? args[2] : Path.GetTempPath();
string output = Path.Combine(outputFolder, "quickstart.cia");

var keys = LoadKeys(keysFolder);
Inspect(input, keys);
if (await Convert(input, output, keys))
    await Verify(output, keys);
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
static async Task<bool> Convert(string input, string output, CtrKeyStore keys)
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
        return true;
    }
    catch (MissingKeyException ex)
    {
        Console.WriteLine($"\nMissing key: {ex.KeyName}");
    }
    catch (CtrFormatException ex)
    {
        Console.WriteLine($"\nCannot convert: {ex.Message}");
    }
    return false;
}

// --- Check the result's internal hashes ------------------------------------------------------
static async Task Verify(string path, CtrKeyStore keys)
{
    CtrVerifyReport report = await new CtrVerifier(keys).VerifyAsync(path);
    // report.Verdict: Intact / Unknown / Bad
    Console.WriteLine($"{report.Verdict}: {report.Checks.Count(c => c.Status == CheckStatus.Pass)} internal check(s) passed");
}

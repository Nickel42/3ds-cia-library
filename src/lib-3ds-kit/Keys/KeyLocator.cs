namespace Lib3dsKit.Keys;

/// <summary>Key files found on disk.</summary>
public sealed record KeyFileSet(string? Boot9Path, string? AesKeysPath, string? SeedDbPath)
{
    public bool Any => Boot9Path is not null || AesKeysPath is not null || SeedDbPath is not null;
}

/// <summary>
/// Finds boot9.bin / aes_keys.txt / seeddb.bin in the usual places: the folders you pass
/// (e.g. your app's own keys folder), Azahar and Citra "sysdata" folders, and pyctr's ~/.3ds.
/// The first folder containing each file wins.
/// </summary>
public static class KeyLocator
{
    public static readonly string[] Boot9Names = { "boot9.bin", "boot9_prot.bin" };
    public const string AesKeysName = "aes_keys.txt";
    public const string SeedDbName = "seeddb.bin";

    /// <summary>Candidate folders in priority order (existing or not).</summary>
    public static IReadOnlyList<string> CandidateDirectories(IEnumerable<string>? extra = null)
    {
        var dirs = new List<string>();
        if (extra is not null) dirs.AddRange(extra);

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string? xdgData = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        if (string.IsNullOrEmpty(xdgData) && !string.IsNullOrEmpty(home)) xdgData = Path.Combine(home, ".local", "share");

        if (OperatingSystem.IsWindows())
        {
            dirs.Add(Path.Combine(appData, "Azahar", "sysdata"));
            dirs.Add(Path.Combine(appData, "Citra", "sysdata"));
        }
        else if (OperatingSystem.IsMacOS())
        {
            string support = Path.Combine(home, "Library", "Application Support");
            dirs.Add(Path.Combine(support, "Azahar", "sysdata"));
            dirs.Add(Path.Combine(support, "Citra", "sysdata"));
        }
        if (!OperatingSystem.IsWindows() && !string.IsNullOrEmpty(xdgData))
        {
            dirs.Add(Path.Combine(xdgData, "azahar-emu", "sysdata"));
            dirs.Add(Path.Combine(xdgData, "citra-emu", "sysdata"));
        }
        if (!string.IsNullOrEmpty(home))
        {
            dirs.Add(Path.Combine(home, ".3ds"));
            dirs.Add(Path.Combine(home, "3ds"));
        }
        // portable installs next to the executable
        dirs.Add(Path.Combine(AppContext.BaseDirectory, "keys"));
        dirs.Add(Path.Combine(AppContext.BaseDirectory, "user", "sysdata"));
        return dirs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static KeyFileSet Find(IEnumerable<string>? extraDirectories = null)
    {
        string? boot9 = null, aes = null, seed = null;
        foreach (var dir in CandidateDirectories(extraDirectories))
        {
            if (!Directory.Exists(dir)) continue;
            boot9 ??= Boot9Names.Select(n => Path.Combine(dir, n)).FirstOrDefault(File.Exists);
            aes ??= File.Exists(Path.Combine(dir, AesKeysName)) ? Path.Combine(dir, AesKeysName) : null;
            seed ??= File.Exists(Path.Combine(dir, SeedDbName)) ? Path.Combine(dir, SeedDbName) : null;
        }
        return new KeyFileSet(boot9, aes, seed);
    }

    /// <summary>Find key files and load everything found into a new key store. Load errors are collected, not thrown.</summary>
    public static CtrKeyStore LoadDefault(out IReadOnlyList<string> errors, IEnumerable<string>? extraDirectories = null)
    {
        var ks = new CtrKeyStore();
        var errs = new List<string>();
        var files = Find(extraDirectories);
        TryLoad(errs, files.Boot9Path, p => ks.LoadBoot9File(p));
        TryLoad(errs, files.AesKeysPath, p => ks.LoadAesKeysFile(p));
        TryLoad(errs, files.SeedDbPath, p => ks.LoadSeedDbFile(p));
        errors = errs;
        return ks;
    }

    private static void TryLoad(List<string> errors, string? path, Action<string> load)
    {
        if (path is null) return;
        try { load(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CtrFormatException)
        {
            errors.Add($"{path}: {ex.Message}");
        }
    }
}

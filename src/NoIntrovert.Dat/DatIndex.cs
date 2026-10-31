using NoIntrovert.Core.Hashing;

namespace NoIntrovert.Dat;

/// <summary>
/// Hash and serial lookup across one or more DAT files.
/// Thread-safe for concurrent lookups once loading is done.
/// </summary>
public sealed class DatIndex
{
    private readonly Dictionary<string, List<DatRom>> _sha256 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<DatRom>> _sha1 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<DatRom>> _md5 = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Crc, long Size), List<DatRom>> _crcSize = new();
    private readonly Dictionary<string, List<DatRom>> _serial = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<DatFile> _dats = new();

    public IReadOnlyList<DatFile> Dats => _dats;
    public int RomCount { get; private set; }

    public static DatIndex FromFiles(IEnumerable<string> paths)
    {
        var idx = new DatIndex();
        foreach (var p in paths) idx.Add(DatParser.Load(p));
        return idx;
    }

    public void Add(DatFile dat)
    {
        _dats.Add(dat);
        foreach (var game in dat.Games)
        {
            foreach (var rom in game.Roms)
            {
                RomCount++;
                AddTo(_sha256, rom.Sha256, rom);
                AddTo(_sha1, rom.Sha1, rom);
                AddTo(_md5, rom.Md5, rom);
                if (rom.Crc32 is not null && rom.Size is long size)
                {
                    if (!_crcSize.TryGetValue((rom.Crc32, size), out var l)) _crcSize[(rom.Crc32, size)] = l = new();
                    l.Add(rom);
                }
                foreach (var key in SerialKeys(rom.Serial ?? game.Serial)) AddTo(_serial, key, rom);
            }
        }
    }

    private static void AddTo(Dictionary<string, List<DatRom>> d, string? key, DatRom rom)
    {
        if (key is null) return;
        if (!d.TryGetValue(key, out var l)) d[key] = l = new();
        if (!l.Contains(rom)) l.Add(rom);
    }

    /// <summary>
    /// Serial keys: the full normalized serial plus, for "XXX-Y-ABCD" style codes,
    /// the trailing game code ("ABCD") so CTR-P-ABCE matches a DAT that lists "ABCE".
    /// A DAT field may hold several serials separated by commas.
    /// </summary>
    public static IEnumerable<string> SerialKeys(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial)) yield break;
        foreach (var part in serial.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string s = part.ToUpperInvariant();
            yield return s;
            int dash = s.LastIndexOf('-');
            if (dash >= 0 && dash < s.Length - 1) yield return s[(dash + 1)..];
        }
    }

    /// <summary>Find the best DAT entry for a set of file hashes.</summary>
    public DatMatch Lookup(FileHashes h)
    {
        foreach (var (dict, key) in new[] { (_sha256, h.Sha256), (_sha1, h.Sha1), (_md5, h.Md5) })
        {
            if (key is null || !dict.TryGetValue(key, out var roms)) continue;
            var rom = roms.FirstOrDefault(r => r.Size is null || r.Size == h.Size);
            if (rom is not null) return new DatMatch(DatMatchKind.Hash, rom);
        }
        if (h.Crc32 is not null && _crcSize.TryGetValue((h.Crc32, h.Size), out var byCrc))
        {
            // only trust CRC when the DAT entry has no stronger hash we could have compared
            var rom = byCrc.FirstOrDefault(r =>
                (r.Sha1 is null || h.Sha1 is null) && (r.Sha256 is null || h.Sha256 is null) && (r.Md5 is null || h.Md5 is null));
            if (rom is not null) return new DatMatch(DatMatchKind.Crc32AndSize, rom);
        }
        return DatMatch.NoMatch;
    }

    /// <summary>All entries whose serial matches (used to name files that cannot be hash-verified).</summary>
    public IReadOnlyList<DatRom> LookupSerial(string? serial)
    {
        var result = new List<DatRom>();
        foreach (var key in SerialKeys(serial))
        {
            if (_serial.TryGetValue(key, out var roms))
                foreach (var r in roms)
                    if (!result.Contains(r)) result.Add(r);
            if (result.Count > 0) break; // prefer the most specific key
        }
        return result;
    }
}

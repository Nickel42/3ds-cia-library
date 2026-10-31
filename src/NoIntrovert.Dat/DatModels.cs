namespace NoIntrovert.Dat;

/// <summary>A parsed DAT file (Logiqx XML or ClrMamePro text).</summary>
public sealed class DatFile
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Version { get; init; } = "";
    public string? SourcePath { get; init; }
    public List<DatGame> Games { get; } = new();

    public override string ToString() => $"{Name} ({Version}, {Games.Count} games)";
}

/// <summary>One game/machine entry.</summary>
public sealed class DatGame
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Serial { get; init; }
    public string? Id { get; init; }
    public List<DatRom> Roms { get; } = new();

    /// <summary>The DAT this game came from (set by the parser).</summary>
    public DatFile? Dat { get; internal set; }

    public override string ToString() => Name;
}

/// <summary>One ROM/file entry. Hash strings are normalized to lowercase hex; missing ones are null.</summary>
public sealed class DatRom
{
    public string Name { get; init; } = "";
    public long? Size { get; init; }
    public string? Crc32 { get; init; }
    public string? Md5 { get; init; }
    public string? Sha1 { get; init; }
    public string? Sha256 { get; init; }
    public string? Serial { get; init; }
    public string? Status { get; init; }

    /// <summary>The game this ROM belongs to (set by the parser).</summary>
    public DatGame Game { get; internal set; } = null!;

    public override string ToString() => Name;
}

/// <summary>How a file was matched to a DAT entry.</summary>
public enum DatMatchKind
{
    None,
    /// <summary>SHA-256, SHA-1 or MD5 matched (size checked when the DAT has one).</summary>
    Hash,
    /// <summary>Only CRC32 + size matched (DAT without strong hashes).</summary>
    Crc32AndSize,
    /// <summary>No hash matched, but the serial / product code did.</summary>
    Serial,
}

/// <summary>Result of a DAT lookup.</summary>
public sealed record DatMatch(DatMatchKind Kind, DatRom? Rom, string? Note = null)
{
    public static readonly DatMatch NoMatch = new(DatMatchKind.None, null);
    public DatGame? Game => Rom?.Game;
    public bool IsVerified => Kind is DatMatchKind.Hash or DatMatchKind.Crc32AndSize;
}

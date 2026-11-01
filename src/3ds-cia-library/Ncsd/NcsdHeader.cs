using System.Buffers.Binary;

namespace ThreeDsCiaLibrary.Ncsd;

/// <summary>One NCSD partition (byte offsets).</summary>
public readonly record struct NcsdPartition(int Index, long Offset, long Size, ulong PartitionId)
{
    public static string IndexName(int index) => index switch
    {
        0 => "Game (CXI)",
        1 => "Manual (CFA)",
        2 => "Download Play child (CFA)",
        6 => "New3DS update data (CFA)",
        7 => "Update data (CFA)",
        _ => $"Partition {index}",
    };
}

/// <summary>Parsed NCSD (CCI / .3ds) header, from the first 0x4000 bytes of the image.</summary>
public sealed class NcsdHeader
{
    public const int MediaUnit = 0x200;
    public const int HeaderAreaSize = 0x4000;
    private readonly byte[] _raw;

    public NcsdHeader(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 0x200) throw new CtrFormatException("NCSD header is truncated.");
        if (!IsNcsd(raw)) throw new CtrFormatException("Missing NCSD magic.");
        _raw = raw[..Math.Min(raw.Length, HeaderAreaSize)].ToArray();
        var parts = new List<NcsdPartition>();
        for (int i = 0; i < 8; i++)
        {
            uint off = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x120 + i * 8));
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x124 + i * 8));
            if (size == 0) continue;
            parts.Add(new NcsdPartition(i, (long)off * MediaUnit, (long)size * MediaUnit,
                BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x190 + i * 8))));
        }
        Partitions = parts;
    }

    public static bool IsNcsd(ReadOnlySpan<byte> header) =>
        header.Length >= 0x104 && header[0x100] == 'N' && header[0x101] == 'C' && header[0x102] == 'S' && header[0x103] == 'D';

    public ReadOnlySpan<byte> Raw => _raw;

    /// <summary>Card size declared in the header (the untrimmed image size).</summary>
    public long MediaSize => (long)BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(0x104)) * MediaUnit;
    public ulong MediaId => BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x108));
    public IReadOnlyList<NcsdPartition> Partitions { get; }

    /// <summary>End of the last partition: the size of a trimmed image.</summary>
    public long UsedSize => Partitions.Count == 0 ? HeaderAreaSize : Partitions.Max(p => p.Offset + p.Size);

    public byte MediaType => _raw[0x188 + 5]; // 1 = CARD1, 2 = CARD2
    public ushort TitleVersion => _raw.Length >= 0x312 ? BinaryPrimitives.ReadUInt16LittleEndian(_raw.AsSpan(0x310)) : (ushort)0;

    public string MediaTypeName => MediaType switch
    {
        0 => "Inner device",
        1 => "CARD1",
        2 => "CARD2",
        3 => "Extended device",
        _ => $"Unknown ({MediaType})",
    };
}

/// <summary>Builds the 0x4000-byte NCSD header area for a CCI made from a CIA.</summary>
public static class NcsdBuilder
{
    /// <summary>Saves larger than this go on CARD2 (writable on-chip save area).</summary>
    public const ulong Card2SaveThreshold = 0x100000;

    /// <summary>Smallest standard card size (128 MiB doubled) that holds <paramref name="usedBytes"/>.</summary>
    public static long CardSizeFor(long usedBytes)
    {
        long size = 128L * 1024 * 1024;
        while (size < usedBytes) size *= 2;
        return size;
    }

    /// <param name="partitions">Index, size (bytes, media-unit aligned) and the first 0x200 bytes
    /// of the NCCH as it will be written, in ascending index order. Laid out back-to-back from 0x4000.</param>
    public static byte[] Build(ulong titleId, ushort titleVersion,
        IReadOnlyList<(int Index, long Size, byte[] NcchHeader)> partitions, ulong saveDataSize)
    {
        long used = NcsdHeader.HeaderAreaSize + partitions.Sum(p => p.Size);
        long card = CardSizeFor(used);
        var h = new byte[NcsdHeader.HeaderAreaSize];
        var s = h.AsSpan();
        "NCSD"u8.CopyTo(s[0x100..]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x104..], (uint)(card / NcsdHeader.MediaUnit));
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x108..], titleId);
        long off = NcsdHeader.HeaderAreaSize;
        byte[]? p0 = null;
        foreach (var (index, size, ncch) in partitions)
        {
            if (index is < 0 or > 7) throw new CtrFormatException($"Partition index {index} out of range.");
            if (size % NcsdHeader.MediaUnit != 0) throw new CtrFormatException("Partition size must be media-unit aligned.");
            BinaryPrimitives.WriteUInt32LittleEndian(s[(0x120 + index * 8)..], (uint)(off / NcsdHeader.MediaUnit));
            BinaryPrimitives.WriteUInt32LittleEndian(s[(0x124 + index * 8)..], (uint)(size / NcsdHeader.MediaUnit));
            ncch.AsSpan(0x108, 8).CopyTo(s[(0x190 + index * 8)..]);
            if (index == 0) p0 = ncch;
            off += size;
        }
        if (p0 is not null) p0.AsSpan(0x160, 0x20).CopyTo(s[0x160..]);
        bool card2 = saveDataSize > Card2SaveThreshold;
        s[0x188 + 4] = 1;                 // platform: CTR
        s[0x188 + 5] = card2 ? (byte)2 : (byte)1;
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x200..], card2 ? (uint)(used / NcsdHeader.MediaUnit) : 0xFFFFFFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x300..], (uint)Math.Min(used, uint.MaxValue));
        BinaryPrimitives.WriteUInt16LittleEndian(s[0x310..], titleVersion);
        // InitialData: seed = title id; title key blob unknown (zero); copy of NCCH header minus signature
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x1000..], titleId);
        if (p0 is not null) p0.AsSpan(0x100, 0x100).CopyTo(s[0x1100..]);
        s[0x1200..].Fill(0xFF);
        return h;
    }
}

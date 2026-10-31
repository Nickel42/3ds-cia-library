using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NoIntrovert.Ctr.Cia;

/// <summary>
/// Builds the small CIA sections (ticket, TMD, meta, archive header) for CIAs made from
/// cartridge images. Signatures are left zeroed ("fakesigned"): emulators accept them;
/// real consoles need signature patches (e.g. Luma3DS) to install them.
/// </summary>
public static class CiaBuilder
{
    public const int TicketSize = 0x350;
    public const int DefaultCertChainSize = 0xA00;
    public const int MetaSize = 0x3AC0;

    private static readonly byte[] TicketIssuer = "Root-CA00000003-XS0000000c"u8.ToArray();
    private static readonly byte[] TmdIssuer = "Root-CA00000003-CP0000000b"u8.ToArray();

    /// <summary>Content index header used by tickets that grant all contents.</summary>
    private static readonly byte[] TicketContentIndexHeader = Convert.FromHexString(
        "00010014000000AC000000140001001400000000000000280000000100000084000000840003000000000000");

    /// <summary>Ticket with a zero title key (contents are stored unencrypted at the CIA layer).</summary>
    public static byte[] BuildTicket(ulong titleId, ushort titleVersion)
    {
        var t = new byte[TicketSize];
        var s = t.AsSpan();
        BinaryPrimitives.WriteUInt32BigEndian(s, SignatureBlock.Rsa2048Sha256);
        const int d = 0x140;
        TicketIssuer.CopyTo(s[d..]);
        s[d + 0x7C] = 1; // ticket format version
        BinaryPrimitives.WriteUInt64BigEndian(s[(d + 0x9C)..], titleId);
        BinaryPrimitives.WriteUInt16BigEndian(s[(d + 0xA6)..], titleVersion);
        const int ci = d + 0x164;
        TicketContentIndexHeader.CopyTo(s[ci..]);
        s.Slice(ci + 0x2C, 0x80).Fill(0xFF);
        return t;
    }

    public static int TmdSize(int contentCount) => 0x140 + Tmd.HeaderSize + Tmd.InfoRecordsSize + Tmd.ChunkRecordSize * contentCount;

    /// <summary>TMD with one content-info record covering all chunks.</summary>
    public static byte[] BuildTmd(ulong titleId, ushort titleVersion, uint saveDataSize, IReadOnlyList<ContentChunk> chunks)
    {
        int n = chunks.Count;
        var t = new byte[TmdSize(n)];
        var s = t.AsSpan();
        BinaryPrimitives.WriteUInt32BigEndian(s, SignatureBlock.Rsa2048Sha256);
        const int h = 0x140;
        TmdIssuer.CopyTo(s[h..]);
        s[h + 0x40] = 1; // TMD format version
        BinaryPrimitives.WriteUInt64BigEndian(s[(h + 0x4C)..], titleId);
        BinaryPrimitives.WriteUInt32BigEndian(s[(h + 0x54)..], 0x40); // title type: CTR
        BinaryPrimitives.WriteUInt32LittleEndian(s[(h + 0x5A)..], saveDataSize);
        BinaryPrimitives.WriteUInt16BigEndian(s[(h + 0x9C)..], titleVersion);
        BinaryPrimitives.WriteUInt16BigEndian(s[(h + 0x9E)..], (ushort)n);
        int baseOff = h + Tmd.HeaderSize + Tmd.InfoRecordsSize;
        for (int i = 0; i < n; i++) chunks[i].WriteTo(s[(baseOff + i * Tmd.ChunkRecordSize)..]);
        const int info = h + Tmd.HeaderSize;
        BinaryPrimitives.WriteUInt16BigEndian(s[info..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(s[(info + 2)..], (ushort)n);
        SHA256.HashData(s.Slice(baseOff, Tmd.ChunkRecordSize * n)).CopyTo(t, info + 4);
        SHA256.HashData(s.Slice(info, Tmd.InfoRecordsSize)).CopyTo(t, h + 0xA4);
        return t;
    }

    /// <summary>
    /// Meta section: dependency list from the extended header, core version 2, and the SMDH icon.
    /// Returns an empty array when the extended header or icon are unavailable.
    /// </summary>
    public static byte[] BuildMeta(byte[]? exHeader, byte[]? icon)
    {
        if (exHeader is null || icon is null) return Array.Empty<byte>();
        var m = new byte[MetaSize];
        exHeader.AsSpan(0x40, 0x180).CopyTo(m);
        BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(0x300), 2);
        icon.AsSpan(0, Math.Min(icon.Length, 0x36C0)).CopyTo(m.AsSpan(0x400));
        return m;
    }

    /// <summary>The 0x2020-byte archive header.</summary>
    public static byte[] BuildArchiveHeader(int certSize, int ticketSize, int tmdSize, int metaSize,
        ulong contentSize, IEnumerable<int> contentIndexes)
    {
        var h = new byte[CiaFile.ArchiveHeaderSize];
        var s = h.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s, CiaFile.ArchiveHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[8..], (uint)certSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[0xC..], (uint)ticketSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x10..], (uint)tmdSize);
        BinaryPrimitives.WriteUInt32LittleEndian(s[0x14..], (uint)metaSize);
        BinaryPrimitives.WriteUInt64LittleEndian(s[0x18..], contentSize);
        foreach (int idx in contentIndexes) h[0x20 + (idx >> 3)] |= (byte)(0x80 >> (idx & 7));
        return h;
    }
}

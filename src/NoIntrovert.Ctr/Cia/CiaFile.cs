using System.Buffers.Binary;
using System.Security.Cryptography;
using NoIntrovert.Core.Crypto;
using NoIntrovert.Core.IO;
using NoIntrovert.Ctr.Keys;

namespace NoIntrovert.Ctr.Cia;

/// <summary>Signature block sizes shared by tickets, TMDs and certificates.</summary>
public static class SignatureBlock
{
    public const uint Rsa2048Sha256 = 0x00010004;

    /// <summary>Size of type + signature + padding, i.e. where the signed body starts.</summary>
    public static int Size(ReadOnlySpan<byte> blob)
    {
        uint type = BinaryPrimitives.ReadUInt32BigEndian(blob);
        return type switch
        {
            0x00010000 or 0x00010003 => 4 + 0x200 + 0x3C,
            0x00010001 or 0x00010004 => 4 + 0x100 + 0x3C,
            0x00010002 or 0x00010005 => 4 + 0x3C + 0x40,
            _ => throw new CtrFormatException($"Unknown signature type 0x{type:X8}."),
        };
    }
}

/// <summary>A ticket (eTicket). Holds the encrypted title key.</summary>
public sealed class Ticket
{
    public Ticket(byte[] raw)
    {
        Raw = raw;
        BodyOffset = SignatureBlock.Size(raw);
        if (raw.Length < BodyOffset + 0x164) throw new CtrFormatException("Ticket is truncated.");
    }

    public byte[] Raw { get; }
    public int BodyOffset { get; }
    public ReadOnlySpan<byte> EncryptedTitleKey => Raw.AsSpan(BodyOffset + 0x7F, 16);
    public ulong TicketId => BinaryPrimitives.ReadUInt64BigEndian(Raw.AsSpan(BodyOffset + 0x90));
    public ulong TitleId => BinaryPrimitives.ReadUInt64BigEndian(Raw.AsSpan(BodyOffset + 0x9C));
    public ushort TitleVersion => BinaryPrimitives.ReadUInt16BigEndian(Raw.AsSpan(BodyOffset + 0xA6));
    public byte CommonKeyIndex => Raw[BodyOffset + 0xB1];

    /// <summary>Decrypt the title key: AES-CBC with the common key, IV = title ID (big-endian) + 8 zero bytes.</summary>
    public byte[] DecryptTitleKey(CtrKeyStore keys)
    {
        Span<byte> iv = stackalloc byte[16];
        Raw.AsSpan(BodyOffset + 0x9C, 8).CopyTo(iv);
        return AesUtil.CbcDecrypt(keys.GetCommonKey(CommonKeyIndex), iv, EncryptedTitleKey);
    }
}

/// <summary>A TMD content chunk record.</summary>
public sealed record ContentChunk(uint Id, ushort Index, ushort Type, ulong Size, byte[] Hash)
{
    public const ushort TypeEncrypted = 0x0001;
    public bool IsEncrypted => (Type & TypeEncrypted) != 0;

    public void WriteTo(Span<byte> dest)
    {
        BinaryPrimitives.WriteUInt32BigEndian(dest, Id);
        BinaryPrimitives.WriteUInt16BigEndian(dest[4..], Index);
        BinaryPrimitives.WriteUInt16BigEndian(dest[6..], Type);
        BinaryPrimitives.WriteUInt64BigEndian(dest[8..], Size);
        Hash.AsSpan(0, 32).CopyTo(dest[16..]);
    }
}

/// <summary>Title metadata.</summary>
public sealed class Tmd
{
    public const int HeaderSize = 0xC4;
    public const int InfoRecordsSize = 0x900;
    public const int ChunkRecordSize = 0x30;

    public Tmd(byte[] raw)
    {
        Raw = raw;
        HeaderOffset = SignatureBlock.Size(raw);
        if (raw.Length < HeaderOffset + HeaderSize + InfoRecordsSize) throw new CtrFormatException("TMD is truncated.");
        int count = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(HeaderOffset + 0x9E));
        int baseOff = ChunkBase;
        if (raw.Length < baseOff + count * ChunkRecordSize) throw new CtrFormatException("TMD content records are truncated.");
        var chunks = new List<ContentChunk>(count);
        for (int i = 0; i < count; i++)
        {
            var r = raw.AsSpan(baseOff + i * ChunkRecordSize, ChunkRecordSize);
            chunks.Add(new ContentChunk(
                BinaryPrimitives.ReadUInt32BigEndian(r),
                BinaryPrimitives.ReadUInt16BigEndian(r[4..]),
                BinaryPrimitives.ReadUInt16BigEndian(r[6..]),
                BinaryPrimitives.ReadUInt64BigEndian(r[8..]),
                r.Slice(16, 32).ToArray()));
        }
        Chunks = chunks;
    }

    public byte[] Raw { get; }
    public int HeaderOffset { get; }
    private int ChunkBase => HeaderOffset + HeaderSize + InfoRecordsSize;
    public IReadOnlyList<ContentChunk> Chunks { get; }
    public ulong TitleId => BinaryPrimitives.ReadUInt64BigEndian(Raw.AsSpan(HeaderOffset + 0x4C));
    public uint SaveDataSize => BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(HeaderOffset + 0x5A));
    public ushort TitleVersion => BinaryPrimitives.ReadUInt16BigEndian(Raw.AsSpan(HeaderOffset + 0x9C));

    /// <summary>
    /// Copy of this TMD with replaced chunk records and recomputed content-info hashes
    /// (signature left as-is, so the result is "fakesigned").
    /// </summary>
    public byte[] Rebuild(IReadOnlyList<ContentChunk> chunks)
    {
        if (chunks.Count != Chunks.Count) throw new ArgumentException("Chunk count must not change.");
        var o = (byte[])Raw.Clone();
        int ho = HeaderOffset, baseOff = ChunkBase, info = ho + HeaderSize;
        for (int i = 0; i < chunks.Count; i++) chunks[i].WriteTo(o.AsSpan(baseOff + i * ChunkRecordSize));
        for (int r = 0; r < 64; r++)
        {
            int ro = info + r * 0x24;
            int idxOff = BinaryPrimitives.ReadUInt16BigEndian(o.AsSpan(ro));
            int cmdCount = BinaryPrimitives.ReadUInt16BigEndian(o.AsSpan(ro + 2));
            if (cmdCount == 0) continue;
            SHA256.HashData(o.AsSpan(baseOff + idxOff * ChunkRecordSize, cmdCount * ChunkRecordSize)).CopyTo(o, ro + 4);
        }
        SHA256.HashData(o.AsSpan(info, InfoRecordsSize)).CopyTo(o, ho + 0xA4);
        return o;
    }
}

/// <summary>A content present in a CIA, with its absolute offset in the CIA file.</summary>
public readonly record struct CiaContent(ContentChunk Chunk, long Offset);

/// <summary>
/// CIA (CTR Importable Archive) reader. Small sections (certificates, ticket, TMD, meta)
/// are loaded into memory; contents are exposed as streams.
/// </summary>
public sealed class CiaFile
{
    public const int ArchiveHeaderSize = 0x2020;
    public const int Alignment = 64;

    private CiaFile() { }

    public uint HeaderSize { get; private init; }
    public ushort Type { get; private init; }
    public ushort FormatVersion { get; private init; }
    public byte[] CertificateChain { get; private init; } = Array.Empty<byte>();
    public Ticket Ticket { get; private init; } = null!;
    public Tmd Tmd { get; private init; } = null!;
    public byte[] Meta { get; private init; } = Array.Empty<byte>();
    public ulong ContentSize { get; private init; }
    public byte[] ContentIndexBitmap { get; private init; } = Array.Empty<byte>();
    public long TicketOffset { get; private init; }
    public long TmdOffset { get; private init; }
    public long ContentOffset { get; private init; }
    public long MetaOffset { get; private init; }
    public IReadOnlyList<CiaContent> Contents { get; private init; } = Array.Empty<CiaContent>();

    public ulong TitleId => Tmd.TitleId;

    public static long Align(long v) => (v + Alignment - 1) / Alignment * Alignment;

    public static bool LooksLikeCia(ReadOnlySpan<byte> header) =>
        header.Length >= 0x20 && BinaryPrimitives.ReadUInt32LittleEndian(header) == ArchiveHeaderSize
        && BinaryPrimitives.ReadUInt16LittleEndian(header[4..]) == 0;

    public static CiaFile Read(Stream s)
    {
        var hdr = VirtualStream.ReadBytesAt(s, 0, ArchiveHeaderSize);
        if (!LooksLikeCia(hdr)) throw new CtrFormatException("Not a CIA file (bad archive header).");
        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr);
        uint certSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(8));
        uint ticketSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(0xC));
        uint tmdSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(0x10));
        uint metaSize = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(0x14));
        ulong contentSize = BinaryPrimitives.ReadUInt64LittleEndian(hdr.AsSpan(0x18));
        if (certSize > 0x100000 || ticketSize > 0x100000 || tmdSize > 0x1000000 || metaSize > 0x1000000)
            throw new CtrFormatException("CIA section sizes are implausible.");

        long certOff = Align(headerSize);
        long ticketOff = Align(certOff + certSize);
        long tmdOff = Align(ticketOff + ticketSize);
        long contentOff = Align(tmdOff + tmdSize);
        long metaOff = Align(contentOff + (long)contentSize);
        if (contentOff + (long)contentSize > s.Length)
            throw new CtrFormatException("CIA is truncated (content section extends past end of file).");

        var tmd = new Tmd(VirtualStream.ReadBytesAt(s, tmdOff, (int)tmdSize));
        byte[] bitmap = hdr.AsSpan(0x20, 0x2000).ToArray();
        var contents = new List<CiaContent>();
        long p = contentOff;
        foreach (var c in tmd.Chunks)
        {
            if ((bitmap[c.Index >> 3] & (0x80 >> (c.Index & 7))) == 0) continue;
            contents.Add(new CiaContent(c, p));
            p += (long)c.Size;
        }
        return new CiaFile
        {
            HeaderSize = headerSize,
            Type = BinaryPrimitives.ReadUInt16LittleEndian(hdr.AsSpan(4)),
            FormatVersion = BinaryPrimitives.ReadUInt16LittleEndian(hdr.AsSpan(6)),
            CertificateChain = VirtualStream.ReadBytesAt(s, certOff, (int)certSize),
            Ticket = new Ticket(VirtualStream.ReadBytesAt(s, ticketOff, (int)ticketSize)),
            Tmd = tmd,
            Meta = metaSize > 0 && metaOff + metaSize <= s.Length ? VirtualStream.ReadBytesAt(s, metaOff, (int)metaSize) : Array.Empty<byte>(),
            ContentSize = contentSize,
            ContentIndexBitmap = bitmap,
            TicketOffset = ticketOff,
            TmdOffset = tmdOff,
            ContentOffset = contentOff,
            MetaOffset = metaOff,
            Contents = contents,
        };
    }

    /// <summary>
    /// Stream of a content with the CIA-layer (title key, AES-CBC) encryption removed.
    /// The NCCH inside may still be NCCH-encrypted. IV = content index (big-endian u16) + 14 zero bytes.
    /// </summary>
    public Stream OpenContent(Stream cia, CiaContent content, CtrKeyStore keys, byte[]? titleKey = null)
    {
        var raw = new SubStream(cia, content.Offset, (long)content.Chunk.Size);
        if (!content.Chunk.IsEncrypted) return raw;
        titleKey ??= Ticket.DecryptTitleKey(keys);
        var iv = new byte[16];
        BinaryPrimitives.WriteUInt16BigEndian(iv, content.Chunk.Index);
        return new AesCbcDecryptStream(raw, titleKey, iv);
    }
}

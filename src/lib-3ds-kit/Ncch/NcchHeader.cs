using System.Buffers.Binary;
using System.Text;

namespace Lib3dsKit.Ncch;

/// <summary>NCCH flags[7] bits.</summary>
[Flags]
public enum NcchFlags7 : byte
{
    None = 0,
    FixedCryptoKey = 0x01,
    NoMountRomFs = 0x02,
    NoCrypto = 0x04,
    UsesSeed = 0x20,
}

public enum NcchContentType
{
    Unspecified = 0,
    SystemUpdate = 1,
    Manual = 2,
    DownloadPlayChild = 3,
    Trial = 4,
    ExtendedSystemUpdate = 5,
}

/// <summary>Parsed 0x200-byte NCCH header (CXI or CFA). All region values are in bytes.</summary>
public sealed class NcchHeader
{
    public const int Size = 0x200;
    public const int FlagsOffset = 0x188;
    private readonly byte[] _raw;

    public NcchHeader(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < Size) throw new CtrFormatException("NCCH header is truncated.");
        _raw = raw[..Size].ToArray();
        if (!IsNcch(_raw)) throw new CtrFormatException("Missing NCCH magic.");
    }

    public static bool IsNcch(ReadOnlySpan<byte> header) =>
        header.Length >= 0x104 && header[0x100] == 'N' && header[0x101] == 'C' && header[0x102] == 'C' && header[0x103] == 'H';

    public ReadOnlySpan<byte> Raw => _raw;
    public byte[] ToArray() => (byte[])_raw.Clone();

    /// <summary>First 16 bytes of the RSA signature; used as KeyY.</summary>
    public ReadOnlySpan<byte> KeyY => _raw.AsSpan(0, 16);

    private uint U32(int off) => BinaryPrimitives.ReadUInt32LittleEndian(_raw.AsSpan(off));

    public long MediaUnit => 0x200L << _raw[FlagsOffset + 6];
    public long ContentSize => U32(0x104) * MediaUnit;
    public ulong PartitionId => BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x108));
    public string MakerCode => Encoding.ASCII.GetString(_raw, 0x110, 2).TrimEnd('\0');
    public ushort Version => BinaryPrimitives.ReadUInt16LittleEndian(_raw.AsSpan(0x112));
    public ReadOnlySpan<byte> SeedCheck => _raw.AsSpan(0x114, 4);
    public ulong ProgramId => BinaryPrimitives.ReadUInt64LittleEndian(_raw.AsSpan(0x118));
    public ReadOnlySpan<byte> ProgramIdBytes => _raw.AsSpan(0x118, 8);
    public ReadOnlySpan<byte> LogoHash => _raw.AsSpan(0x130, 0x20);
    public string ProductCode => Encoding.ASCII.GetString(_raw, 0x150, 0x10).Split('\0')[0];
    public ReadOnlySpan<byte> ExHeaderHash => _raw.AsSpan(0x160, 0x20);
    public uint ExHeaderSize => U32(0x180);

    public byte CryptoMethod => _raw[FlagsOffset + 3];
    public byte ContentPlatform => _raw[FlagsOffset + 4];
    public byte ContentTypeFlags => _raw[FlagsOffset + 5];
    public NcchFlags7 Flags7 => (NcchFlags7)_raw[FlagsOffset + 7];

    public bool IsExecutable => (ContentTypeFlags & 0x02) != 0;
    public NcchContentType ContentType => (NcchContentType)(ContentTypeFlags >> 2);
    public bool NoCrypto => Flags7.HasFlag(NcchFlags7.NoCrypto);
    public bool FixedCryptoKey => Flags7.HasFlag(NcchFlags7.FixedCryptoKey);
    public bool UsesSeed => Flags7.HasFlag(NcchFlags7.UsesSeed);
    public bool HasExHeader => ExHeaderSize == 0x400;

    /// <summary>System titles (category bit 0x10) use the fixed system key instead of the zero key.</summary>
    public bool IsSystemTitle => (ProgramId & (0x10UL << 32)) != 0;

    private (long Offset, long Size) Region(int off) => (U32(off) * MediaUnit, U32(off + 4) * MediaUnit);

    public (long Offset, long Size) PlainRegion => Region(0x190);
    public (long Offset, long Size) LogoRegion => Region(0x198);
    public (long Offset, long Size) ExeFs => Region(0x1A0);
    public long ExeFsHashRegionSize => U32(0x1A8) * MediaUnit;
    public (long Offset, long Size) RomFs => Region(0x1B0);
    public long RomFsHashRegionSize => U32(0x1B8) * MediaUnit;
    public ReadOnlySpan<byte> ExeFsSuperblockHash => _raw.AsSpan(0x1C0, 0x20);
    public ReadOnlySpan<byte> RomFsSuperblockHash => _raw.AsSpan(0x1E0, 0x20);

    /// <summary>Human-readable description of the encryption in use.</summary>
    public string CryptoDescription
    {
        get
        {
            if (NoCrypto) return "Decrypted (NoCrypto)";
            if (FixedCryptoKey) return IsSystemTitle ? "Fixed system key" : "Fixed zero key";
            string method = CryptoMethod switch
            {
                0x00 => "Original (0x2C)",
                0x01 => "7.x (0x25)",
                0x0A => "New3DS 9.3 (0x18)",
                0x0B => "New3DS 9.6 (0x1B)",
                _ => $"Unknown (0x{CryptoMethod:X2})",
            };
            return UsesSeed ? method + " + seed" : method;
        }
    }

    /// <summary>Flags as they must look after decryption (crypto method 0, seed/fixed cleared, NoCrypto set).</summary>
    public static void ApplyDecryptedFlags(Span<byte> flags8)
    {
        flags8[3] = 0;
        flags8[7] = (byte)((flags8[7] & ~(byte)(NcchFlags7.FixedCryptoKey | NcchFlags7.UsesSeed)) | (byte)NcchFlags7.NoCrypto);
    }
}

/// <summary>One ExeFS file table entry. Offset is relative to the end of the 0x200-byte ExeFS header.</summary>
public readonly record struct ExeFsEntry(string Name, uint Offset, uint Size, int Index)
{
    /// <summary>Parse the 10-entry file table of a (decrypted) ExeFS header.</summary>
    public static List<ExeFsEntry> ParseTable(ReadOnlySpan<byte> exefsHeader)
    {
        var list = new List<ExeFsEntry>();
        for (int i = 0; i < 10; i++)
        {
            var e = exefsHeader.Slice(i * 16, 16);
            int len = e[..8].IndexOf((byte)0);
            if (len < 0) len = 8;
            string name = Encoding.ASCII.GetString(e[..len]);
            uint off = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
            if (name.Length > 0 && size > 0) list.Add(new ExeFsEntry(name, off, size, i));
        }
        return list;
    }

    /// <summary>SHA-256 of entry <paramref name="index"/> is stored in reverse order at the end of the header.</summary>
    public static ReadOnlySpan<byte> StoredHash(ReadOnlySpan<byte> exefsHeader, int index) =>
        exefsHeader.Slice(0x200 - (index + 1) * 0x20, 0x20);
}

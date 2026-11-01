using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Lib3dsKit.IO;

namespace Lib3dsKit.Ncch;

/// <summary>Title strings from an SMDH icon file.</summary>
public sealed record SmdhInfo(string ShortTitle, string LongTitle, string Publisher, uint RegionLockout)
{
    public const int Size = 0x36C0;
    private static readonly string[] Languages =
        { "Japanese", "English", "French", "German", "Italian", "Spanish", "SimplifiedChinese",
          "Korean", "Dutch", "Portuguese", "Russian", "TraditionalChinese" };

    /// <summary>Parse English titles (falling back to the first non-empty language).</summary>
    public static SmdhInfo? Parse(ReadOnlySpan<byte> smdh)
    {
        if (smdh.Length < 0x2040 || smdh[0] != 'S' || smdh[1] != 'M' || smdh[2] != 'D' || smdh[3] != 'H') return null;
        byte[] data = smdh[..0x2040].ToArray(); // spans cannot be captured by local functions
        string Str(int lang, int off, int len)
        {
            var s = Encoding.Unicode.GetString(data, 8 + lang * 0x200 + off, len);
            int z = s.IndexOf('\0');
            return (z >= 0 ? s[..z] : s).Replace('\n', ' ').Trim();
        }
        int pick = 1; // English
        if (Str(pick, 0, 0x80).Length == 0)
        {
            for (int l = 0; l < Languages.Length; l++)
                if (Str(l, 0, 0x80).Length > 0) { pick = l; break; }
        }
        uint region = BinaryPrimitives.ReadUInt32LittleEndian(smdh.Slice(0x2018, 4));
        return new SmdhInfo(Str(pick, 0, 0x80), Str(pick, 0x80, 0x100), Str(pick, 0x180, 0x80), region);
    }
}

public enum CheckStatus { Pass, Fail, Skipped }

/// <summary>Result of one integrity check.</summary>
public sealed record IntegrityCheck(string Name, CheckStatus Status, string? Detail = null)
{
    public override string ToString() => Detail is null ? $"{Name}: {Status}" : $"{Name}: {Status} ({Detail})";
}

/// <summary>Helpers that read structured data out of a decrypted NCCH view.</summary>
public static class NcchContent
{
    /// <summary>Read an ExeFS file by name from a decrypted (or NoCrypto) NCCH stream.</summary>
    public static byte[]? ReadExeFsFile(Stream plainNcch, NcchHeader header, string name)
    {
        var (off, size) = header.ExeFs;
        if (size < 0x200) return null;
        var table = VirtualStream.ReadBytesAt(plainNcch, off, 0x200);
        foreach (var e in ExeFsEntry.ParseTable(table))
        {
            if (e.Name != name) continue;
            long fileOff = off + 0x200 + e.Offset;
            if (fileOff + e.Size > plainNcch.Length) return null;
            return VirtualStream.ReadBytesAt(plainNcch, fileOff, (int)e.Size);
        }
        return null;
    }

    public static SmdhInfo? ReadSmdh(Stream plainNcch, NcchHeader header)
    {
        var icon = ReadExeFsFile(plainNcch, header, "icon");
        return icon is null ? null : SmdhInfo.Parse(icon);
    }

    /// <summary>The 0x400-byte extended header (SCI + ACI), or null for CFAs.</summary>
    public static byte[]? ReadExHeader(Stream plainNcch, NcchHeader header) =>
        header.HasExHeader ? VirtualStream.ReadBytesAt(plainNcch, 0x200, 0x400) : null;

    /// <summary>Save data size from the extended header (0 for CFAs).</summary>
    public static ulong ReadSaveDataSize(Stream plainNcch, NcchHeader header)
    {
        var exh = ReadExHeader(plainNcch, header);
        return exh is null ? 0 : BinaryPrimitives.ReadUInt64LittleEndian(exh.AsSpan(0x1C0));
    }

    /// <summary>
    /// Verify the hashes stored in the NCCH header: extended header, logo, ExeFS superblock,
    /// every ExeFS file and the RomFS superblock. Requires a decrypted view.
    /// </summary>
    public static List<IntegrityCheck> Verify(Stream plainNcch, NcchHeader header, string prefix = "")
    {
        var checks = new List<IntegrityCheck>();
        bool HashOk(long off, long len, ReadOnlySpan<byte> expected)
        {
            if (off + len > plainNcch.Length) return false;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            plainNcch.Position = off;
            var buf = new byte[Math.Min(len, 4 * 1024 * 1024)];
            long left = len;
            while (left > 0)
            {
                int n = (int)Math.Min(buf.Length, left);
                plainNcch.ReadExactly(buf, 0, n);
                sha.AppendData(buf, 0, n);
                left -= n;
            }
            return sha.GetHashAndReset().AsSpan().SequenceEqual(expected);
        }
        IntegrityCheck Check(string name, bool ok) => new(prefix + name, ok ? CheckStatus.Pass : CheckStatus.Fail);

        if (header.HasExHeader)
            checks.Add(Check("ExHeader hash", HashOk(0x200, 0x400, header.ExHeaderHash)));
        var (logoOff, logoSize) = header.LogoRegion;
        if (logoSize > 0 && header.LogoHash.IndexOfAnyExcept((byte)0) >= 0)
            checks.Add(Check("Logo hash", HashOk(logoOff, logoSize, header.LogoHash)));
        var (exefsOff, exefsSize) = header.ExeFs;
        if (exefsSize > 0)
        {
            checks.Add(Check("ExeFS superblock hash", HashOk(exefsOff, header.ExeFsHashRegionSize, header.ExeFsSuperblockHash)));
            if (exefsOff + 0x200 <= plainNcch.Length)
            {
                var table = VirtualStream.ReadBytesAt(plainNcch, exefsOff, 0x200);
                foreach (var e in ExeFsEntry.ParseTable(table))
                    checks.Add(Check($"ExeFS '{e.Name}' hash",
                        HashOk(exefsOff + 0x200 + e.Offset, e.Size, ExeFsEntry.StoredHash(table, e.Index))));
            }
        }
        var (romfsOff, romfsSize) = header.RomFs;
        if (romfsSize > 0)
            checks.Add(Check("RomFS superblock hash", HashOk(romfsOff, header.RomFsHashRegionSize, header.RomFsSuperblockHash)));
        return checks;
    }
}

using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Lib3dsKit.Keys;

/// <summary>The 3DS AES engine's hardware key scrambler.</summary>
public static class KeyScrambler
{
    private static readonly UInt128 C = new(0x1FF9E9AAC5FE0408UL, 0x024591DC5D52768AUL);

    /// <summary>NormalKey = ROL128((ROL128(KeyX, 2) XOR KeyY) + C, 87), all values big-endian.</summary>
    public static byte[] Generate(ReadOnlySpan<byte> keyX, ReadOnlySpan<byte> keyY)
    {
        if (keyX.Length != 16 || keyY.Length != 16) throw new ArgumentException("Keys must be 16 bytes.");
        UInt128 x = ToUInt128(keyX), y = ToUInt128(keyY);
        UInt128 n = UInt128.RotateLeft(unchecked((UInt128.RotateLeft(x, 2) ^ y) + C), 87);
        var result = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(result, (ulong)(n >> 64));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(8), (ulong)n);
        return result;
    }

    private static UInt128 ToUInt128(ReadOnlySpan<byte> b) =>
        new(BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));
}

/// <summary>What the key store can currently do (for UI status display).</summary>
public sealed record KeyStoreStatus(
    bool HasNcchOriginalKeyX,
    bool HasNcch70KeyX,
    bool HasNcch93KeyX,
    bool HasNcch96KeyX,
    bool HasCommonKeyX,
    int CommonKeyYCount,
    bool HasFixedSystemKey,
    int SeedCount,
    IReadOnlyList<string> LoadedFrom)
{
    /// <summary>Enough keys to decrypt typical retail cartridges and eShop CIAs.</summary>
    public bool IsRetailReady => HasNcchOriginalKeyX && HasNcch70KeyX && HasCommonKeyX && CommonKeyYCount >= 2;
}

/// <summary>
/// Holds the user-supplied keys and seeds used for 3DS decryption.
/// This library ships no key material: everything comes from the user's own
/// boot9.bin (dumped from their console), aes_keys.txt and seeddb.bin.
/// </summary>
public sealed class CtrKeyStore
{
    /// <summary>SHA-256 of the full (0x10000) and protected-half (0x8000) retail ARM9 bootrom.</summary>
    public const string Boot9FullSha256 = "2f88744feed717856386400a44bba4b9ca62e76a32c715d4f309c399bf28166f";
    public const string Boot9ProtSha256 = "7331f7edece3dd33f2ab4bd0b3a5d607229fd19212c10b734cedcaf78c1a7b98";

    internal const int Boot9KeyblobOffset = 0x5860; // within the protected half
    internal const int KeyblobKeyX2C = 0x170;
    internal const int KeyblobKeyX3D = 0x1C0;

    private readonly Dictionary<int, byte[]> _keyX = new();
    private readonly Dictionary<int, byte[]> _keyY = new();
    private readonly Dictionary<int, byte[]> _normal = new();
    private readonly byte[]?[] _commonKeyY = new byte[6][];
    private readonly Dictionary<ulong, byte[]> _seeds = new();
    private readonly List<string> _loadedFrom = new();
    private byte[]? _fixedSystemKey;
    private byte[]? _certificateChain;

    /// <summary>Optional CIA certificate chain (CA + XS + CP, usually 0xA00 bytes) used when building CIAs.</summary>
    public byte[]? CertificateChain => _certificateChain;

    // ------------------------------------------------------------ loading ---

    /// <summary>
    /// Load KeyX 0x2C (NCCH) and 0x3D (common key) from an ARM9 bootrom dump.
    /// Accepts the full 0x10000-byte boot9.bin or the 0x8000-byte protected half.
    /// </summary>
    /// <param name="requireKnownHash">Reject files whose SHA-256 is not a known retail bootrom.
    /// Only turn this off for synthetic test data.</param>
    public void LoadBoot9(ReadOnlySpan<byte> data, bool requireKnownHash = true, string? source = null)
    {
        if (data.Length != 0x10000 && data.Length != 0x8000)
            throw new CtrFormatException($"boot9 must be 0x10000 or 0x8000 bytes, got 0x{data.Length:X}.");
        if (requireKnownHash)
        {
            string hash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
            bool ok = data.Length == 0x10000 ? hash == Boot9FullSha256 : hash == Boot9ProtSha256;
            if (!ok) throw new CtrFormatException("boot9 hash does not match a retail ARM9 bootrom dump.");
        }
        int blob = Boot9KeyblobOffset + (data.Length == 0x10000 ? 0x8000 : 0);
        _keyX[0x2C] = data.Slice(blob + KeyblobKeyX2C, 16).ToArray();
        _keyX[0x3D] = data.Slice(blob + KeyblobKeyX3D, 16).ToArray();
        _loadedFrom.Add(source ?? "boot9");
    }

    public void LoadBoot9File(string path, bool requireKnownHash = true)
    {
        var fi = new FileInfo(path);
        if (fi.Length > 0x10000) throw new CtrFormatException($"{path} is too large to be boot9.bin.");
        LoadBoot9(File.ReadAllBytes(path), requireKnownHash, path);
    }

    private static readonly Regex SlotRegex = new(@"^slot0x([0-9a-f]{2})key([xyn])$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex CommonRegex = new(@"^common([0-5])$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HexKey = new(@"^[0-9a-fA-F]{32}$", RegexOptions.Compiled);

    /// <summary>
    /// Load keys from Citra/Azahar-style <c>aes_keys.txt</c> text:
    /// <c>slot0xNNKeyX=</c>, <c>slot0xNNKeyY=</c>, <c>slot0xNNKeyN=</c>, <c>common0</c>..<c>common5</c>
    /// (common key Y values) and optionally <c>fixedSystemKey=</c>. Unknown lines are ignored.
    /// </summary>
    /// <returns>Number of keys loaded.</returns>
    public int LoadAesKeysText(string text, string? source = null)
    {
        int loaded = 0;
        foreach (var raw in text.Split('\n'))
        {
            string line = raw;
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            string name = line[..eq].Trim();
            string value = line[(eq + 1)..].Replace(" ", "").Trim();
            if (!HexKey.IsMatch(value)) continue;
            byte[] key = Convert.FromHexString(value);
            var m = SlotRegex.Match(name);
            if (m.Success)
            {
                int slot = int.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                switch (char.ToUpperInvariant(m.Groups[2].Value[0]))
                {
                    case 'X': _keyX[slot] = key; break;
                    case 'Y': _keyY[slot] = key; break;
                    default: _normal[slot] = key; break;
                }
                loaded++;
                continue;
            }
            m = CommonRegex.Match(name);
            if (m.Success)
            {
                _commonKeyY[m.Groups[1].Value[0] - '0'] = key;
                loaded++;
                continue;
            }
            if (name.Equals("fixedSystemKey", StringComparison.OrdinalIgnoreCase))
            {
                _fixedSystemKey = key;
                loaded++;
            }
        }
        if (loaded > 0) _loadedFrom.Add(source ?? "aes_keys.txt");
        return loaded;
    }

    public int LoadAesKeysFile(string path) => LoadAesKeysText(File.ReadAllText(path), path);

    /// <summary>
    /// Load seeds from a seeddb.bin: u32 count, 12 bytes padding, then 0x20-byte entries
    /// (u64 title ID, 16-byte seed, 8 bytes padding), all little-endian.
    /// </summary>
    public int LoadSeedDb(ReadOnlySpan<byte> data, string? source = null)
    {
        if (data.Length < 0x10) throw new CtrFormatException("seeddb is too short.");
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (0x10 + (long)count * 0x20 > data.Length) throw new CtrFormatException("seeddb is truncated.");
        for (int i = 0; i < count; i++)
        {
            var e = data.Slice(0x10 + i * 0x20, 0x20);
            _seeds[BinaryPrimitives.ReadUInt64LittleEndian(e)] = e.Slice(8, 16).ToArray();
        }
        _loadedFrom.Add(source ?? "seeddb");
        return (int)count;
    }

    public int LoadSeedDbFile(string path) => LoadSeedDb(File.ReadAllBytes(path), path);

    public void AddSeed(ulong titleId, ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 16) throw new ArgumentException("Seed must be 16 bytes.", nameof(seed));
        _seeds[titleId] = seed.ToArray();
    }

    /// <summary>Set the CIA certificate chain used by CCI→CIA conversion.</summary>
    public void SetCertificateChain(byte[] certs)
    {
        if (certs.Length < 0x100) throw new CtrFormatException("Certificate chain is too short.");
        _certificateChain = certs;
    }

    /// <summary>Copy the certificate chain out of an existing CIA file.</summary>
    public void LoadCertificateChainFromCia(string ciaPath)
    {
        using var fs = File.OpenRead(ciaPath);
        var cia = Cia.CiaFile.Read(fs);
        SetCertificateChain(cia.CertificateChain);
        _loadedFrom.Add(ciaPath + " (certificates)");
    }

    // ------------------------------------------------------------- access ---

    public bool HasKeyX(int slot) => _keyX.ContainsKey(slot);

    public byte[] GetKeyX(int slot) =>
        _keyX.TryGetValue(slot, out var k) ? k
            : throw new MissingKeyException($"KeyX for keyslot 0x{slot:X2} is not loaded (boot9.bin / aes_keys.txt).", $"slot0x{slot:X2}KeyX");

    /// <summary>Normal key for a keyslot given a KeyY.</summary>
    public byte[] GetNormalKey(int slot, ReadOnlySpan<byte> keyY) => KeyScrambler.Generate(GetKeyX(slot), keyY);

    /// <summary>Normal key for the common-key keyslot (0x3D) with common key Y <paramref name="index"/>.</summary>
    public byte[] GetCommonKey(int index)
    {
        if (index is < 0 or > 5) throw new CtrFormatException($"Invalid common key index {index}.");
        var y = _commonKeyY[index]
            ?? throw new MissingKeyException($"Common key Y #{index} is not loaded (aes_keys.txt 'common{index}=').", $"common{index}");
        return GetNormalKey(0x3D, y);
    }

    public byte[] GetFixedSystemKey() => _fixedSystemKey
        ?? throw new MissingKeyException("The fixed system key is not loaded (aes_keys.txt 'fixedSystemKey=').", "fixedSystemKey");

    public bool TryGetSeed(ulong titleId, out byte[] seed)
    {
        if (_seeds.TryGetValue(titleId, out var s)) { seed = s; return true; }
        seed = Array.Empty<byte>();
        return false;
    }

    public KeyStoreStatus GetStatus() => new(
        _keyX.ContainsKey(0x2C), _keyX.ContainsKey(0x25), _keyX.ContainsKey(0x18), _keyX.ContainsKey(0x1B),
        _keyX.ContainsKey(0x3D), _commonKeyY.Count(k => k is not null), _fixedSystemKey is not null,
        _seeds.Count, _loadedFrom.ToArray());
}

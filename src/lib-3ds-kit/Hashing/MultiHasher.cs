using System.Security.Cryptography;

namespace Lib3dsKit.Hashing;

[Flags]
public enum HashKinds
{
    None = 0,
    Crc32 = 1,
    Md5 = 2,
    Sha1 = 4,
    Sha256 = 8,
    All = Crc32 | Md5 | Sha1 | Sha256,
}

/// <summary>Hashes of one byte stream. Hex strings are lowercase; absent algorithms are null.</summary>
public sealed record FileHashes(long Size, string? Crc32, string? Md5, string? Sha1, string? Sha256)
{
    public override string ToString() =>
        $"size={Size} crc32={Crc32 ?? "-"} md5={Md5 ?? "-"} sha1={Sha1 ?? "-"} sha256={Sha256 ?? "-"}";
}

/// <summary>Computes several hashes in a single streaming pass.</summary>
public sealed class MultiHasher : IDisposable
{
    private readonly Crc32? _crc;
    private readonly IncrementalHash? _md5;
    private readonly IncrementalHash? _sha1;
    private readonly IncrementalHash? _sha256;
    private long _size;

    public MultiHasher(HashKinds kinds = HashKinds.All)
    {
        if (kinds.HasFlag(HashKinds.Crc32)) _crc = new Crc32();
        if (kinds.HasFlag(HashKinds.Md5)) _md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        if (kinds.HasFlag(HashKinds.Sha1)) _sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        if (kinds.HasFlag(HashKinds.Sha256)) _sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    }

    public long Size => _size;

    public void Append(ReadOnlySpan<byte> data)
    {
        _size += data.Length;
        _crc?.Append(data);
        _md5?.AppendData(data);
        _sha1?.AppendData(data);
        _sha256?.AppendData(data);
    }

    /// <summary>Finish and return the hashes. The hasher must not be used afterwards.</summary>
    public FileHashes Finish() => new(
        _size,
        _crc is null ? null : _crc.GetCurrentValue().ToString("x8"),
        _md5 is null ? null : Hex(_md5.GetHashAndReset()),
        _sha1 is null ? null : Hex(_sha1.GetHashAndReset()),
        _sha256 is null ? null : Hex(_sha256.GetHashAndReset()));

    public static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    public void Dispose()
    {
        _md5?.Dispose();
        _sha1?.Dispose();
        _sha256?.Dispose();
    }

    /// <summary>Hash a whole stream from position 0, optionally reporting the bytes read to <paramref name="progress"/>.</summary>
    public static FileHashes HashStream(Stream s, HashKinds kinds = HashKinds.All, CancellationToken ct = default,
        IO.ProgressTracker? progress = null)
    {
        using var h = new MultiHasher(kinds);
        IO.StreamCopier.CopyAll(s, null, progress, ct, h);
        return h.Finish();
    }
}

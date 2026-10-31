using System.Buffers.Binary;
using System.Security.Cryptography;
using NoIntrovert.Core.Crypto;
using NoIntrovert.Core.IO;
using NoIntrovert.Ctr.Keys;

namespace NoIntrovert.Ctr.Ncch;

/// <summary>The two AES keys of an encrypted NCCH.</summary>
public sealed record NcchKeyPair(byte[] Key0, byte[] Key1);

/// <summary>Key selection and AES-CTR layout for NCCH containers.</summary>
public static class NcchCrypto
{
    public const int SectionExHeader = 1, SectionExeFs = 2, SectionRomFs = 3;

    /// <summary>KeyX slot used by the secondary ("content") key, from flags[3].</summary>
    public static int SecondaryKeyslot(byte cryptoMethod) => cryptoMethod switch
    {
        0x00 => 0x2C,
        0x01 => 0x25,
        0x0A => 0x18,
        0x0B => 0x1B,
        _ => throw new CtrFormatException($"Unknown NCCH crypto method 0x{cryptoMethod:X2}."),
    };

    /// <summary>
    /// Derive the NCCH keys. Returns null for NoCrypto content.
    /// Throws <see cref="MissingKeyException"/> when a key or seed is not available.
    /// </summary>
    public static NcchKeyPair? GetKeys(NcchHeader h, CtrKeyStore keys)
    {
        if (h.NoCrypto) return null;
        if (h.FixedCryptoKey)
        {
            byte[] k = h.IsSystemTitle ? keys.GetFixedSystemKey() : new byte[16];
            return new NcchKeyPair(k, k);
        }
        byte[] keyY = h.KeyY.ToArray();
        byte[] key0 = keys.GetNormalKey(0x2C, keyY);
        byte[] keyY1 = keyY;
        if (h.UsesSeed)
        {
            if (!keys.TryGetSeed(h.ProgramId, out var seed))
                throw new MissingKeyException(
                    $"Title {h.ProgramId:X16} uses seed encryption and its seed is not loaded (seeddb.bin).",
                    $"seed:{h.ProgramId:X16}");
            Span<byte> check = stackalloc byte[0x18];
            seed.CopyTo(check);
            h.ProgramIdBytes.CopyTo(check[16..]);
            if (!SHA256.HashData(check)[..4].AsSpan().SequenceEqual(h.SeedCheck))
                throw new CtrFormatException($"The seed for title {h.ProgramId:X16} does not match the NCCH header.");
            Span<byte> mix = stackalloc byte[32];
            keyY.CopyTo(mix);
            seed.CopyTo(mix[16..]);
            keyY1 = SHA256.HashData(mix)[..16];
        }
        byte[] key1 = keys.GetNormalKey(SecondaryKeyslot(h.CryptoMethod), keyY1);
        return new NcchKeyPair(key0, key1);
    }

    /// <summary>
    /// Initial counter of a section. Versions 0 and 2: [partition id (big-endian), section, 0...];
    /// version 1: [partition id (as stored), 0, 0, 0, 0, offset (big-endian u32)].
    /// </summary>
    public static UInt128 Counter(NcchHeader h, int section, long regionOffset)
    {
        if (h.Version == 1)
        {
            Span<byte> b = stackalloc byte[16];
            h.Raw.Slice(0x108, 8).CopyTo(b);
            BinaryPrimitives.WriteUInt32BigEndian(b[12..], (uint)regionOffset);
            return AesCtrCipher.ReadCounter(b);
        }
        return ((UInt128)h.PartitionId << 64) | ((UInt128)(uint)section << 56);
    }

    /// <summary>One encrypted byte range of an NCCH.</summary>
    /// <param name="Start">First byte (NCCH-relative).</param>
    /// <param name="End">One past the last byte.</param>
    /// <param name="KeyIndex">0 = primary key, 1 = secondary key.</param>
    /// <param name="RegionStart">Where the counter equals <paramref name="CounterBase"/>.</param>
    public readonly record struct Segment(long Start, long End, int KeyIndex, long RegionStart, UInt128 CounterBase);

    /// <summary>
    /// Encrypted ranges, sorted and non-overlapping. <paramref name="exefsHeaderPlain"/> is the
    /// decrypted ExeFS header, needed to know which ExeFS files use the secondary key
    /// (every file except "icon" and "banner").
    /// </summary>
    public static List<Segment> Segments(NcchHeader h, ReadOnlySpan<byte> exefsHeaderPlain)
    {
        var segs = new List<Segment>();
        if (h.HasExHeader)
            segs.Add(new Segment(0x200, 0xA00, 0, 0x200, Counter(h, SectionExHeader, 0x200)));

        var (exefsOff, exefsSize) = h.ExeFs;
        if (exefsSize > 0)
        {
            UInt128 ctr = Counter(h, SectionExeFs, exefsOff);
            long end = exefsOff + exefsSize;
            var key1 = new List<(long S, long E)>();
            if (!exefsHeaderPlain.IsEmpty)
            {
                foreach (var e in ExeFsEntry.ParseTable(exefsHeaderPlain))
                {
                    if (e.Name is "icon" or "banner") continue;
                    long s = exefsOff + 0x200 + e.Offset;
                    key1.Add((s, Math.Min(s + e.Size, end)));
                }
            }
            key1.Sort();
            long cur = exefsOff;
            foreach (var (s0, e) in key1)
            {
                if (s0 > cur) segs.Add(new Segment(cur, s0, 0, exefsOff, ctr));
                long s = Math.Max(s0, cur);
                if (e > s)
                {
                    segs.Add(new Segment(s, e, 1, exefsOff, ctr));
                    cur = e;
                }
            }
            if (cur < end) segs.Add(new Segment(cur, end, 0, exefsOff, ctr));
        }

        var (romfsOff, romfsSize) = h.RomFs;
        if (romfsSize > 0)
            segs.Add(new Segment(romfsOff, romfsOff + romfsSize, 1, romfsOff, Counter(h, SectionRomFs, romfsOff)));
        return segs;
    }
}

/// <summary>
/// Read-only, seekable decrypted view of an NCCH (CXI/CFA). The header reported by this
/// stream already carries the "decrypted" flags (NoCrypto set, crypto method 0), so copying
/// it to a file produces a valid decrypted NCCH. NoCrypto input passes through unchanged.
/// </summary>
public sealed class NcchStream : VirtualStream
{
    private readonly Stream _source;
    private readonly AesCtrCipher? _c0;
    private readonly AesCtrCipher? _c1;
    private readonly List<NcchCrypto.Segment> _segments = new();
    private readonly byte[] _plainHeader;

    /// <param name="source">The NCCH bytes (e.g. a <see cref="SubStream"/> over a CCI partition).</param>
    /// <exception cref="MissingKeyException">Keys or seed for this NCCH are not loaded.</exception>
    public NcchStream(Stream source, CtrKeyStore keys)
    {
        _source = source;
        Span<byte> hdr = stackalloc byte[NcchHeader.Size];
        ReadExactlyAt(source, 0, hdr);
        Header = new NcchHeader(hdr);
        WasEncrypted = !Header.NoCrypto;
        _plainHeader = Header.ToArray();
        var keyPair = NcchCrypto.GetKeys(Header, keys);
        if (keyPair is not null)
        {
            _c0 = new AesCtrCipher(keyPair.Key0);
            _c1 = new AesCtrCipher(keyPair.Key1);
            byte[] exefsHeader = Array.Empty<byte>();
            var (exefsOff, exefsSize) = Header.ExeFs;
            if (exefsSize >= 0x200 && exefsOff + 0x200 <= source.Length)
            {
                exefsHeader = ReadBytesAt(source, exefsOff, 0x200);
                _c0.Transform(NcchCrypto.Counter(Header, NcchCrypto.SectionExeFs, exefsOff), 0, exefsHeader);
            }
            _segments = NcchCrypto.Segments(Header, exefsHeader);
            NcchHeader.ApplyDecryptedFlags(_plainHeader.AsSpan(NcchHeader.FlagsOffset, 8));
        }
        DecryptedHeader = new NcchHeader(_plainHeader);
    }

    /// <summary>The header as stored in the source.</summary>
    public NcchHeader Header { get; }

    /// <summary>The header as this stream presents it (decrypted flags).</summary>
    public NcchHeader DecryptedHeader { get; }

    public bool WasEncrypted { get; }

    public override long Length => _source.Length;

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        ReadExactlyAt(_source, position, buffer);
        long end = position + buffer.Length;
        if (position < NcchHeader.Size)
        {
            int n = (int)Math.Min(NcchHeader.Size - position, buffer.Length);
            _plainHeader.AsSpan((int)position, n).CopyTo(buffer);
        }
        foreach (var seg in _segments)
        {
            long s = Math.Max(seg.Start, position);
            long e = Math.Min(seg.End, end);
            if (s >= e) continue;
            var cipher = seg.KeyIndex == 0 ? _c0! : _c1!;
            cipher.Transform(seg.CounterBase, s - seg.RegionStart, buffer.Slice((int)(s - position), (int)(e - s)));
        }
    }

    /// <summary>Read a decrypted range into a new array.</summary>
    public byte[] ReadDecrypted(long offset, int count)
    {
        var b = new byte[count];
        ReadAt(offset, b);
        return b;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _c0?.Dispose();
            _c1?.Dispose();
        }
        base.Dispose(disposing);
    }
}

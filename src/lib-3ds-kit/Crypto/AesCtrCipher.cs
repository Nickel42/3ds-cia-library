using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lib3dsKit.Crypto;

/// <summary>
/// AES-128-CTR with a 128-bit big-endian counter, built on AES-ECB (.NET has no CTR mode).
/// Random access: any byte range can be transformed independently.
/// Encryption and decryption are the same operation.
/// </summary>
public sealed class AesCtrCipher : IDisposable
{
    private const int BatchBlocks = 4096; // 64 KiB of keystream per ECB call
    private readonly Aes _aes;

    public AesCtrCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16) throw new ArgumentException("AES-128 key must be 16 bytes.", nameof(key));
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
    }

    /// <summary>
    /// XOR <paramref name="data"/> in place with the keystream, where <paramref name="data"/>[0]
    /// sits <paramref name="relativeOffset"/> bytes after the point where the counter equals
    /// <paramref name="counterBase"/>.
    /// </summary>
    public void Transform(UInt128 counterBase, long relativeOffset, Span<byte> data)
    {
        if (data.IsEmpty) return;
        ArgumentOutOfRangeException.ThrowIfNegative(relativeOffset);
        UInt128 counter = counterBase + (UInt128)(ulong)(relativeOffset >> 4);
        int skip = (int)(relativeOffset & 15);

        int maxBlocks = Math.Min(BatchBlocks, (skip + data.Length + 15) / 16);
        byte[] ctrBuf = ArrayPool<byte>.Shared.Rent(maxBlocks * 16);
        byte[] ksBuf = ArrayPool<byte>.Shared.Rent(maxBlocks * 16);
        try
        {
            int done = 0;
            while (done < data.Length)
            {
                int bytesWanted = skip + (data.Length - done);
                int blocks = Math.Min(maxBlocks, (bytesWanted + 15) / 16);
                for (int i = 0; i < blocks; i++)
                {
                    WriteCounter(ctrBuf.AsSpan(i * 16, 16), counter);
                    counter++;
                }
                var ks = ksBuf.AsSpan(0, blocks * 16);
                _aes.EncryptEcb(ctrBuf.AsSpan(0, blocks * 16), ks, PaddingMode.None);
                int usable = Math.Min(blocks * 16 - skip, data.Length - done);
                Xor(data.Slice(done, usable), ks.Slice(skip, usable));
                done += usable;
                skip = 0;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ctrBuf);
            ArrayPool<byte>.Shared.Return(ksBuf);
        }
    }

    /// <summary>Big-endian 16-byte representation of a counter.</summary>
    public static void WriteCounter(Span<byte> dest, UInt128 value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(dest, (ulong)(value >> 64));
        BinaryPrimitives.WriteUInt64BigEndian(dest[8..], (ulong)value);
    }

    public static UInt128 ReadCounter(ReadOnlySpan<byte> src) =>
        new(BinaryPrimitives.ReadUInt64BigEndian(src), BinaryPrimitives.ReadUInt64BigEndian(src[8..]));

    private static void Xor(Span<byte> data, ReadOnlySpan<byte> keystream)
    {
        int i = 0;
        // 8 bytes at a time
        var d8 = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, ulong>(data);
        var k8 = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, ulong>(keystream);
        for (int j = 0; j < d8.Length; j++) d8[j] ^= k8[j];
        i = d8.Length * 8;
        for (; i < data.Length; i++) data[i] ^= keystream[i];
    }

    public void Dispose() => _aes.Dispose();
}

/// <summary>Helpers for one-shot AES operations on small buffers (title keys, tests).</summary>
public static class AesUtil
{
    public static byte[] CbcDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.DecryptCbc(data, iv, PaddingMode.None);
    }

    public static byte[] CbcEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.EncryptCbc(data, iv, PaddingMode.None);
    }
}

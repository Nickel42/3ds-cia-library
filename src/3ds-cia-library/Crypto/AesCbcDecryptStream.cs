using System.Buffers;
using System.Security.Cryptography;
using ThreeDsCiaLibrary.IO;

namespace ThreeDsCiaLibrary.Crypto;

/// <summary>
/// Random-access AES-128-CBC decryption view over a ciphertext stream
/// (no padding; the ciphertext length must be a multiple of 16).
/// Plaintext block i = AES-Decrypt(C[i]) XOR C[i-1] (C[-1] = IV), so any range can be
/// decrypted by also reading the block before it.
/// </summary>
public sealed class AesCbcDecryptStream : VirtualStream
{
    private readonly Stream _cipher;
    private readonly byte[] _iv;
    private readonly Aes _aes;

    public AesCbcDecryptStream(Stream ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (ciphertext.Length % 16 != 0)
            throw new ArgumentException("CBC ciphertext length must be a multiple of 16.", nameof(ciphertext));
        _cipher = ciphertext;
        _iv = iv.ToArray();
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
    }

    public override long Length => _cipher.Length;

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        long start = position & ~15L;
        long end = (position + buffer.Length + 15) & ~15L;
        int span = (int)(end - start);
        byte[] ct = ArrayPool<byte>.Shared.Rent(span);
        byte[] pt = ArrayPool<byte>.Shared.Rent(span);
        try
        {
            Span<byte> iv = stackalloc byte[16];
            if (start == 0) _iv.CopyTo(iv);
            else ReadExactlyAt(_cipher, start - 16, iv);
            ReadExactlyAt(_cipher, start, ct.AsSpan(0, span));
            _aes.DecryptCbc(ct.AsSpan(0, span), iv, pt.AsSpan(0, span), PaddingMode.None);
            pt.AsSpan((int)(position - start), buffer.Length).CopyTo(buffer);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ct);
            ArrayPool<byte>.Shared.Return(pt);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _aes.Dispose();
        base.Dispose(disposing);
    }
}

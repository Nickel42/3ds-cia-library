namespace ThreeDsCiaLibrary.IO;

/// <summary>
/// Base class for read-only, seekable, computed streams. Implementers only provide
/// <see cref="ReadAt"/>; position handling and the Stream boilerplate live here.
/// </summary>
public abstract class VirtualStream : Stream
{
    private long _position;

    public sealed override bool CanRead => true;
    public sealed override bool CanSeek => true;
    public sealed override bool CanWrite => false;

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    /// <summary>Fill <paramref name="buffer"/> with bytes starting at <paramref name="position"/>.
    /// The caller guarantees <c>position + buffer.Length &lt;= Length</c>.</summary>
    protected abstract void ReadAt(long position, Span<byte> buffer);

    public sealed override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public sealed override int Read(Span<byte> buffer)
    {
        long remaining = Length - _position;
        if (remaining <= 0 || buffer.Length == 0) return 0;
        int n = (int)Math.Min(buffer.Length, remaining);
        ReadAt(_position, buffer[..n]);
        _position += n;
        return n;
    }

    public sealed override long Seek(long offset, SeekOrigin origin)
    {
        Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        return _position;
    }

    public override void Flush() { }
    public sealed override void SetLength(long value) => throw new NotSupportedException();
    public sealed override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <summary>Read exactly <paramref name="buffer"/>.Length bytes from a stream or throw.</summary>
    public static void ReadExactlyAt(Stream s, long position, Span<byte> buffer)
    {
        s.Position = position;
        s.ReadExactly(buffer);
    }

    /// <summary>Read <paramref name="count"/> bytes at <paramref name="position"/> into a new array.</summary>
    public static byte[] ReadBytesAt(Stream s, long position, int count)
    {
        var b = new byte[count];
        ReadExactlyAt(s, position, b);
        return b;
    }
}

/// <summary>A stream of <see cref="Length"/> copies of one byte value (e.g. 0xFF card padding).</summary>
public sealed class FillStream : VirtualStream
{
    private readonly long _length;
    private readonly byte _value;

    public FillStream(long length, byte value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _length = length;
        _value = value;
    }

    public override long Length => _length;
    protected override void ReadAt(long position, Span<byte> buffer) => buffer.Fill(_value);
}

/// <summary>Wraps an in-memory byte array as a <see cref="VirtualStream"/>.</summary>
public sealed class BytesStream : VirtualStream
{
    private readonly byte[] _data;
    public BytesStream(byte[] data) => _data = data;
    public override long Length => _data.LongLength;
    protected override void ReadAt(long position, Span<byte> buffer) =>
        _data.AsSpan((int)position, buffer.Length).CopyTo(buffer);
}

/// <summary>Concatenation of several readable, seekable streams.</summary>
public sealed class ConcatStream : VirtualStream
{
    private readonly Stream[] _parts;
    private readonly long[] _starts;
    private readonly long _length;

    public ConcatStream(IEnumerable<Stream> parts)
    {
        _parts = parts.ToArray();
        _starts = new long[_parts.Length];
        long pos = 0;
        for (int i = 0; i < _parts.Length; i++)
        {
            _starts[i] = pos;
            pos += _parts[i].Length;
        }
        _length = pos;
    }

    public override long Length => _length;

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        int done = 0;
        while (done < buffer.Length)
        {
            long p = position + done;
            int i = Array.BinarySearch(_starts, p);
            if (i < 0) i = ~i - 1;
            while (i < _parts.Length - 1 && _parts[i].Length == 0) i++;
            long inPart = p - _starts[i];
            int n = (int)Math.Min(buffer.Length - done, _parts[i].Length - inPart);
            ReadExactlyAt(_parts[i], inPart, buffer.Slice(done, n));
            done += n;
        }
    }
}

/// <summary>
/// Overlays byte patches on top of a base stream. Patches may either replace bytes
/// or XOR them (XOR is used to patch AES-CTR ciphertext without re-encrypting).
/// </summary>
public sealed class OverlayStream : VirtualStream
{
    private readonly Stream _base;
    private readonly List<(long Offset, byte[] Data, bool Xor)> _patches = new();

    public OverlayStream(Stream baseStream) => _base = baseStream;

    public override long Length => _base.Length;

    public OverlayStream Replace(long offset, byte[] data)
    {
        _patches.Add((offset, data, false));
        return this;
    }

    public OverlayStream Xor(long offset, byte[] data)
    {
        _patches.Add((offset, data, true));
        return this;
    }

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        ReadExactlyAt(_base, position, buffer);
        long end = position + buffer.Length;
        foreach (var (off, data, xor) in _patches)
        {
            long s = Math.Max(off, position);
            long e = Math.Min(off + data.Length, end);
            for (long p = s; p < e; p++)
            {
                byte v = data[p - off];
                ref byte dst = ref buffer[(int)(p - position)];
                dst = xor ? (byte)(dst ^ v) : v;
            }
        }
    }
}

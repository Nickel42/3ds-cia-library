namespace Lib3dsKit.IO;

/// <summary>
/// Read-only, seekable window <c>[offset, offset + length)</c> over another seekable stream.
/// Every read re-positions the base stream, so several windows can share one base
/// stream as long as they are used from a single thread.
/// </summary>
public sealed class SubStream : Stream
{
    private readonly Stream _base;
    private readonly long _offset;
    private readonly long _length;
    private readonly bool _leaveOpen;
    private long _position;

    public SubStream(Stream baseStream, long offset, long length, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(baseStream);
        if (!baseStream.CanSeek || !baseStream.CanRead)
            throw new ArgumentException("Base stream must be readable and seekable.", nameof(baseStream));
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _base = baseStream;
        _offset = offset;
        _length = length;
        _leaveOpen = leaveOpen;
    }

    public long BaseOffset => _offset;
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        long remaining = _length - _position;
        if (remaining <= 0 || buffer.Length == 0) return 0;
        int toRead = (int)Math.Min(buffer.Length, remaining);
        _base.Position = _offset + _position;
        int total = 0;
        while (total < toRead)
        {
            int n = _base.Read(buffer.Slice(total, toRead - total));
            if (n == 0) break; // base stream shorter than declared window
            total += n;
        }
        _position += total;
        return total;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        Position = target;
        return _position;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen) _base.Dispose();
        base.Dispose(disposing);
    }
}

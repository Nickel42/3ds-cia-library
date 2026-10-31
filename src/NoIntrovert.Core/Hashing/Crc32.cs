namespace NoIntrovert.Core.Hashing;

/// <summary>
/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320) as used by DAT files and zip.
/// Slicing-by-8 implementation with no external dependencies.
/// </summary>
public sealed class Crc32
{
    private static readonly uint[][] Tables = BuildTables();
    private uint _state = 0xFFFFFFFFu;

    private static uint[][] BuildTables()
    {
        var t = new uint[8][];
        for (int k = 0; k < 8; k++) t[k] = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[0][i] = c;
        }
        for (int i = 0; i < 256; i++)
            for (int k = 1; k < 8; k++)
                t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xFF];
        return t;
    }

    public void Append(ReadOnlySpan<byte> data)
    {
        uint crc = _state;
        var t0 = Tables[0]; var t1 = Tables[1]; var t2 = Tables[2]; var t3 = Tables[3];
        var t4 = Tables[4]; var t5 = Tables[5]; var t6 = Tables[6]; var t7 = Tables[7];
        int i = 0;
        for (; i + 8 <= data.Length; i += 8)
        {
            uint lo = crc ^ (uint)(data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24);
            uint hi = (uint)(data[i + 4] | data[i + 5] << 8 | data[i + 6] << 16 | data[i + 7] << 24);
            crc = t7[lo & 0xFF] ^ t6[(lo >> 8) & 0xFF] ^ t5[(lo >> 16) & 0xFF] ^ t4[lo >> 24]
                ^ t3[hi & 0xFF] ^ t2[(hi >> 8) & 0xFF] ^ t1[(hi >> 16) & 0xFF] ^ t0[hi >> 24];
        }
        for (; i < data.Length; i++) crc = t0[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        _state = crc;
    }

    public uint GetCurrentValue() => ~_state;

    public void Reset() => _state = 0xFFFFFFFFu;

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var c = new Crc32();
        c.Append(data);
        return c.GetCurrentValue();
    }
}

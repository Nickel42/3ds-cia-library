using System.Buffers.Binary;
using System.Text;

namespace NoIntrovert.Ctr.Cia;

/// <summary>A content file of a CDN title, matched to its TMD record.</summary>
public readonly record struct CdnContent(ContentChunk Chunk, string Path);

/// <summary>
/// A title as downloaded from Nintendo's CDN: one folder holding the TMD, the ticket and one file per
/// content, named by content ID. Accepts the raw CDN names (<c>tmd</c>, <c>cetk</c>, <c>00000000</c>) and
/// the NUSspli/FunKiiU-style ones (<c>title.tmd</c>, <c>title.tik</c>, <c>title.cert</c>, <c>00000000.app</c>).
/// The certificates Nintendo appends to the TMD and ticket are split off and kept for the CIA's chain.
/// </summary>
public sealed class CdnTitle
{
    private const string CaName = "CA00000003";
    private const string TicketSignerName = "XS0000000c";
    private const string TmdSignerName = "CP0000000b";

    private CdnTitle() { }

    public string Folder { get; private init; } = "";
    public Tmd Tmd { get; private init; } = null!;
    public Ticket Ticket { get; private init; } = null!;

    /// <summary>Contents listed in the TMD that have a file in the folder, in TMD order.</summary>
    public IReadOnlyList<CdnContent> Contents { get; private init; } = Array.Empty<CdnContent>();

    /// <summary>Contents listed in the TMD with no file (normal for DLC you do not own in full).</summary>
    public IReadOnlyList<ContentChunk> Missing { get; private init; } = Array.Empty<ContentChunk>();

    /// <summary>Certificates found after the TMD/ticket or in a <c>cert</c> file, by name (e.g. "CA00000003").</summary>
    public IReadOnlyDictionary<string, byte[]> Certificates { get; private init; } = new Dictionary<string, byte[]>();

    public IReadOnlyList<string> Warnings { get; private init; } = Array.Empty<string>();

    /// <summary>
    /// True when the ticket's title version differs from the TMD's, which CDN downloads often have.
    /// Installers ignore it; <see cref="TicketBytes"/> can write a matching ticket.
    /// </summary>
    public bool TicketVersionMismatch => Ticket.TitleVersion != Tmd.TitleVersion;

    /// <summary>True for DLC (title ID high word 0004008C), whose CDN folders may hold only some contents.</summary>
    public bool IsDlc => (Tmd.TitleId >> 32) == 0x0004008C;

    /// <summary>True when <paramref name="folder"/> looks like a CDN title (it holds a TMD).</summary>
    public static bool LooksLikeCdn(string folder) => Directory.Exists(folder) && FindTmd(folder, out _) is not null;

    public static CdnTitle Open(string folder)
    {
        if (!Directory.Exists(folder)) throw new CtrFormatException($"CDN folder not found: {folder}");
        var warnings = new List<string>();
        var certs = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        string tmdPath = FindTmd(folder, out string? tmdNote)
            ?? throw new CtrFormatException("No TMD in the CDN folder (expected 'tmd' or 'title.tmd').");
        if (tmdNote is not null) warnings.Add(tmdNote);
        var tmdFile = File.ReadAllBytes(tmdPath);
        var tmdRaw = tmdFile.AsSpan(0, TmdLength(tmdFile)).ToArray();
        ReadCertificates(tmdFile, tmdRaw.Length, certs);

        string ticketPath = FindFile(folder, "cetk", "title.tik", "ticket", "ticket.tik")
            ?? Directory.EnumerateFiles(folder, "*.tik").OrderBy(p => p, StringComparer.OrdinalIgnoreCase).FirstOrDefault()
            ?? throw new CtrFormatException("No ticket in the CDN folder (expected 'cetk' or 'title.tik'). The title key is needed to build a CIA.");
        var ticketFile = File.ReadAllBytes(ticketPath);
        var ticketRaw = ticketFile.AsSpan(0, TicketLength(ticketFile)).ToArray();
        ReadCertificates(ticketFile, ticketRaw.Length, certs);

        if (FindFile(folder, "cert", "title.cert") is { } certPath)
            ReadCertificates(File.ReadAllBytes(certPath), 0, certs);

        var tmd = new Tmd(tmdRaw);
        var ticket = new Ticket(ticketRaw);
        if (ticket.TitleId != tmd.TitleId)
            throw new CtrFormatException($"Ticket is for title {ticket.TitleId:X16} but the TMD is for {tmd.TitleId:X16}.");

        var contents = new List<CdnContent>();
        var missing = new List<ContentChunk>();
        foreach (var chunk in tmd.Chunks)
        {
            string id = chunk.Id.ToString("x8");
            string? path = FindFile(folder, id, id + ".app");
            if (path is null)
            {
                missing.Add(chunk);
                continue;
            }
            long length = new FileInfo(path).Length;
            if (length < (long)chunk.Size)
                throw new CtrFormatException($"Content {id} is {length:N0} bytes but the TMD lists {chunk.Size:N0} (incomplete download).");
            contents.Add(new CdnContent(chunk, path));
        }
        if (contents.Count == 0) throw new CtrFormatException("None of the contents listed in the TMD are in the CDN folder.");

        return new CdnTitle
        {
            Folder = folder,
            Tmd = tmd,
            Ticket = ticket,
            Contents = contents,
            Missing = missing,
            Certificates = certs,
            Warnings = warnings,
        };
    }

    /// <summary>
    /// The CIA certificate chain (CA, ticket signer, TMD signer: 0xA00 bytes) built from the certificates
    /// that came with the download, or null when any of the three is missing.
    /// </summary>
    public byte[]? BuildCertificateChain()
    {
        if (!Certificates.TryGetValue(CaName, out var ca) || !Certificates.TryGetValue(TicketSignerName, out var xs)
            || !Certificates.TryGetValue(TmdSignerName, out var cp)) return null;
        return [.. ca, .. xs, .. cp];
    }

    /// <summary>The ticket bytes to put in a CIA, optionally with its title version set to the TMD's.</summary>
    public byte[] TicketBytes(bool matchVersionToTmd)
    {
        var raw = (byte[])Ticket.Raw.Clone();
        if (matchVersionToTmd)
            BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(Ticket.BodyOffset + 0xA6), Tmd.TitleVersion);
        return raw;
    }

    // ------------------------------------------------------------- layout ---

    /// <summary>Signature block + header + content info records + one record per content.</summary>
    private static int TmdLength(byte[] file)
    {
        if (file.Length < 4) throw new CtrFormatException("TMD is truncated.");
        int header = SignatureBlock.Size(file);
        if (file.Length < header + Tmd.HeaderSize + Tmd.InfoRecordsSize) throw new CtrFormatException("TMD is truncated.");
        int count = BinaryPrimitives.ReadUInt16BigEndian(file.AsSpan(header + 0x9E));
        int length = header + Tmd.HeaderSize + Tmd.InfoRecordsSize + count * Tmd.ChunkRecordSize;
        if (file.Length < length) throw new CtrFormatException("TMD content records are truncated.");
        return length;
    }

    /// <summary>Signature block + 0x164-byte body + the content index, whose size is stored at its offset 4.</summary>
    private static int TicketLength(byte[] file)
    {
        if (file.Length < 4) throw new CtrFormatException("Ticket is truncated.");
        int body = SignatureBlock.Size(file);
        int index = body + 0x164;
        if (file.Length < index + 8) throw new CtrFormatException("Ticket is truncated.");
        long length = index + (long)BinaryPrimitives.ReadUInt32BigEndian(file.AsSpan(index + 4));
        if (length > file.Length || length < index) throw new CtrFormatException("Ticket content index is corrupt.");
        return (int)length;
    }

    /// <summary>Reads back-to-back certificates from <paramref name="offset"/> to the end of <paramref name="data"/>.</summary>
    private static void ReadCertificates(byte[] data, int offset, Dictionary<string, byte[]> into)
    {
        int pos = offset;
        while (data.Length - pos >= 4)
        {
            int body;
            try
            {
                body = pos + SignatureBlock.Size(data.AsSpan(pos));
            }
            catch (CtrFormatException)
            {
                return; // not a certificate (e.g. padding); nothing more to read
            }
            if (data.Length < body + 0x88) return;
            uint keyType = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(body + 0x40));
            int keySize = keyType switch
            {
                0 => 0x238, // RSA-4096
                1 => 0x138, // RSA-2048
                2 => 0x78,  // ECC
                _ => -1,
            };
            if (keySize < 0 || data.Length < body + 0x88 + keySize) return;
            int end = body + 0x88 + keySize;
            string name = Encoding.ASCII.GetString(data, body + 0x44, 0x40).TrimEnd('\0');
            into.TryAdd(name, data[pos..end]);
            pos = end;
        }
    }

    // -------------------------------------------------------------- files ---

    private static string? FindFile(string folder, params string[] names)
    {
        foreach (var name in names)
        {
            var match = Directory.EnumerateFiles(folder)
                .FirstOrDefault(p => string.Equals(Path.GetFileName(p), name, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return match;
        }
        return null;
    }

    /// <summary><c>tmd</c> / <c>title.tmd</c>, else the highest of <c>tmd.&lt;version&gt;</c>.</summary>
    private static string? FindTmd(string folder, out string? note)
    {
        note = null;
        if (FindFile(folder, "tmd", "title.tmd") is { } plain) return plain;
        var versioned = Directory.EnumerateFiles(folder, "tmd.*")
            .Select(p => (Path: p, Ok: ushort.TryParse(Path.GetExtension(p).TrimStart('.'), out var v), Version: v))
            .Where(x => x.Ok)
            .OrderByDescending(x => x.Version)
            .ToList();
        if (versioned.Count == 0) return null;
        if (versioned.Count > 1)
            note = $"Several TMD versions found; using {Path.GetFileName(versioned[0].Path)}.";
        return versioned[0].Path;
    }
}

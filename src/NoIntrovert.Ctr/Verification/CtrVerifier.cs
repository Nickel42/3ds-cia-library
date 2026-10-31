using System.Security.Cryptography;
using NoIntrovert.Core.Hashing;
using NoIntrovert.Core.IO;
using NoIntrovert.Ctr.Cia;
using NoIntrovert.Ctr.Keys;
using NoIntrovert.Ctr.Ncch;
using NoIntrovert.Ctr.Ncsd;
using NoIntrovert.Dat;

namespace NoIntrovert.Ctr.Verification;

public sealed class CtrVerifyOptions
{
    /// <summary>Check the hashes stored inside the file (TMD content hashes, NCCH header hashes).</summary>
    public bool CheckIntegrity { get; init; } = true;
    /// <summary>For trimmed CCIs, also hash the image as if padded to card size (how No-Intro hashes carts).</summary>
    public bool HashUntrimmed { get; init; } = true;
    public HashKinds HashKinds { get; init; } = HashKinds.All;
}

/// <summary>Overall verdict, from best to worst.</summary>
public enum CtrVerdict
{
    /// <summary>Hash-matched a DAT entry.</summary>
    Verified,
    /// <summary>Hash-matched after virtually padding a trimmed image.</summary>
    VerifiedUntrimmed,
    /// <summary>No DAT match, but every internal hash checked out (e.g. converted or homebrew files).</summary>
    IntactNotInDat,
    /// <summary>No DAT match and internal checks were skipped (keys missing / no DAT loaded).</summary>
    Unknown,
    /// <summary>An internal hash is wrong: the file is corrupt or modified.</summary>
    Bad,
}

public sealed record CtrVerifyReport
{
    public required CtrFileInfo Info { get; init; }
    public required FileHashes Hashes { get; init; }
    /// <summary>Hashes of the trimmed CCI padded to card size, when computed.</summary>
    public FileHashes? UntrimmedHashes { get; init; }
    public DatMatch Match { get; init; } = DatMatch.NoMatch;
    public bool MatchedUntrimmed { get; init; }
    /// <summary>Candidates found by product code when no hash matched.</summary>
    public IReadOnlyList<DatRom> SerialCandidates { get; init; } = Array.Empty<DatRom>();
    public IReadOnlyList<IntegrityCheck> Checks { get; init; } = Array.Empty<IntegrityCheck>();
    public CtrVerdict Verdict { get; init; }

    public bool AnyCheckFailed => Checks.Any(c => c.Status == CheckStatus.Fail);
}

/// <summary>
/// Hashes 3DS files, looks them up in DATs (No-Intro), and checks internal integrity.
/// </summary>
public sealed class CtrVerifier
{
    private readonly CtrKeyStore _keys;
    private readonly DatIndex? _dats;

    public CtrVerifier(CtrKeyStore keys, DatIndex? dats)
    {
        _keys = keys;
        _dats = dats;
    }

    public Task<CtrVerifyReport> VerifyAsync(string path, CtrVerifyOptions? options = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Verify(path, options ?? new(), progress, ct), ct);

    public CtrVerifyReport Verify(string path, CtrVerifyOptions options, IProgress<OperationProgress>? progress = null,
        CancellationToken ct = default)
    {
        using var fs = CtrFile.OpenRead(path);
        var info = CtrInspector.Inspect(fs, path, _keys);

        // ---- whole-file hashes (one pass; padded variant fed the same bytes plus virtual 0xFF)
        bool padded = options.HashUntrimmed && info.IsTrimmed;
        long total = padded ? info.MediaSize : fs.Length;
        var tracker = new ProgressTracker(progress, total);
        tracker.SetStage("Hashing " + Path.GetFileName(path));
        using var raw = new MultiHasher(options.HashKinds);
        using var pad = padded ? new MultiHasher(options.HashKinds) : null;
        fs.Position = 0;
        StreamCopier.Copy(fs, null, fs.Length, tracker, ct, raw, pad);
        FileHashes hashes = raw.Finish();
        FileHashes? untrimmed = null;
        if (pad is not null)
        {
            StreamCopier.Fill(null, info.MediaSize - fs.Length, 0xFF, tracker, ct, pad);
            untrimmed = pad.Finish();
        }

        // ---- DAT lookup
        var match = DatMatch.NoMatch;
        bool matchedUntrimmed = false;
        IReadOnlyList<DatRom> serialCandidates = Array.Empty<DatRom>();
        if (_dats is not null)
        {
            match = _dats.Lookup(hashes);
            if (!match.IsVerified && untrimmed is not null)
            {
                var m2 = _dats.Lookup(untrimmed);
                if (m2.IsVerified) { match = m2; matchedUntrimmed = true; }
            }
            if (!match.IsVerified)
            {
                serialCandidates = _dats.LookupSerial(info.ProductCode);
                if (serialCandidates.Count > 0)
                    match = new DatMatch(DatMatchKind.Serial, serialCandidates[0],
                        serialCandidates.Count > 1 ? $"{serialCandidates.Count} DAT entries share this serial" : null);
            }
        }

        // ---- internal integrity
        var checks = new List<IntegrityCheck>();
        if (options.CheckIntegrity)
        {
            tracker.SetStage("Checking internal hashes");
            fs.Position = 0;
            switch (info.Type)
            {
                case CtrFileType.Cci: CheckCci(fs, checks, ct); break;
                case CtrFileType.Cia: CheckCia(fs, checks, ct); break;
                case CtrFileType.Cxi or CtrFileType.Cfa: CheckNcch(fs, "", checks); break;
            }
        }

        CtrVerdict verdict;
        if (checks.Any(c => c.Status == CheckStatus.Fail)) verdict = CtrVerdict.Bad;
        else if (match.IsVerified) verdict = matchedUntrimmed ? CtrVerdict.VerifiedUntrimmed : CtrVerdict.Verified;
        else if (checks.Count > 0 && checks.All(c => c.Status == CheckStatus.Pass)) verdict = CtrVerdict.IntactNotInDat;
        else verdict = CtrVerdict.Unknown;

        return new CtrVerifyReport
        {
            Info = info,
            Hashes = hashes,
            UntrimmedHashes = untrimmed,
            Match = match,
            MatchedUntrimmed = matchedUntrimmed,
            SerialCandidates = serialCandidates,
            Checks = checks,
            Verdict = verdict,
        };
    }

    private void CheckNcch(Stream ncch, string prefix, List<IntegrityCheck> checks)
    {
        NcchStream ns;
        try { ns = new NcchStream(ncch, _keys); }
        catch (MissingKeyException ex)
        {
            checks.Add(new IntegrityCheck(prefix + "NCCH hashes", CheckStatus.Skipped, ex.Message));
            return;
        }
        catch (CtrFormatException ex)
        {
            checks.Add(new IntegrityCheck(prefix + "NCCH crypto", CheckStatus.Fail, ex.Message));
            return;
        }
        using (ns) checks.AddRange(NcchContent.Verify(ns, ns.DecryptedHeader, prefix));
    }

    private void CheckCci(Stream fs, List<IntegrityCheck> checks, CancellationToken ct)
    {
        var ncsd = new NcsdHeader(VirtualStream.ReadBytesAt(fs, 0, (int)Math.Min(NcsdHeader.HeaderAreaSize, fs.Length)));
        foreach (var p in ncsd.Partitions)
        {
            ct.ThrowIfCancellationRequested();
            string prefix = $"Partition {p.Index}: ";
            if (p.Offset + p.Size > fs.Length)
            {
                checks.Add(new IntegrityCheck(prefix + "present", CheckStatus.Fail, "extends past end of file"));
                continue;
            }
            var sub = new SubStream(fs, p.Offset, p.Size);
            if (!NcchHeader.IsNcch(VirtualStream.ReadBytesAt(sub, 0, (int)Math.Min(0x200, sub.Length))))
            {
                checks.Add(new IntegrityCheck(prefix + "NCCH header", CheckStatus.Fail, "missing NCCH magic"));
                continue;
            }
            CheckNcch(sub, prefix, checks);
        }
    }

    private void CheckCia(Stream fs, List<IntegrityCheck> checks, CancellationToken ct)
    {
        var cia = CiaFile.Read(fs);
        byte[]? titleKey = null;
        if (cia.Contents.Any(c => c.Chunk.IsEncrypted))
        {
            try { titleKey = cia.Ticket.DecryptTitleKey(_keys); }
            catch (MissingKeyException ex)
            {
                checks.Add(new IntegrityCheck("TMD content hashes", CheckStatus.Skipped, ex.Message));
                return;
            }
        }
        foreach (var c in cia.Contents)
        {
            ct.ThrowIfCancellationRequested();
            string prefix = $"Content {c.Chunk.Index}: ";
            var data = cia.OpenContent(fs, c, _keys, titleKey);
            using var sha = new MultiHasher(HashKinds.Sha256);
            StreamCopier.CopyAll(data, null, null, ct, sha);
            bool ok = string.Equals(sha.Finish().Sha256, MultiHasher.Hex(c.Chunk.Hash), StringComparison.Ordinal);
            checks.Add(new IntegrityCheck(prefix + "TMD SHA-256", ok ? CheckStatus.Pass : CheckStatus.Fail,
                ok ? null : "content does not match its TMD hash"));
            if (ok && data.Length >= 0x200 && NcchHeader.IsNcch(VirtualStream.ReadBytesAt(data, 0, 0x200)))
                CheckNcch(data, prefix, checks);
        }
    }
}

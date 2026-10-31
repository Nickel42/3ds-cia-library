using NoIntrovert.Core.IO;
using NoIntrovert.Dat;

namespace NoIntrovert.Ctr.Verification;

/// <summary>
/// Verifies 3DS files and plans renames: DAT names for verified files, and metadata-based
/// names (SMDH title, region, product code) for files that are not in any DAT.
/// </summary>
public sealed class CtrRenameService
{
    private readonly CtrVerifier _verifier;

    public CtrRenameService(CtrVerifier verifier) => _verifier = verifier;

    /// <summary>Template fields available for a file: title, longtitle, publisher, region, serial, titleid, version, name, romname.</summary>
    public static Dictionary<string, string?> FieldsFor(CtrFileInfo info) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["title"] = info.Titles?.ShortTitle,
        ["longtitle"] = info.Titles?.LongTitle,
        ["publisher"] = info.Titles?.Publisher,
        ["region"] = info.Region,
        ["serial"] = info.ProductCode,
        ["titleid"] = info.TitleId == 0 ? null : info.TitleIdHex,
        ["version"] = info.TitleVersion == 0 ? null : $"v{info.TitleVersion}",
    };

    public static RenameCandidate CandidateFor(CtrVerifyReport report) => new()
    {
        SourcePath = report.Info.Path,
        Match = report.Match,
        Fields = FieldsFor(report.Info),
    };

    /// <summary>Verify every file and build a rename plan (nothing is renamed until <see cref="RenamePlanner.Apply"/>).</summary>
    public async Task<(IReadOnlyList<CtrVerifyReport> Reports, IReadOnlyList<RenamePlanEntry> Plan)> PlanAsync(
        IEnumerable<string> files, RenameOptions? options = null, CtrVerifyOptions? verifyOptions = null,
        IProgress<OperationProgress>? progress = null, CancellationToken ct = default)
    {
        var reports = new List<CtrVerifyReport>();
        var list = files.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(new OperationProgress($"Verifying {Path.GetFileName(list[i])}", i, list.Count));
            reports.Add(await _verifier.VerifyAsync(list[i], verifyOptions, null, ct).ConfigureAwait(false));
        }
        progress?.Report(new OperationProgress("Planning renames", list.Count, list.Count));
        var plan = RenamePlanner.Plan(reports.Select(CandidateFor), options);
        return (reports, plan);
    }

    /// <summary>3DS files directly in (or below) a folder.</summary>
    public static IEnumerable<string> FindFiles(string directory, bool recursive) =>
        Directory.EnumerateFiles(directory, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(f => CtrFile.Extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)
                        && !f.EndsWith(".3dsx", StringComparison.OrdinalIgnoreCase));
}

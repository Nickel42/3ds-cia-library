using System.Text;
using System.Text.RegularExpressions;

namespace NoIntrovert.Dat;

/// <summary>Makes strings safe to use as file names on Windows, macOS and Linux.</summary>
public static class FileNameSanitizer
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static string Sanitize(string name, int maxLength = 200)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            switch (c)
            {
                case ':': sb.Append(" -"); break;
                case '/': case '\\': case '|': sb.Append('-'); break;
                case '?': case '*': break;
                case '"': sb.Append('\''); break;
                case '<': sb.Append('('); break;
                case '>': sb.Append(')'); break;
                default:
                    if (c >= 0x20) sb.Append(c);
                    break;
            }
        }
        string s = Regex.Replace(sb.ToString(), @"\s{2,}", " ").Trim().TrimEnd('.', ' ');
        if (s.Length == 0) s = "_";
        if (Reserved.Contains(s.Split('.')[0])) s = "_" + s;
        if (s.Length > maxLength) s = s[..maxLength].TrimEnd('.', ' ');
        return s;
    }
}

/// <summary>
/// Expands templates like <c>"{title} ({region}) [{serial}]"</c>. Unknown or empty tokens
/// expand to nothing, and the brackets/parentheses left empty by them are removed.
/// </summary>
public static class FileNameTemplate
{
    private static readonly Regex Token = new(@"\{([A-Za-z0-9_]+)\}", RegexOptions.Compiled);

    public static string Expand(string template, IReadOnlyDictionary<string, string?> fields)
    {
        string s = Token.Replace(template, m =>
            fields.TryGetValue(m.Groups[1].Value, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : "");
        // drop empty () [] {} groups and tidy spacing
        s = Regex.Replace(s, @"\(\s*\)|\[\s*\]", "");
        s = Regex.Replace(s, @"\s{2,}", " ").Trim();
        return s;
    }
}

/// <summary>What a renamer knows about one file.</summary>
public sealed class RenameCandidate
{
    public required string SourcePath { get; init; }
    /// <summary>DAT match, if any. A verified match uses the DAT game name.</summary>
    public DatMatch Match { get; init; } = DatMatch.NoMatch;
    /// <summary>Template fields for the fallback name (title, region, serial, titleid, version...).</summary>
    public Dictionary<string, string?> Fields { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Extension to give the new file (including the dot). Defaults to the source extension.</summary>
    public string? Extension { get; init; }
}

public enum RenameAction { Rename, Unchanged, Skip, Conflict }

public sealed record RenamePlanEntry(string SourcePath, string? TargetPath, RenameAction Action, string Reason);

public sealed class RenameOptions
{
    /// <summary>Template used when the file has a verified (hash) DAT match.</summary>
    public string VerifiedTemplate { get; init; } = "{name}";
    /// <summary>Template used without a hash match. Set to null to leave such files alone.</summary>
    public string? FallbackTemplate { get; init; } = "{title} ({region}) [{serial}]";
    /// <summary>Allow naming from a serial-only DAT match (not hash verified).</summary>
    public bool UseSerialMatches { get; init; } = true;
    /// <summary>Use the DAT rom name's extension instead of the source file's.</summary>
    public bool UseDatExtension { get; init; }
}

/// <summary>Builds and applies rename plans. Planning never touches the disk.</summary>
public static class RenamePlanner
{
    public static IReadOnlyList<RenamePlanEntry> Plan(IEnumerable<RenameCandidate> candidates, RenameOptions? options = null)
    {
        options ??= new RenameOptions();
        var plan = new List<RenamePlanEntry>();
        var claimed = new HashSet<string>(OperatingSystem.IsLinux() ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(c.SourcePath)) ?? ".";
            string ext = c.Extension ?? Path.GetExtension(c.SourcePath);
            string? baseName = null;
            string reason;
            var fields = new Dictionary<string, string?>(c.Fields, StringComparer.OrdinalIgnoreCase);
            if (c.Match.Rom is { } rom)
            {
                fields["name"] = rom.Game.Name;
                fields["romname"] = Path.GetFileNameWithoutExtension(rom.Name);
                if (options.UseDatExtension && Path.HasExtension(rom.Name)) ext = Path.GetExtension(rom.Name);
            }
            if (c.Match.IsVerified)
            {
                baseName = FileNameTemplate.Expand(options.VerifiedTemplate, fields);
                reason = $"DAT {c.Match.Kind} match";
            }
            else if (c.Match.Kind == DatMatchKind.Serial && options.UseSerialMatches)
            {
                baseName = FileNameTemplate.Expand(options.VerifiedTemplate, fields);
                reason = "DAT serial match (not hash-verified)";
            }
            else if (options.FallbackTemplate is not null)
            {
                baseName = FileNameTemplate.Expand(options.FallbackTemplate, fields);
                reason = "no DAT match; named from file metadata";
            }
            else
            {
                plan.Add(new(c.SourcePath, null, RenameAction.Skip, "no DAT match"));
                continue;
            }

            if (string.IsNullOrWhiteSpace(baseName))
            {
                plan.Add(new(c.SourcePath, null, RenameAction.Skip, "template produced an empty name"));
                continue;
            }
            string target = Path.Combine(dir, FileNameSanitizer.Sanitize(baseName) + ext);
            string source = Path.GetFullPath(c.SourcePath);
            if (string.Equals(target, source, StringComparison.Ordinal))
            {
                claimed.Add(target);
                plan.Add(new(c.SourcePath, target, RenameAction.Unchanged, reason));
                continue;
            }
            bool sameFileDifferentCase = string.Equals(target, source, StringComparison.OrdinalIgnoreCase);
            if (claimed.Contains(target) || (File.Exists(target) && !sameFileDifferentCase))
            {
                plan.Add(new(c.SourcePath, target, RenameAction.Conflict, "target name already taken"));
                continue;
            }
            claimed.Add(target);
            plan.Add(new(c.SourcePath, target, RenameAction.Rename, reason));
        }
        return plan;
    }

    /// <summary>Apply the Rename entries of a plan. Returns entries that failed with their error.</summary>
    public static IReadOnlyList<(RenamePlanEntry Entry, Exception Error)> Apply(IEnumerable<RenamePlanEntry> plan)
    {
        var failures = new List<(RenamePlanEntry, Exception)>();
        foreach (var e in plan)
        {
            if (e.Action != RenameAction.Rename || e.TargetPath is null) continue;
            try
            {
                if (string.Equals(Path.GetFullPath(e.SourcePath), e.TargetPath, StringComparison.OrdinalIgnoreCase))
                {
                    // case-only rename on case-insensitive file systems: go through a temp name
                    string tmp = e.TargetPath + ".renaming";
                    File.Move(e.SourcePath, tmp);
                    File.Move(tmp, e.TargetPath);
                }
                else
                {
                    File.Move(e.SourcePath, e.TargetPath, overwrite: false);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failures.Add((e, ex));
            }
        }
        return failures;
    }
}

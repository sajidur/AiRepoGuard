using System.Text.RegularExpressions;

namespace OrgDlp.Core;

public sealed record Finding(
    string Rule,
    string Category,
    string Severity,
    string Message,
    string Path,
    long MatchCount,
    string? Sample);

public sealed class DetectionEngine
{
    private static readonly string[] TextExtensions =
    [".cs", ".json", ".xml", ".config", ".yml", ".yaml", ".toml", ".ini", ".ps1", ".sh",
     ".sql", ".js", ".ts", ".py", ".env", ".txt", ".md", ".csv", ".log", ".rtf", ".html"];

    private static readonly Dictionary<string, byte[]> MagicBytes = new()
    {
        [".zip"] = [0x50, 0x4B],
        [".docx"] = [0x50, 0x4B],
        [".xlsx"] = [0x50, 0x4B],
        [".pdf"] = [0x25, 0x50, 0x44, 0x46],
        [".png"] = [0x89, 0x50, 0x4E, 0x47],
        [".jpg"] = [0xFF, 0xD8],
        [".jpeg"] = [0xFF, 0xD8],
    };

    private readonly IReadOnlyList<IDataClassifier> _classifiers;
    private readonly List<DocumentFingerprinter> _edm;

    public DetectionEngine(DlpPolicy policy)
    {
        var list = new List<IDataClassifier>(BuiltInClassifiers.All());
        foreach (var r in policy.CustomRegexRules)
            list.Add(new RegexClassifier(r.Name, r.Category, r.Severity, r.Description, r.Pattern, r.MinMatches));
        _classifiers = list;
        _edm = policy.Edm.ReferenceFiles
            .Where(File.Exists)
            .Select(f => new DocumentFingerprinter(File.ReadAllText(f)))
            .ToList();
    }

    public IReadOnlyList<Finding> Scan(string root, DlpPolicy policy)
    {
        var findings = new List<Finding>();
        var files = Enumerate(root, policy).Take(policy.MaximumFilesToScan).ToList();

        foreach (var (relative, full) in files)
        {
            var normalized = relative.Replace('\\', '/');
            foreach (var pattern in policy.SensitiveFilePatterns)
                if (GlobLikeMatch(normalized, pattern))
                    findings.Add(new Finding("SENSITIVE_PATH", "FS", "HIGH",
                        "Path matches sensitive-file policy", relative, 1, null));

            if (!IsInspectable(full)) continue;
            var info = new FileInfo(full);
            if (info.Length > policy.MaximumFileBytes) continue;

            string content;
            try { content = File.ReadAllText(full); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }

            foreach (var classifier in _classifiers)
            {
                var c = classifier.Classify(content, relative);
                if (c is not null)
                    findings.Add(new Finding(c.RuleName, c.Category, c.Severity,
                        c.Description, relative, c.MatchCount, c.Sample));
            }

            foreach (var fp in _edm)
                if (fp.Similarity(content) >= policy.Edm.SimilarityThreshold)
                {
                    findings.Add(new Finding("EDM_SIMILAR", "CUSTOM", "MEDIUM",
                        "Content is similar to a protected record set", relative, 1, null));
                    break;
                }
        }
        return findings;
    }

    /// <summary>Produces a redacted copy of a file with every detected value masked.</summary>
    public string RedactFile(string path)
    {
        var content = File.ReadAllText(path);
        foreach (var c in _classifiers.OfType<RegexClassifier>()) content = c.Redact(content);
        return content;
    }

    private static IEnumerable<(string Relative, string Full)> Enumerate(string root, DlpPolicy policy)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> dirs, files;
            try { dirs = Directory.EnumerateDirectories(dir).ToArray(); files = Directory.EnumerateFiles(dir).ToArray(); }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var f in files) yield return (Path.GetRelativePath(root, f), f);
            foreach (var d in dirs)
                if (!policy.ExcludedDirectories.Contains(Path.GetFileName(d), StringComparer.OrdinalIgnoreCase))
                    stack.Push(d);
        }
    }

    private static bool IsInspectable(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (TextExtensions.Contains(ext)) return true;
        if (!MagicBytes.TryGetValue(ext, out var magic)) return false;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[magic.Length];
            return fs.Read(buf, 0, magic.Length) == magic.Length && buf.SequenceEqual(magic);
        }
        catch { return false; }
    }

    private static bool GlobLikeMatch(string path, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern.Replace('\\', '/')).Replace("\\*\\*", ".*").Replace("\\*", "[^/]*") + "$";
        return Regex.IsMatch(path, regex, RegexOptions.IgnoreCase);
    }
}
using System.Text.Json;
using OrgDlp.Core;

namespace AiRepoGuard;

// `scan` subcommand: runs the OrgDlp.Core content-DLP engine over a path,
// classifying files for PII/PCI/PHI/secrets and EDM (golden-record) matches.
// Optionally writes redacted copies and quarantines offending files. This
// inspects files the operator points it at; it does not watch users.
internal static class ScanCommand
{
    public static int Run(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.WriteLine(
                "Content DLP scan - classify files for PII/PCI/PHI/secrets and EDM matches.\n" +
                "Usage:\n" +
                "  airepoguard scan <path> [--policy <dlp-policy.json>] [--redact] [--quarantine]\n\n" +
                "  --policy      DLP policy JSON (default <path>/dlp-policy.json, else built-in defaults)\n" +
                "  --redact      Write masked copies of matching files to the policy's redacted directory\n" +
                "  --quarantine  Copy matching files to the policy's quarantine directory\n\n" +
                "Exit codes: 0 no HIGH findings, 3 one or more HIGH findings, 2 usage/path error.\n");
            return args.Length < 1 ? 2 : 0;
        }

        var root = Path.GetFullPath(args[0]);
        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine($"Path does not exist: {root}");
            return 2;
        }

        var policyPath = GetOption(args, "--policy") ?? Path.Combine(root, "dlp-policy.json");
        DlpPolicy policy;
        try { policy = DlpPolicy.Load(policyPath); }
        catch (JsonException ex) { Console.Error.WriteLine($"Invalid policy JSON: {ex.Message}"); return 2; }

        var engine = new DetectionEngine(policy);
        var findings = engine.Scan(root, policy);

        foreach (var f in findings.OrderByDescending(x => Rank(x.Severity)).ThenBy(x => x.Path, StringComparer.Ordinal))
        {
            var old = Console.ForegroundColor;
            Console.ForegroundColor = f.Severity switch
            {
                "HIGH" => ConsoleColor.Red,
                "MEDIUM" => ConsoleColor.Yellow,
                _ => ConsoleColor.Cyan,
            };
            Console.Write($"[{f.Severity}] {f.Rule} ({f.Category}): ");
            Console.ForegroundColor = old;
            var sample = string.IsNullOrEmpty(f.Sample) ? "" : $" e.g. {f.Sample}";
            Console.WriteLine($"{f.Message} ({f.Path}) x{f.MatchCount}{sample}");
        }

        var affected = findings.Select(f => f.Path).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var redact = HasFlag(args, "--redact") || policy.Actions.WriteRedactedCopy;
        var quarantine = HasFlag(args, "--quarantine");
        if (redact) WriteCopies(root, affected, Path.Combine(root, policy.Actions.RedactedDirectory), engine.RedactFile, "Redacted");
        if (quarantine) WriteCopies(root, affected, Path.Combine(root, policy.Actions.QuarantineDirectory), File.ReadAllText, "Quarantined");

        var reportPath = WriteReport(root, policyPath, findings);
        var high = findings.Count(f => f.Severity == "HIGH");
        var medium = findings.Count(f => f.Severity == "MEDIUM");

        Console.WriteLine($"\nReport: {reportPath}");
        Console.WriteLine($"Findings: {findings.Count} ({high} HIGH, {medium} MEDIUM) across {affected.Count} file(s).");
        Console.WriteLine(high == 0 ? "RESULT: PASS" : $"RESULT: BLOCKED ({high} HIGH finding(s))");
        return high > 0 ? 3 : 0;
    }

    private static void WriteCopies(string root, IEnumerable<string> relatives, string targetDir,
        Func<string, string> transform, string verb)
    {
        var count = 0;
        foreach (var relative in relatives)
        {
            try
            {
                var source = Path.Combine(root, relative);
                var dest = Path.Combine(targetDir, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.WriteAllText(dest, transform(source));
                count++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"  {verb} failed for {relative}: {ex.GetType().Name}");
            }
        }
        if (count > 0) Console.WriteLine($"{verb} {count} file(s) to {targetDir}");
    }

    private static string WriteReport(string root, string policyPath, IReadOnlyList<Finding> findings)
    {
        var report = new
        {
            tool = "AiRepoGuard",
            mode = "scan",
            repository = root,
            policy = policyPath,
            generatedAtUtc = DateTimeOffset.UtcNow,
            high = findings.Count(f => f.Severity == "HIGH"),
            medium = findings.Count(f => f.Severity == "MEDIUM"),
            low = findings.Count(f => f.Severity == "LOW"),
            findingCount = findings.Count,
            findings,
        };
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AIRepoGuard", "Reports");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "airepoguard-dlp-scan.json");
        File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        return path;
    }

    private static int Rank(string severity) => severity switch { "HIGH" => 3, "MEDIUM" => 2, _ => 1 };

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 1; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static bool HasFlag(string[] args, string name) =>
        args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
}

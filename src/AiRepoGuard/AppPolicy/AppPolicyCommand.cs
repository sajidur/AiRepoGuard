using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace AiRepoGuard.AppPolicy;

// `app-policy` subcommand: compiles app-policy.json (a list of executables to
// block, by path / publisher / file hash) into an AppLocker policy XML that
// Windows enforces at the OS level. AppLocker is admin-managed, visible, and
// reversible - it denies named executables, it does not hook or kill processes.
//
// Defaults to EnforcementMode "AuditOnly" so you can see what WOULD be blocked
// (event log) before switching to "Enabled". Apply with Apply-AppLockerPolicy.ps1
// or distribute via PolicyServer + PolicyAgent. See docs/app-control.md.
internal static class AppPolicyCommand
{
    private const string Everyone = "S-1-1-0";
    private static readonly string[] Modes = ["NotConfigured", "AuditOnly", "Enabled"];

    public static int Run(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.WriteLine(
                "app-policy - compile app-policy.json into an AppLocker policy XML.\n" +
                "Usage:\n" +
                "  airepoguard app-policy <app-policy.json> [--out <dir>]\n\n" +
                "Output: <dir>/AppLocker.xml  (default <config-dir>/out)\n" +
                "Apply it with security/app-policy/Apply-AppLockerPolicy.ps1 (admin),\n" +
                "or PUT it to PolicyServer for PolicyAgent to distribute.\n");
            return args.Length < 1 ? 2 : 0;
        }

        var configPath = Path.GetFullPath(args[0]);
        if (!File.Exists(configPath)) { Console.Error.WriteLine($"Config not found: {configPath}"); return 2; }
        var outDir = GetOption(args, "--out") ?? Path.Combine(Path.GetDirectoryName(configPath)!, "out");

        AppPolicyFile? policy;
        try { policy = JsonSerializer.Deserialize<AppPolicyFile>(File.ReadAllText(configPath), JsonOpts); }
        catch (JsonException ex) { Console.Error.WriteLine($"Invalid JSON: {ex.Message}"); return 2; }
        if (policy is null) { Console.Error.WriteLine("Config deserialized to null."); return 2; }

        var mode = string.IsNullOrWhiteSpace(policy.EnforcementMode) ? "AuditOnly" : policy.EnforcementMode;
        if (!Modes.Contains(mode, StringComparer.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"enforcementMode '{mode}' invalid; allowed: {string.Join(", ", Modes)}.");
            return 2;
        }

        var errors = new List<string>();
        var rules = new List<XElement>();

        // Baseline: allow everything, so only the Deny rules below actually block
        // (a non-empty Exe collection otherwise blocks everything not allowed).
        rules.Add(new XElement("FilePathRule",
            new XAttribute("Id", NewId()), new XAttribute("Name", "(baseline) Allow all executables"),
            new XAttribute("Description", "Generated baseline so only explicit Deny rules block."),
            new XAttribute("UserOrGroupSid", Everyone), new XAttribute("Action", "Allow"),
            new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", "*")))));

        var denyCount = 0;
        foreach (var rule in policy.Block ?? [])
        {
            var name = string.IsNullOrWhiteSpace(rule.Name) ? "Blocked executable" : rule.Name!;
            var desc = rule.Reason ?? "";
            var element = (rule.Type ?? "").ToLowerInvariant() switch
            {
                "path" => BuildPath(name, desc, rule, errors),
                "publisher" => BuildPublisher(name, desc, rule, errors),
                "hash" => BuildHash(name, desc, rule, errors),
                _ => Fail(errors, $"Rule '{name}': type must be path, publisher, or hash (got '{rule.Type}')."),
            };
            if (element is not null) { rules.Add(element); denyCount++; }
        }

        if (errors.Count > 0)
        {
            Console.Error.WriteLine("Policy validation failed:");
            foreach (var e in errors) Console.Error.WriteLine("  - " + e);
            return 2;
        }

        var doc = new XDocument(
            new XElement("AppLockerPolicy", new XAttribute("Version", "1"),
                new XElement("RuleCollection",
                    new XAttribute("Type", "Exe"),
                    new XAttribute("EnforcementMode", Modes.First(m => m.Equals(mode, StringComparison.OrdinalIgnoreCase))),
                    rules)));

        Directory.CreateDirectory(outDir);
        var outPath = Path.Combine(outDir, "AppLocker.xml");
        doc.Save(outPath);

        Console.WriteLine($"Compiled {denyCount} block rule(s) into Exe collection (EnforcementMode={mode}).");
        Console.WriteLine($"Output: {outPath}");
        if (mode.Equals("AuditOnly", StringComparison.OrdinalIgnoreCase))
            Console.WriteLine("AuditOnly: blocks are logged (not enforced). Review events, then set enforcementMode=Enabled.");
        return 0;
    }

    private static XElement? BuildPath(string name, string desc, AppRule rule, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(rule.Path)) return Fail(errors, $"Rule '{name}': path rule needs 'path'.");
        return new XElement("FilePathRule",
            new XAttribute("Id", NewId()), new XAttribute("Name", name), new XAttribute("Description", desc),
            new XAttribute("UserOrGroupSid", Everyone), new XAttribute("Action", "Deny"),
            new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", rule.Path!))));
    }

    private static XElement? BuildPublisher(string name, string desc, AppRule rule, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(rule.Publisher)) return Fail(errors, $"Rule '{name}': publisher rule needs 'publisher'.");
        return new XElement("FilePublisherRule",
            new XAttribute("Id", NewId()), new XAttribute("Name", name), new XAttribute("Description", desc),
            new XAttribute("UserOrGroupSid", Everyone), new XAttribute("Action", "Deny"),
            new XElement("Conditions", new XElement("FilePublisherCondition",
                new XAttribute("PublisherName", rule.Publisher!),
                new XAttribute("ProductName", string.IsNullOrWhiteSpace(rule.Product) ? "*" : rule.Product!),
                new XAttribute("BinaryName", string.IsNullOrWhiteSpace(rule.Binary) ? "*" : rule.Binary!),
                new XElement("BinaryVersionRange", new XAttribute("LowSection", "*"), new XAttribute("HighSection", "*")))));
    }

    private static XElement? BuildHash(string name, string desc, AppRule rule, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(rule.Path) || !File.Exists(rule.Path))
            return Fail(errors, $"Rule '{name}': hash rule needs 'path' to an existing file to hash.");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(rule.Path!); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { return Fail(errors, $"Rule '{name}': cannot read '{rule.Path}': {ex.GetType().Name}."); }

        var hash = "0x" + Convert.ToHexString(SHA256.HashData(bytes));
        return new XElement("FileHashRule",
            new XAttribute("Id", NewId()), new XAttribute("Name", name), new XAttribute("Description", desc),
            new XAttribute("UserOrGroupSid", Everyone), new XAttribute("Action", "Deny"),
            new XElement("Conditions", new XElement("FileHashCondition",
                new XElement("FileHash",
                    new XAttribute("Type", "SHA256"), new XAttribute("Data", hash),
                    new XAttribute("SourceFileName", Path.GetFileName(rule.Path!)),
                    new XAttribute("SourceFileLength", bytes.Length)))));
    }

    private static XElement? Fail(List<string> errors, string message) { errors.Add(message); return null; }

    private static string NewId() => Guid.NewGuid().ToString("B");

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 1; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private sealed class AppPolicyFile
    {
        public int Version { get; init; }
        public string? EnforcementMode { get; init; }
        public List<AppRule>? Block { get; init; }
    }

    private sealed class AppRule
    {
        public string? Type { get; init; }       // path | publisher | hash
        public string? Name { get; init; }
        public string? Reason { get; init; }
        public string? Path { get; init; }        // path rule, or file to hash
        public string? Publisher { get; init; }   // publisher rule
        public string? Product { get; init; }
        public string? Binary { get; init; }
    }
}

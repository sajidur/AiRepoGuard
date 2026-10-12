using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AiRepoGuard.UrlPolicy;

// `url-policy` subcommand: reads url-policy.json (the single source of truth for
// monitored vs. blocked destinations) and compiles it into the import formats
// each enforcement point needs: Microsoft Defender for Endpoint indicators, a
// Purview sensitive-service domain list, a plain SWG/DNS blocklist, and a KQL
// hunting filter.
//
// This only generates config artifacts; it does not push anything or touch
// devices. Review the outputs, then import them into the relevant console.
internal static partial class UrlPolicyCommand
{
    private static readonly string[] MonitorActions = ["Audit", "Warn", "Allowed"];
    private static readonly string[] BlockActions = ["Block", "Warn", "BlockAndRemediate"];

    public static int Run(string[] args)
    {
        if (args.Length < 1 || args[0] is "-h" or "--help")
        {
            Console.WriteLine(
                "url-policy - compile url-policy.json into enforcement-tool exports\n" +
                "Usage:\n" +
                "  airepoguard url-policy <url-policy.json> [--out <dir>]\n\n" +
                "Outputs (into <dir>, default <config-dir>/out):\n" +
                "  browser-urlblocklist.reg       Edge/Chrome enterprise URL blocklist (actually blocks in-browser)\n" +
                "  hosts.txt                      0.0.0.0 host entries for the Windows hosts file\n" +
                "  blocklist-domains.txt          Feed a secure web gateway / DNS filter\n" +
                "  defender-indicators.csv        Import under Defender > Settings > Endpoints > Indicators\n" +
                "  purview-sensitive-domains.txt  Paste into the Purview sensitive service domain group\n" +
                "  monitor-kql.txt                Advanced Hunting / Sentinel filter for monitored domains\n");
            return args.Length < 1 ? 2 : 0;
        }

        var configPath = Path.GetFullPath(args[0]);
        if (!File.Exists(configPath))
        {
            Console.Error.WriteLine($"Config not found: {configPath}");
            return 2;
        }
        var outDir = GetOption(args, "--out")
                     ?? Path.Combine(Path.GetDirectoryName(configPath)!, "out");

        PolicyFile? policy;
        try
        {
            policy = JsonSerializer.Deserialize<PolicyFile>(File.ReadAllText(configPath), JsonOpts);
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"Invalid JSON: {ex.Message}");
            return 2;
        }
        if (policy is null)
        {
            Console.Error.WriteLine("Config deserialized to null.");
            return 2;
        }

        var errors = new List<string>();
        var monitor = Normalize(policy.Monitor, DefaultOf(policy.Defaults?.MonitorAction, "Audit"), MonitorActions, "monitor", errors);
        var block = Normalize(policy.Block, DefaultOf(policy.Defaults?.BlockAction, "Block"), BlockActions, "block", errors);

        // A domain can't be both monitored and blocked.
        var conflicts = monitor.Keys.Intersect(block.Keys, StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var c in conflicts)
            errors.Add($"Domain '{c}' appears in both monitor and block lists.");

        if (errors.Count > 0)
        {
            Console.Error.WriteLine("Policy validation failed:");
            foreach (var e in errors) Console.Error.WriteLine("  - " + e);
            return 2;
        }

        Directory.CreateDirectory(outDir);
        WriteDefenderCsv(Path.Combine(outDir, "defender-indicators.csv"), monitor.Values, block.Values);
        WriteLines(Path.Combine(outDir, "purview-sensitive-domains.txt"), monitor.Keys);
        WriteLines(Path.Combine(outDir, "blocklist-domains.txt"), block.Keys);
        WriteKql(Path.Combine(outDir, "monitor-kql.txt"), monitor.Keys);
        // Enforcement artifacts that actually block on the local machine:
        WriteBrowserReg(Path.Combine(outDir, "browser-urlblocklist.reg"), block.Keys);
        WriteHosts(Path.Combine(outDir, "hosts.txt"), block.Keys);

        Console.WriteLine($"Compiled {monitor.Count} monitored + {block.Count} blocked domain(s).");
        Console.WriteLine($"Output: {outDir}");
        Console.WriteLine("To actually block in-browser, apply browser-urlblocklist.reg (admin) " +
                          "or import blocklist-domains.txt into your DNS filter / gateway. Compiling alone does not block.");
        return 0;
    }

    // ---- Normalization + validation ----------------------------------------

    private static Dictionary<string, Rule> Normalize(
        List<Entry>? entries, string listDefaultAction, string[] allowed, string listName, List<string> errors)
    {
        var result = new Dictionary<string, Rule>(StringComparer.OrdinalIgnoreCase);
        if (entries is null) return result;

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Domain))
            {
                errors.Add($"[{listName}] entry with empty domain.");
                continue;
            }
            var domain = NormalizeDomain(entry.Domain);
            if (!DomainPattern().IsMatch(domain))
            {
                errors.Add($"[{listName}] '{entry.Domain}' is not a valid domain or wildcard.");
                continue;
            }
            var action = entry.Action ?? listDefaultAction;
            if (!allowed.Contains(action, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add($"[{listName}] '{domain}' has action '{action}'; allowed: {string.Join(", ", allowed)}.");
                continue;
            }
            // De-duplicate within the list (last one wins, but warn on differing action).
            if (result.TryGetValue(domain, out var existing) && !existing.Action.Equals(action, StringComparison.OrdinalIgnoreCase))
                errors.Add($"[{listName}] '{domain}' listed twice with different actions ('{existing.Action}' vs '{action}').");
            result[domain] = new Rule(domain, action, entry.Category ?? "", entry.Reason ?? "");
        }
        return result;
    }

    private static string NormalizeDomain(string raw)
    {
        var s = raw.Trim().ToLowerInvariant();
        var scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];
        var slash = s.IndexOf('/');
        if (slash >= 0) s = s[..slash];
        var colon = s.IndexOf(':');          // strip port
        if (colon >= 0) s = s[..colon];
        return s.TrimEnd('.');
    }

    // ---- Exports ------------------------------------------------------------

    private static void WriteDefenderCsv(string path, IEnumerable<Rule> monitor, IEnumerable<Rule> block)
    {
        var sb = new StringBuilder();
        // Column order accepted by the Defender for Endpoint indicator import template.
        sb.AppendLine("IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups");
        foreach (var r in monitor.Concat(block))
        {
            var severity = r.Action is "Block" or "BlockAndRemediate" ? "High" : "Informational";
            var title = $"URL policy: {r.Action} {r.Domain}";
            var desc = string.IsNullOrEmpty(r.Reason) ? r.Category : $"{r.Category}: {r.Reason}";
            sb.AppendLine(string.Join(",",
                Csv("DomainName"), Csv(r.Domain), Csv(""), Csv(r.Action), Csv(severity),
                Csv(title), Csv(desc), Csv(""), Csv("")));
        }
        File.WriteAllText(path, sb.ToString(), Utf8NoBom);
    }

    private static void WriteLines(string path, IEnumerable<string> domains) =>
        File.WriteAllText(path, string.Join('\n', domains.OrderBy(d => d, StringComparer.Ordinal)) + "\n", Utf8NoBom);

    private static void WriteKql(string path, IEnumerable<string> domains)
    {
        var list = domains.OrderBy(d => d, StringComparer.Ordinal).ToList();
        var sb = new StringBuilder();
        sb.AppendLine("// Monitored destinations - Defender Advanced Hunting / Sentinel.");
        if (list.Count == 0)
        {
            sb.AppendLine("// (no monitored domains)");
        }
        else
        {
            var quoted = string.Join(", ", list.Select(d => "\"" + d.TrimStart('*', '.') + "\""));
            sb.AppendLine("DeviceNetworkEvents");
            sb.AppendLine($"| where RemoteUrl has_any ({quoted})");
            sb.AppendLine("| summarize Connections=count(), Devices=dcount(DeviceId) by RemoteUrl, InitiatingProcessAccountUpn");
            sb.AppendLine("| order by Connections desc");
        }
        File.WriteAllText(path, sb.ToString(), Utf8NoBom);
    }

    // Edge/Chrome enterprise URL blocklist policy. This is what actually blocks
    // the sites in-browser on a managed device; it is read from HKLM and is
    // visible to the user at edge://policy / chrome://policy. A plain host filter
    // blocks that host and its subdomains, so a wildcard entry collapses to apex.
    private static void WriteBrowserReg(string path, IEnumerable<string> blockDomains)
    {
        var apex = ApexDomains(blockDomains).ToList();
        var sb = new StringBuilder();
        sb.AppendLine("Windows Registry Editor Version 5.00");
        sb.AppendLine();
        sb.AppendLine("; Generated by airepoguard url-policy - enterprise browser URL blocklist.");
        sb.AppendLine("; Apply on a managed device (admin):  reg import browser-urlblocklist.reg");
        sb.AppendLine("; Blocks these hosts and subdomains in Microsoft Edge and Google Chrome.");
        sb.AppendLine("; Verify at edge://policy or chrome://policy; restart the browser to apply.");
        foreach (var (name, key) in new[]
        {
            ("Microsoft Edge", @"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist"),
            ("Google Chrome", @"SOFTWARE\Policies\Google\Chrome\URLBlocklist"),
        })
        {
            sb.AppendLine();
            sb.AppendLine($"; --- {name} ---");
            sb.AppendLine($"[HKEY_LOCAL_MACHINE\\{key}]");
            for (var i = 0; i < apex.Count; i++)
                sb.AppendLine($"\"{i + 1}\"=\"{apex[i]}\"");
        }
        // reg.exe is most reliable with UTF-16 LE + BOM.
        File.WriteAllText(path, sb.ToString(), new UnicodeEncoding(bigEndian: false, byteOrderMark: true));
    }

    private static void WriteHosts(string path, IEnumerable<string> blockDomains)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Generated by airepoguard url-policy. Merge into");
        sb.AppendLine("# C:\\Windows\\System32\\drivers\\etc\\hosts as administrator.");
        sb.AppendLine("# NOTE: browsers using DNS-over-HTTPS can bypass the hosts file; prefer");
        sb.AppendLine("# browser-urlblocklist.reg or a DNS filter for reliable blocking.");
        foreach (var d in ApexDomains(blockDomains))
        {
            sb.AppendLine($"0.0.0.0 {d}");
            sb.AppendLine($"0.0.0.0 www.{d}");
        }
        File.WriteAllText(path, sb.ToString(), Utf8NoBom);
    }

    // Collapse wildcards to the apex host and de-duplicate.
    private static IEnumerable<string> ApexDomains(IEnumerable<string> domains) =>
        domains.Select(d => d.StartsWith("*.", StringComparison.Ordinal) ? d[2..] : d)
               .Distinct(StringComparer.OrdinalIgnoreCase)
               .OrderBy(d => d, StringComparer.Ordinal);

    // ---- Helpers ------------------------------------------------------------

    private static string Csv(string value)
    {
        if (value.IndexOfAny([',', '"', '\n', '\r']) < 0) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private static string DefaultOf(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 1; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    [GeneratedRegex(@"^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+$")]
    private static partial Regex DomainPattern();

    // ---- Model --------------------------------------------------------------

    private sealed record Rule(string Domain, string Action, string Category, string Reason);

    private sealed class PolicyFile
    {
        public int Version { get; init; }
        public Defaults? Defaults { get; init; }
        public List<Entry>? Monitor { get; init; }
        public List<Entry>? Block { get; init; }
    }

    private sealed class Defaults
    {
        public string? MonitorAction { get; init; }
        public string? BlockAction { get; init; }
    }

    private sealed class Entry
    {
        public string Domain { get; init; } = "";
        public string? Category { get; init; }
        public string? Reason { get; init; }
        public string? Action { get; init; }
        [JsonPropertyName("$schema")] public string? Schema { get; init; }
    }
}

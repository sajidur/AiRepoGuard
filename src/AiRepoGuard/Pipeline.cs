using System.Text.Json;
using AiRepoGuard.AppPolicy;
using AiRepoGuard.Dlp;
using AiRepoGuard.UrlPolicy;

namespace AiRepoGuard;

// Default "do everything" pipeline: runs with NO arguments. Reads airepoguard.json
// (from the working dir, or next to the exe) for paths, then runs each enabled
// step - audit, content scan, url-policy compile, app-policy compile, and
// optionally a collect report. Steps that need credentials (collect pull) or
// elevation (applying blocklists) are never run blind here.
internal static class Pipeline
{
    public static async Task<int> RunAsync(string[] args)
    {
        var configPath = args.Length >= 1 && !args[0].StartsWith('-') ? Path.GetFullPath(args[0]) : FindConfig();
        var baseDir = configPath is not null ? Path.GetDirectoryName(configPath)! : Directory.GetCurrentDirectory();
        var cfg = Load(configPath);

        Console.WriteLine("AI Repo Guard - running default pipeline (no arguments).");
        Console.WriteLine(configPath is not null
            ? $"Config: {configPath}"
            : "Config: built-in defaults (no airepoguard.json found)");

        var repo = Resolve(baseDir, cfg.RepoPath) ?? Directory.GetCurrentDirectory();
        var results = new List<(string Step, string Outcome)>();

        if (cfg.Audit)
            results.Add(("audit", Step("audit", () => RepoGuard.Run(["audit", repo]))));

        if (cfg.Scan)
        {
            var policy = Resolve(baseDir, cfg.ScanPolicy);
            string[] scanArgs = policy is null ? [repo] : [repo, "--policy", policy];
            results.Add(("scan", Step("scan", () => ScanCommand.Run(scanArgs))));
        }

        if (Resolve(baseDir, cfg.UrlPolicy) is { } urlCfg)
            results.Add(("url-policy", Step("url-policy", () => UrlPolicyCommand.Run([urlCfg]))));

        if (Resolve(baseDir, cfg.AppPolicy) is { } appCfg)
            results.Add(("app-policy", Step("app-policy", () => AppPolicyCommand.Run([appCfg]))));

        if (cfg.CollectReport)
        {
            Header("collect report");
            int code;
            try { code = await DlpCollector.RunAsync(["report"]); }
            catch (Exception ex) { Console.Error.WriteLine(ex.Message); code = -1; }
            results.Add(("collect report", CodeToText(code)));
        }

        Console.WriteLine("\n==================== Pipeline summary ====================");
        foreach (var (step, outcome) in results)
            Console.WriteLine($"  {step,-16} {outcome}");
        Console.WriteLine("\nEdit airepoguard.json to change paths or toggle steps. " +
                          "To run one step directly: airepoguard <command> ...  (airepoguard help)");
        return 0; // findings are reported per step; the pipeline itself succeeds once it runs
    }

    private static string Step(string name, Func<int> run)
    {
        Header(name);
        try { return CodeToText(run()); }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return $"ERROR ({ex.GetType().Name})"; }
    }

    private static void Header(string name) =>
        Console.WriteLine($"\n-------------------- {name} --------------------");

    private static string CodeToText(int code) => code switch
    {
        0 => "OK",
        1 => "blocked / error (1)",
        2 => "config or usage issue (2)",
        3 => "findings present (3)",
        _ => $"exit {code}",
    };

    private static string? Resolve(string baseDir, string? relative) =>
        string.IsNullOrWhiteSpace(relative) ? null : Path.GetFullPath(Path.Combine(baseDir, relative));

    private static string? FindConfig()
    {
        foreach (var dir in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var p = Path.Combine(dir, "airepoguard.json");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    private static RunConfig Load(string? path)
    {
        if (path is null || !File.Exists(path)) return new RunConfig();
        try
        {
            return JsonSerializer.Deserialize<RunConfig>(File.ReadAllText(path), JsonOpts) ?? new RunConfig();
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"airepoguard.json invalid ({ex.Message}); using defaults.");
            return new RunConfig();
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private sealed class RunConfig
    {
        public string RepoPath { get; init; } = ".";
        public bool Audit { get; init; } = true;
        public bool Scan { get; init; } = true;
        public string? ScanPolicy { get; init; }
        public string? UrlPolicy { get; init; }
        public string? AppPolicy { get; init; }
        public bool CollectReport { get; init; }
    }
}

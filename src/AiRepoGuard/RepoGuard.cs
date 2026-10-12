using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AiRepoGuard;

// Repository preflight/audit command. Dispatched from Program for the
// `audit`, `preflight`, and `init` subcommands (and interactive mode).
internal static class RepoGuard
{
    private static readonly string[] DefaultExcludedDirectories =
    [".git", ".vs", "bin", "obj", "node_modules", "packages", "dist", "build", "coverage"];

    private static readonly (string Name, Regex Pattern)[] SecretPatterns =
    [
        ("Private key material", new Regex("-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        ("Possible cloud access key", new Regex("\\bAKIA[0-9A-Z]{16}\\b", RegexOptions.Compiled)),
        ("Possible GitHub token", new Regex("\\bgh[pousr]_[A-Za-z0-9_]{30,}\\b", RegexOptions.Compiled)),
        ("Possible Slack token", new Regex("\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b", RegexOptions.Compiled)),
        ("Possible Google API key", new Regex("\\bAIza[0-9A-Za-z-_]{35}\\b", RegexOptions.Compiled)),
        ("Possible JWT", new Regex("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b", RegexOptions.Compiled)),
        ("Possible connection string with password", new Regex("(?i)(server|data source|host)\\s*=\\s*[^;\\s]+;.{0,80}?(password|pwd)\\s*=\\s*[^;\\s]{6,}", RegexOptions.Compiled | RegexOptions.Singleline)),
        ("Possible generic credential assignment", new Regex("(?i)\\b(password|passwd|client_secret|api[_-]?key|access[_-]?token)\\b\\s*[:=]\\s*['\"]?[^\\s'\"]{8,}", RegexOptions.Compiled))
    ];

    public static int Run(string[] args)
    {
        if (args.Length < 2 || args[0] is not ("audit" or "preflight" or "init"))
        {
            Console.WriteLine("AI Repo Guard\nUsage:\n  airepoguard audit <repo-path> [--policy <policy.json>]\n  airepoguard preflight <repo-path> [--policy <policy.json>]\n  airepoguard init <repo-path>");
            return 2;
        }

        return RunCommand(args[0], Path.GetFullPath(args[1]), GetOption(args, "--policy"), pause: false);
    }

    // ---------------- Command execution ----------------

    private static int RunCommand(string command, string root, string? policyOverride, bool pause)
    {
        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine($"Repository path does not exist: {root}");
            Pause(pause);
            return 2;
        }

        if (command == "init")
        {
            var code = Initialize(root);
            Pause(pause);
            return code;
        }

        var policyPath = policyOverride ?? Path.Combine(root, ".airepoguard.json");
        var policy = LoadPolicy(policyPath);
        var findings = Audit(root, policy);
        PrintFindings(findings);
        var reportPath = WriteReport(root, command, policyPath, findings);
        var blockers = findings.Count(f => f.Blocking);

        Console.WriteLine($"\nReport: {reportPath}");
        Console.WriteLine(blockers == 0 ? "RESULT: PASS" : $"RESULT: BLOCKED ({blockers} blocking finding(s))");

        Pause(pause);
        return blockers == 0 ? 0 : (command == "preflight" ? 1 : 3);
    }

    private static void PrintFindings(List<Finding> findings)
    {
        foreach (var finding in findings)
        {
            var oldColor = Console.ForegroundColor;
            Console.ForegroundColor = finding.Severity == "HIGH" ? ConsoleColor.Red
                                   : finding.Severity == "MEDIUM" ? ConsoleColor.Yellow : ConsoleColor.Cyan;
            Console.Write($"[{finding.Severity}] {finding.Code}: ");
            Console.ForegroundColor = oldColor;
            Console.WriteLine($"{finding.Message}{(finding.Path is null ? "" : $" ({finding.Path})")}");
        }
    }


    private static string WriteReport(
        string root,
        string mode,
        string policyPath,
        List<Finding> findings)
    {
        var report = new
        {
            tool = "AiRepoGuard",
            version = "0.1.0",
            repository = root,
            mode,
            policy = policyPath,
            generatedAtUtc = DateTimeOffset.UtcNow,
            passed = !findings.Any(f => f.Blocking),
            high = findings.Count(f => f.Severity == "HIGH"),
            medium = findings.Count(f => f.Severity == "MEDIUM"),
            low = findings.Count(f => f.Severity == "LOW"),
            findingCount = findings.Count,
            findings
        };

        // Use a shared application-data directory by default.
        var reportDirectory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "AIRepoGuard",
            "Reports"
        );

        Directory.CreateDirectory(reportDirectory);

        var reportPath = Path.Combine(
            reportDirectory,
            "airepoguard-report.json"
        );

        var json = JsonSerializer.Serialize(
            report,
            new JsonSerializerOptions
            {
                WriteIndented = true
            }
        );

        File.WriteAllText(reportPath, json);

        return reportPath;
    }


    private static void Pause(bool enabled)
    {
        if (!enabled) return;
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey(intercept: true);
    }

    // ---------------- Audit ----------------

    private static List<Finding> Audit(string root, GuardPolicy policy)
    {
        var findings = new List<Finding>();
        var relativeFiles = EnumerateFiles(root, policy.ExcludedDirectories).ToList();

        foreach (var relative in relativeFiles)
        {
            var normalized = relative.Replace('\\', '/');
            if (policy.SensitiveFilePatterns.Any(pattern => GlobLikeMatch(normalized, pattern)))
                findings.Add(new("SENSITIVE_FILE", "HIGH", $"Sensitive file path matches policy pattern", relative, true));

            try
            {
                if (new FileInfo(Path.Combine(root, relative)).Length > policy.MaximumFileBytes)
                    findings.Add(new("LARGE_FILE", "MEDIUM",
                        $"File exceeds MaximumFileBytes ({policy.MaximumFileBytes:N0}); large blobs can hide data and bloat history", relative, false));
            }
            catch { }
        }

        var git = RunGit(root, "status --porcelain");
        if (git.ExitCode != 0)
            findings.Add(new("GIT_UNAVAILABLE", "HIGH", "Git status failed; repository state cannot be verified", null, true));
        else if (!string.IsNullOrWhiteSpace(git.Output))
            findings.Add(new("DIRTY_WORKTREE", "MEDIUM", "Working tree is not clean. Review and checkpoint changes before AI work", null, policy.RequireCleanWorkingTree));

        var branch = RunGit(root, "branch --show-current");
        if (branch.ExitCode != 0 || string.IsNullOrWhiteSpace(branch.Output))
            findings.Add(new("BRANCH_UNKNOWN", "HIGH", "Could not determine current Git branch", null, true));
        else if (policy.ProtectedBranches.Contains(branch.Output.Trim(), StringComparer.OrdinalIgnoreCase))
            findings.Add(new("PROTECTED_BRANCH", "HIGH", $"Current branch '{branch.Output.Trim()}' is protected by policy; use a working branch", null, true));

        var settingsPath = Path.Combine(root, ".claude", "settings.json");
        if (policy.RequireClaudeSettings && !File.Exists(settingsPath))
            findings.Add(new("CLAUDE_SETTINGS_MISSING", "HIGH", "Expected .claude/settings.json is missing", ".claude/settings.json", true));
        else if (File.Exists(settingsPath))
            ValidateClaudeSettings(root, settingsPath, findings);

        var secretScanCount = 0;
        foreach (var relative in relativeFiles)
        {
            if (secretScanCount++ >= policy.MaximumFilesToScan) break;
            var full = Path.Combine(root, relative);
            if (!IsTextCandidate(full)) continue;
            try
            {
                var info = new FileInfo(full);
                if (info.Length > policy.MaximumFileBytes) continue;
                var content = File.ReadAllText(full);
                foreach (var (name, pattern) in SecretPatterns)
                {
                    if (pattern.IsMatch(content))
                        findings.Add(new("POSSIBLE_SECRET", "HIGH", name + "; verify and rotate any real exposed credential", relative, policy.BlockOnPossibleSecrets));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                findings.Add(new("FILE_UNREADABLE", "LOW", "Could not scan file: " + ex.GetType().Name, relative, false));
            }
        }

        if (relativeFiles.Count > policy.MaximumFilesToScan)
            findings.Add(new("SCAN_LIMIT_REACHED", "MEDIUM", $"Scan stopped at {policy.MaximumFilesToScan} files; audit may be incomplete", null, policy.BlockIfScanIncomplete));

        if (policy.RepositoryMode.Equals("LocalOnly", StringComparison.OrdinalIgnoreCase))
        {
            var remote = RunGit(root, "remote get-url origin");
            if (remote.ExitCode == 0 && !string.IsNullOrWhiteSpace(remote.Output))
                findings.Add(new("REMOTE_ON_LOCALONLY", "HIGH",
                    $"Policy is LocalOnly but repo has remote origin '{remote.Output}'. Remove it or change RepositoryMode", null, true));

            findings.Add(new("LOCAL_ONLY_POLICY", "HIGH", "Repository is classified LocalOnly. This tool cannot stop an AI client from sending data; enforce network/provider controls or use a local model", null, true));
        }

        return findings;
    }

    private static void ValidateClaudeSettings(string root, string settingsPath, List<Finding> findings)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(settingsPath));
            var rootElement = doc.RootElement;
            if (!rootElement.TryGetProperty("permissions", out var permissions) || !permissions.TryGetProperty("deny", out var deny) || deny.ValueKind != JsonValueKind.Array)
            {
                findings.Add(new("DENY_RULES_MISSING", "HIGH", "Claude settings have no permissions.deny array; check centrally managed policy", ".claude/settings.json", true));
                return;
            }
            var values = deny.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray();
            var required = new[] { "Read(.env)", "Read(.env.*)", "Read(**/.env)", "Read(**/.env.*)" };
            foreach (var rule in required)
                if (!values.Contains(rule, StringComparer.Ordinal))
                    findings.Add(new("DENY_RULE_MISSING", "MEDIUM", $"Expected deny rule is missing: {rule}", ".claude/settings.json", true));
        }
        catch (JsonException)
        {
            findings.Add(new("CLAUDE_SETTINGS_INVALID", "HIGH", "Claude settings JSON is invalid", ".claude/settings.json", true));
        }
        catch (IOException)
        {
            findings.Add(new("CLAUDE_SETTINGS_UNREADABLE", "HIGH", "Claude settings could not be read", ".claude/settings.json", true));
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root, string[] excluded)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            IEnumerable<string> dirs;
            IEnumerable<string> files;
            try { dirs = Directory.EnumerateDirectories(current).ToArray(); files = Directory.EnumerateFiles(current).ToArray(); }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var file in files)
                if (!Path.GetFileName(file).Equals("airepoguard-report.json", StringComparison.OrdinalIgnoreCase))
                    yield return Path.GetRelativePath(root, file);
            foreach (var dir in dirs)
                if (!excluded.Contains(Path.GetFileName(dir), StringComparer.OrdinalIgnoreCase)) stack.Push(dir);
        }
    }

    private static bool IsTextCandidate(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".cs" or ".json" or ".xml" or ".config" or ".yml" or ".yaml" or ".toml" or ".ini" or ".ps1" or ".sh" or ".sql" or ".js" or ".ts" or ".tsx" or ".jsx" or ".py" or ".env" or ".txt" or ".md" or ".props" or ".targets";
    }

    private static bool GlobLikeMatch(string path, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern.Replace('\\', '/')).Replace("\\*\\*", ".*").Replace("\\*", "[^/]*") + "$";
        return Regex.IsMatch(path, regex, RegexOptions.IgnoreCase);
    }

    private static GuardPolicy LoadPolicy(string path)
    {
        if (!File.Exists(path)) return new GuardPolicy();
        return JsonSerializer.Deserialize<GuardPolicy>(File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new GuardPolicy();
    }

    private static int Initialize(string root)
    {
        var policyPath = Path.Combine(root, ".airepoguard.json");
        if (!File.Exists(policyPath)) File.WriteAllText(policyPath, JsonSerializer.Serialize(new GuardPolicy(), new JsonSerializerOptions { WriteIndented = true }));
        var claudeDir = Path.Combine(root, ".claude");
        Directory.CreateDirectory(claudeDir);
        var settingsPath = Path.Combine(claudeDir, "settings.json");
        if (!File.Exists(settingsPath))
        {
            var settings = new
            {
                permissions = new
                {
                    defaultMode = "default",
                    deny = new[] { "Read(.env)", "Read(.env.*)", "Read(**/.env)", "Read(**/.env.*)", "Read(**/secrets/**)", "Read(**/*credentials*)", "Read(**/*.pem)", "Read(**/*.pfx)", "Read(**/appsettings.Production.json)", "Edit(.env)", "Edit(.env.*)", "Edit(**/.env)", "Edit(**/.env.*)", "Edit(**/secrets/**)", "Edit(**/appsettings.Production.json)" }
                },
                sandbox = new { enabled = true, failIfUnavailable = true },
                env = new { DISABLE_TELEMETRY = "1", DISABLE_ERROR_REPORTING = "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1" }
            };
            File.WriteAllText(settingsPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        }
        Console.WriteLine($"Initialized policy: {policyPath}\nClaude settings template: {settingsPath}\nReview both files and verify settings against your installed Claude Code version before use.");
        return 0;
    }

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 2; i < args.Length - 1; i++) if (args[i] == name) return args[i + 1];
        return null;
    }

    private static (int ExitCode, string Output) RunGit(string root, string arguments)
    {
        try
        {
            using var process = new Process { StartInfo = new ProcessStartInfo("git", arguments) { WorkingDirectory = root, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);
            return (process.ExitCode, output.Trim());
        }
        catch { return (-1, string.Empty); }
    }

    private sealed record Finding(string Code, string Severity, string Message, string? Path, bool Blocking);

    private sealed class GuardPolicy
    {
        public string RepositoryMode { get; set; } = "CloudApproved";
        public bool RequireCleanWorkingTree { get; set; } = true;
        public bool RequireClaudeSettings { get; set; } = true;
        public bool BlockOnPossibleSecrets { get; set; } = true;
        public bool BlockIfScanIncomplete { get; set; } = true;
        public int MaximumFilesToScan { get; set; } = 20000;
        public long MaximumFileBytes { get; set; } = 2_000_000;
        public string[] ProtectedBranches { get; set; } = ["main", "master", "production", "prod", "release"];
        public string[] ExcludedDirectories { get; set; } = DefaultExcludedDirectories;
        public string[] SensitiveFilePatterns { get; set; } = [".env", ".env.*", "**/.env", "**/.env.*", "**/secrets/**", "**/*credentials*", "**/*.pem", "**/*.pfx", "**/appsettings.Production.json", "**/*.bak", "**/*.sql.gz"];
    }
}
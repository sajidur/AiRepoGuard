using AiRepoGuard.AppPolicy;
using AiRepoGuard.Dlp;
using AiRepoGuard.UrlPolicy;

namespace AiRepoGuard;

// Unified entry point. Routes to the repository guard (audit/preflight/init),
// the content DLP scanner (OrgDlp.Core engine), the URL-policy compiler, and
// the Purview event collector. Run with no args for the interactive repo menu.
internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
            return await Pipeline.RunAsync(args); // no args: run the default pipeline

        var command = args[0].ToLowerInvariant();
        var rest = args[1..];
        return command switch
        {
            "run" => await Pipeline.RunAsync(rest),
            "audit" or "preflight" or "init" => RepoGuard.Run(args),
            "scan" => ScanCommand.Run(rest),
            "url-policy" => UrlPolicyCommand.Run(rest),
            "app-policy" => AppPolicyCommand.Run(rest),
            "collect" => await DlpCollector.RunAsync(rest),
            "help" or "-h" or "--help" => Usage(0),
            _ => Usage(2),
        };
    }

    private static int Usage(int code)
    {
        Console.WriteLine(
            "AI Repo Guard - unified security CLI\n" +
            "Usage:\n" +
            "  airepoguard                                              Run the default pipeline (airepoguard.json)\n" +
            "  airepoguard run [airepoguard.json]                       Same, with an explicit config\n" +
            "  airepoguard audit <repo> [--policy p]                    Repo preflight audit\n" +
            "  airepoguard preflight <repo> [--policy p]                Audit; nonzero exit blocks AI work\n" +
            "  airepoguard init <repo>                                  Write starter policy + Claude settings\n" +
            "  airepoguard scan <path> [--policy dlp.json] [--redact] [--quarantine]\n" +
            "                                                           Content DLP scan (PII/PCI/PHI/secrets/EDM)\n" +
            "  airepoguard url-policy <url-policy.json> [--out dir]     Compile monitor/block domain lists\n" +
            "  airepoguard app-policy <app-policy.json> [--out dir]     Compile executable blocklist to AppLocker XML\n" +
            "  airepoguard collect <subscribe|pull|report> [...]        Purview DLP event collector + dashboard\n\n" +
            "Run any subcommand with --help for its own options.\n");
        return code;
    }
}

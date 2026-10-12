using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AiRepoGuard.Dlp;

// `collect` subcommand: pulls DLP events from the Office 365 Management Activity
// API (the tenant's own audit feed) using an admin-consented app registration,
// stores them as newline-delimited JSON, and renders an HTML dashboard.
//
// This reads Microsoft's official audit API for your own tenant. It does not
// touch user devices and collects nothing beyond what Purview already records.
// See docs/dlp-collector.md for the required app registration and permissions.
internal static class DlpCollector
{
    private const string LoginBase = "https://login.microsoftonline.com";
    private const string ApiBase = "https://manage.office.com/api/v1.0";
    private const string DefaultContentType = "DLP.All";

    // The official Management Activity API content types. These are governed,
    // org-owned audit streams (not raw packet capture) - broadening to the
    // Audit.* types gives wider activity visibility while staying on the
    // supported, user-notifiable audit pipeline. Raw network egress is covered
    // by Defender / a secure web gateway instead - see docs/traffic-visibility.md.
    private static readonly string[] AllowedContentTypes =
    [
        "DLP.All",
        "Audit.General",
        "Audit.AzureActiveDirectory",
        "Audit.Exchange",
        "Audit.SharePoint",
    ];

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(100) };

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0) return Usage();
        var command = args[0].ToLowerInvariant();
        try
        {
            return command switch
            {
                "subscribe" => await SubscribeAsync(LoadConfig(args), GetContentType(args)),
                "pull" => await PullAsync(LoadConfig(args), GetContentType(args), GetHours(args)),
                "report" => Report(GetDataDir(args)),
                "help" or "--help" or "-h" => Usage(0),
                _ => Usage()
            };
        }
        catch (ConfigException ex) { Console.Error.WriteLine(ex.Message); return 2; }
        catch (HttpRequestException ex) { Console.Error.WriteLine("HTTP error: " + ex.Message); return 1; }
    }

    private static int Usage(int code = 2)
    {
        Console.WriteLine(
            "collect - central collector for Purview DLP / M365 activity events\n" +
            "Usage:\n" +
            "  airepoguard collect subscribe [--content-type T]           Start an activity subscription (once per type)\n" +
            "  airepoguard collect pull [--content-type T] [--hours N]    Pull new events into the local store (default 24h)\n" +
            "  airepoguard collect report                                 Render dashboard.html from the local store\n\n" +
            "Content types (--content-type, default DLP.All):\n" +
            "  DLP.All, Audit.General, Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint\n\n" +
            "Config (env vars, or --tenant/--client/--secret/--data overrides):\n" +
            "  AIDLP_TENANT_ID, AIDLP_CLIENT_ID, AIDLP_CLIENT_SECRET, AIDLP_DATA_DIR, AIDLP_CONTENT_TYPE\n");
        return code;
    }

    // ---- Commands -----------------------------------------------------------

    private static async Task<int> SubscribeAsync(Config cfg, string contentType)
    {
        var token = await GetTokenAsync(cfg);
        var url = $"{ApiBase}/{cfg.TenantId}/activity/feed/subscriptions/start?contentType={contentType}";
        using var resp = await SendAsync(HttpMethod.Post, url, token, new StringContent("", Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        if (resp.IsSuccessStatusCode)
        {
            Console.WriteLine($"Subscription active for {contentType}.");
            return 0;
        }
        // Already-enabled is not a failure for our purposes.
        if (body.Contains("already enabled", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"Subscription for {contentType} was already enabled.");
            return 0;
        }
        Console.Error.WriteLine($"Subscription failed ({(int)resp.StatusCode}): {body}");
        return 1;
    }

    private static async Task<int> PullAsync(Config cfg, string contentType, int hours)
    {
        Directory.CreateDirectory(cfg.DataDir);
        var token = await GetTokenAsync(cfg);

        var end = DateTime.UtcNow;
        var start = end.AddHours(-hours);
        var startStr = start.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
        var endStr = end.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);

        // 1. Enumerate available content blobs for the window (follow paging).
        var contentUris = new List<string>();
        var listUrl = $"{ApiBase}/{cfg.TenantId}/activity/feed/subscriptions/content" +
                      $"?contentType={contentType}&startTime={startStr}&endTime={endStr}";
        while (listUrl is not null)
        {
            using var resp = await SendAsync(HttpMethod.Get, listUrl, token);
            if (!resp.IsSuccessStatusCode)
            {
                var err = await resp.Content.ReadAsStringAsync();
                Console.Error.WriteLine($"Content listing failed ({(int)resp.StatusCode}): {err}");
                return 1;
            }
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            foreach (var item in doc.RootElement.EnumerateArray())
                if (item.TryGetProperty("contentUri", out var u) && u.GetString() is { } uri)
                    contentUris.Add(uri);

            listUrl = resp.Headers.TryGetValues("NextPageUri", out var next) ? next.FirstOrDefault() : null;
        }

        // 2. Load already-seen event IDs so re-runs don't duplicate.
        var eventsPath = Path.Combine(cfg.DataDir, "events.jsonl");
        var seen = LoadSeenIds(eventsPath);

        // 3. Download each blob, append new events.
        var added = 0;
        await using var writer = new StreamWriter(eventsPath, append: true);
        foreach (var uri in contentUris)
        {
            using var resp = await SendAsync(HttpMethod.Get, uri, token);
            if (!resp.IsSuccessStatusCode) continue;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            foreach (var ev in doc.RootElement.EnumerateArray())
            {
                var id = ev.TryGetProperty("Id", out var idEl) ? idEl.GetString() : null;
                if (id is null || !seen.Add(id)) continue;
                await writer.WriteLineAsync(ev.GetRawText());
                added++;
            }
        }
        await writer.FlushAsync();

        Console.WriteLine($"Pulled {contentUris.Count} content blob(s); added {added} new event(s).");
        Console.WriteLine($"Store: {eventsPath}");
        return 0;
    }

    private static int Report(string dataDir)
    {
        var eventsPath = Path.Combine(dataDir, "events.jsonl");
        if (!File.Exists(eventsPath))
        {
            Console.Error.WriteLine($"No event store found at {eventsPath}. Run 'collect pull' first.");
            return 2;
        }

        var events = new List<DlpEvent>();
        foreach (var line in File.ReadLines(eventsPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { events.Add(DlpEvent.Parse(line)); }
            catch (JsonException) { /* skip malformed line */ }
        }

        var html = DashboardHtml.Render(events);
        var outPath = Path.Combine(dataDir, "dashboard.html");
        File.WriteAllText(outPath, html, new UTF8Encoding(false));
        Console.WriteLine($"Parsed {events.Count} event(s).");
        Console.WriteLine($"Dashboard: {outPath}");
        return 0;
    }

    // ---- HTTP + auth --------------------------------------------------------

    private static async Task<string> GetTokenAsync(Config cfg)
    {
        var url = $"{LoginBase}/{cfg.TenantId}/oauth2/v2.0/token";
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = cfg.ClientId,
            ["client_secret"] = cfg.ClientSecret,
            ["scope"] = "https://manage.office.com/.default",
        });
        using var resp = await Http.PostAsync(url, form);
        var body = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Token request failed ({(int)resp.StatusCode}): {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()
               ?? throw new HttpRequestException("Token response had no access_token.");
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string url, string token, HttpContent? content = null)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method, url) { Content = content };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var resp = await Http.SendAsync(req);
            if (resp.StatusCode != (HttpStatusCode)429 || attempt >= 4) return resp;

            var wait = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(5 * (attempt + 1));
            resp.Dispose();
            Console.Error.WriteLine($"Throttled (429); retrying in {wait.TotalSeconds:0}s...");
            await Task.Delay(wait);
        }
    }

    // ---- Config + args ------------------------------------------------------

    private static Config LoadConfig(string[] args)
    {
        var tenant = GetArg(args, "--tenant") ?? Environment.GetEnvironmentVariable("AIDLP_TENANT_ID");
        var client = GetArg(args, "--client") ?? Environment.GetEnvironmentVariable("AIDLP_CLIENT_ID");
        var secret = GetArg(args, "--secret") ?? Environment.GetEnvironmentVariable("AIDLP_CLIENT_SECRET");
        if (string.IsNullOrWhiteSpace(tenant) || string.IsNullOrWhiteSpace(client) || string.IsNullOrWhiteSpace(secret))
            throw new ConfigException(
                "Missing credentials. Set AIDLP_TENANT_ID, AIDLP_CLIENT_ID, AIDLP_CLIENT_SECRET " +
                "(or pass --tenant/--client/--secret). See docs/dlp-collector.md.");
        return new Config(tenant, client, secret, GetDataDir(args));
    }

    private static string GetDataDir(string[] args) =>
        GetArg(args, "--data")
        ?? Environment.GetEnvironmentVariable("AIDLP_DATA_DIR")
        ?? Path.Combine(Directory.GetCurrentDirectory(), "data");

    private static int GetHours(string[] args) =>
        int.TryParse(GetArg(args, "--hours"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var h) && h is > 0 and <= 168
            ? h : 24;

    private static string GetContentType(string[] args)
    {
        var ct = GetArg(args, "--content-type")
                 ?? Environment.GetEnvironmentVariable("AIDLP_CONTENT_TYPE")
                 ?? DefaultContentType;
        var match = AllowedContentTypes.FirstOrDefault(c => string.Equals(c, ct, StringComparison.OrdinalIgnoreCase));
        return match ?? throw new ConfigException(
            $"Unsupported --content-type '{ct}'. Allowed: {string.Join(", ", AllowedContentTypes)}.");
    }

    private static string? GetArg(string[] args, string name)
    {
        for (var i = 1; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private sealed record Config(string TenantId, string ClientId, string ClientSecret, string DataDir);

    private sealed class ConfigException(string message) : Exception(message);

    private static HashSet<string> LoadSeenIds(string eventsPath)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (!File.Exists(eventsPath)) return seen;
        foreach (var line in File.ReadLines(eventsPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.TryGetProperty("Id", out var id) && id.GetString() is { } s) seen.Add(s);
            }
            catch (JsonException) { /* ignore */ }
        }
        return seen;
    }
}

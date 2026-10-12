using System.Net;
using System.Text;

namespace AiRepoGuard.Dlp;

// Renders a self-contained HTML dashboard (no external assets) summarizing the
// collected DLP events. Opens correctly in light and dark browsers.
internal static class DashboardHtml
{
    public static string Render(IReadOnlyList<DlpEvent> events)
    {
        var dated = events.Where(e => e.CreationTime != DateTimeOffset.MinValue).ToList();
        var min = dated.Count > 0 ? dated.Min(e => e.CreationTime) : (DateTimeOffset?)null;
        var max = dated.Count > 0 ? dated.Max(e => e.CreationTime) : (DateTimeOffset?)null;

        var byWorkload = Count(events.Select(e => e.Workload));
        var byUser = Count(events.Select(e => e.UserId));
        var byPolicy = Count(events.SelectMany(e => e.Policies.DefaultIfEmpty("(no policy)")));
        var bySit = Count(events.SelectMany(e => e.SensitiveTypes.DefaultIfEmpty("(none reported)")));
        var byDay = Count(dated.Select(e => e.CreationTime.ToString("yyyy-MM-dd")));

        var sb = new StringBuilder();
        sb.Append("""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DLP Dashboard</title>
<style>
  :root {
    --bg:#f6f7f9; --card:#fff; --ink:#1b1f24; --muted:#5c6773;
    --line:#e3e6ea; --bar:#3b6ef5; --bar-hi:#d7342b; --accent:#3b6ef5;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#0f1319; --card:#171c24; --ink:#e7ebf0; --muted:#9aa5b1;
      --line:#262d38; --bar:#5b82f6; --bar-hi:#f2655b; --accent:#5b82f6;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:15px/1.5 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:1040px; margin:0 auto; padding:24px 16px 64px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 24px; font-size:13px; }
  .kpis { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:24px; }
  .kpi { background:var(--card); border:1px solid var(--line); border-radius:10px;
         padding:14px 18px; flex:1 1 150px; }
  .kpi .n { font-size:26px; font-weight:650; }
  .kpi .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:18px; margin-bottom:18px; }
  .card h2 { font-size:14px; margin:0 0 14px; text-transform:uppercase;
             letter-spacing:.04em; color:var(--muted); }
  .row { display:grid; grid-template-columns:minmax(0,1fr) 54px; align-items:center;
         gap:10px; margin:6px 0; }
  .row .lab { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .row .cnt { text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); }
  .track { grid-column:1 / 3; height:6px; background:var(--line); border-radius:4px; overflow:hidden; }
  .fill { height:100%; background:var(--bar); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line);
          white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:280px; }
  th { color:var(--muted); font-weight:600; }
  .empty { color:var(--muted); font-style:italic; }
</style>
</head>
<body>
<div class="wrap">
""");

        sb.Append("<h1>DLP Activity Dashboard</h1>");
        var range = min is null
            ? "no dated events"
            : $"{min:yyyy-MM-dd} to {max:yyyy-MM-dd}";
        sb.Append($"<p class=\"sub\">Source: Office 365 Management Activity API (DLP.All). " +
                  $"Window: {E(range)}. Generated {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm} UTC.</p>");

        // KPIs
        sb.Append("<div class=\"kpis\">");
        Kpi(sb, events.Count.ToString(), "Events");
        Kpi(sb, byUser.Count.ToString(), "Users");
        Kpi(sb, byPolicy.Count(p => p.Key != "(no policy)").ToString(), "Policies hit");
        Kpi(sb, byWorkload.Count.ToString(), "Workloads");
        sb.Append("</div>");

        if (events.Count == 0)
            sb.Append("<div class=\"card\"><p class=\"empty\">No events collected yet. Run 'pull' after your DLP policy has produced matches.</p></div>");

        BarCard(sb, "Events per day", byDay, sortByKey: true);
        BarCard(sb, "By workload", byWorkload);
        BarCard(sb, "Top users", Top(byUser, 15));
        BarCard(sb, "By policy", byPolicy);
        BarCard(sb, "By sensitive info type", bySit);

        // Recent events
        sb.Append("<div class=\"card\"><h2>Recent events</h2>");
        var recent = events
            .OrderByDescending(e => e.CreationTime)
            .Take(100)
            .ToList();
        if (recent.Count == 0)
        {
            sb.Append("<p class=\"empty\">None.</p>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>Time (UTC)</th><th>User</th><th>Workload</th>" +
                      "<th>Operation</th><th>Policy</th><th>Sensitive types</th></tr></thead><tbody>");
            foreach (var e in recent)
            {
                var time = e.CreationTime == DateTimeOffset.MinValue ? "(unknown)" : e.CreationTime.ToString("yyyy-MM-dd HH:mm");
                sb.Append("<tr>");
                sb.Append($"<td>{E(time)}</td>");
                sb.Append($"<td>{E(e.UserId)}</td>");
                sb.Append($"<td>{E(e.Workload)}</td>");
                sb.Append($"<td>{E(e.Operation)}</td>");
                sb.Append($"<td>{E(e.Policies.FirstOrDefault() ?? "(none)")}</td>");
                sb.Append($"<td>{E(string.Join(", ", e.SensitiveTypes))}</td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div>");

        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    private static void Kpi(StringBuilder sb, string n, string label) =>
        sb.Append($"<div class=\"kpi\"><div class=\"n\">{E(n)}</div><div class=\"l\">{E(label)}</div></div>");

    private static void BarCard(StringBuilder sb, string title,
        IReadOnlyList<KeyValuePair<string, int>> data, bool sortByKey = false)
    {
        sb.Append($"<div class=\"card\"><h2>{E(title)}</h2>");
        if (data.Count == 0)
        {
            sb.Append("<p class=\"empty\">No data.</p></div>");
            return;
        }
        var ordered = sortByKey
            ? data.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToList()
            : data.OrderByDescending(kv => kv.Value).ToList();
        var maxVal = ordered.Max(kv => kv.Value);
        foreach (var kv in ordered)
        {
            var pct = maxVal == 0 ? 0 : (int)Math.Round(100.0 * kv.Value / maxVal);
            sb.Append("<div class=\"row\">");
            sb.Append($"<span class=\"lab\" title=\"{E(kv.Key)}\">{E(kv.Key)}</span>");
            sb.Append($"<span class=\"cnt\">{kv.Value}</span>");
            sb.Append($"<span class=\"track\"><span class=\"fill\" style=\"width:{pct}%\"></span></span>");
            sb.Append("</div>");
        }
        sb.Append("</div>");
    }

    private static List<KeyValuePair<string, int>> Count(IEnumerable<string> items)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            var key = string.IsNullOrWhiteSpace(item) ? "(unknown)" : item;
            map[key] = map.TryGetValue(key, out var c) ? c + 1 : 1;
        }
        return map.ToList();
    }

    private static List<KeyValuePair<string, int>> Top(List<KeyValuePair<string, int>> data, int n) =>
        data.OrderByDescending(kv => kv.Value).Take(n).ToList();

    private static string E(string s) => WebUtility.HtmlEncode(s);
}

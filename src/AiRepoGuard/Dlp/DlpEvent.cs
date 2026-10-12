using System.Globalization;
using System.Text.Json;

namespace AiRepoGuard.Dlp;

// A flattened view of one Management Activity API DLP record, pulling out the
// fields the dashboard aggregates. Everything is defensive: the API omits
// fields that don't apply to a given workload, so missing data becomes "unknown"
// rather than an exception.
internal sealed record DlpEvent(
    string Id,
    DateTimeOffset CreationTime,
    string Operation,
    string Workload,
    string UserId,
    IReadOnlyList<string> Policies,
    IReadOnlyList<string> Rules,
    IReadOnlyList<string> SensitiveTypes)
{
    public static DlpEvent Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var creation = GetString(root, "CreationTime");
        var when = DateTimeOffset.TryParse(creation, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed : DateTimeOffset.MinValue;

        var policies = new List<string>();
        var rules = new List<string>();
        var sits = new HashSet<string>(StringComparer.Ordinal);

        if (root.TryGetProperty("PolicyDetails", out var pd) && pd.ValueKind == JsonValueKind.Array)
        {
            foreach (var policy in pd.EnumerateArray())
            {
                var name = GetString(policy, "PolicyName");
                if (name.Length > 0) policies.Add(name);

                if (policy.TryGetProperty("Rules", out var ruleArr) && ruleArr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var rule in ruleArr.EnumerateArray())
                    {
                        var rn = GetString(rule, "RuleName");
                        if (rn.Length > 0) rules.Add(rn);

                        if (rule.TryGetProperty("ConditionsMatched", out var cond) &&
                            cond.TryGetProperty("SensitiveInformation", out var siArr) &&
                            siArr.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var si in siArr.EnumerateArray())
                            {
                                var sn = GetString(si, "SensitiveInformationTypeName");
                                if (sn.Length > 0) sits.Add(sn);
                            }
                        }
                    }
                }
            }
        }

        return new DlpEvent(
            Id: GetString(root, "Id"),
            CreationTime: when,
            Operation: Fallback(GetString(root, "Operation")),
            Workload: Fallback(GetString(root, "Workload")),
            UserId: Fallback(GetString(root, "UserId")),
            Policies: policies,
            Rules: rules,
            SensitiveTypes: sits.ToList());
    }

    private static string GetString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string Fallback(string s) => s.Length > 0 ? s : "(unknown)";
}

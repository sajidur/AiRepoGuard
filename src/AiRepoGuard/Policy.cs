using System.Text.Json;
using System.Text.Json.Serialization;

namespace OrgDlp.Core;

public sealed class DlpPolicy
{
    [JsonPropertyName("excludedDirectories")]
    public string[] ExcludedDirectories { get; set; } = [".git", "bin", "obj", "node_modules"];

    [JsonPropertyName("maximumFilesToScan")]
    public int MaximumFilesToScan { get; set; } = 50000;

    [JsonPropertyName("maximumFileBytes")]
    public long MaximumFileBytes { get; set; } = 5_000_000;

    [JsonPropertyName("sensitiveFilePatterns")]
    public string[] SensitiveFilePatterns { get; set; } =
        [".env", ".env.*", "**/secrets/**", "**/*.pem", "**/*.pfx", "**/backup/**", "**/*.sql.gz"];

    [JsonPropertyName("customRegexRules")]
    public CustomRegexRule[] CustomRegexRules { get; set; } = [];

    [JsonPropertyName("edm")]
    public EdmSettings Edm { get; set; } = new();

    [JsonPropertyName("actions")]
    public ActionSettings Actions { get; set; } = new();

    public static DlpPolicy Load(string path) =>
        File.Exists(path)
            ? JsonSerializer.Deserialize<DlpPolicy>(File.ReadAllText(path), Options) ?? new DlpPolicy()
            : new DlpPolicy();

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Options));

    public static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public sealed class CustomRegexRule
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("category")] public string Category { get; set; } = "CUSTOM";
        [JsonPropertyName("severity")] public string Severity { get; set; } = "MEDIUM";
        [JsonPropertyName("description")] public string Description { get; set; } = "";
        [JsonPropertyName("pattern")] public string Pattern { get; set; } = "";
        [JsonPropertyName("minMatches")] public int MinMatches { get; set; } = 1;
    }

    public sealed class EdmSettings
    {
        [JsonPropertyName("referenceFiles")] public string[] ReferenceFiles { get; set; } = [];
        [JsonPropertyName("similarityThreshold")] public double SimilarityThreshold { get; set; } = 0.35;
    }

    public sealed class ActionSettings
    {
        [JsonPropertyName("quarantineDirectory")] public string QuarantineDirectory { get; set; } = "dlp-quarantine";
        [JsonPropertyName("writeRedactedCopy")] public bool WriteRedactedCopy { get; set; } = false;
        [JsonPropertyName("redactedDirectory")] public string RedactedDirectory { get; set; } = "dlp-redacted";
    }
}
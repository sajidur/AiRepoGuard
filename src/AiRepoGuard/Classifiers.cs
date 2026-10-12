using System.Text.RegularExpressions;

namespace OrgDlp.Core;

public sealed record Classification(
    string RuleName,
    string Category,      // PII / PCI / PHI / FIN / IP
    string Severity,      // HIGH / MEDIUM / LOW
    string Description,
    long MatchCount,
    string? Sample);      // masked sample of first match

public interface IDataClassifier
{
    string Name { get; }
    Classification? Classify(string content, string relativePath);
}

/// <summary>Regex-based classifier. Optionally validates matches with a function (e.g. Luhn).</summary>
public sealed class RegexClassifier : IDataClassifier
{
    private readonly Regex _regex;
    private readonly Func<string, bool>? _validator;
    private readonly int _minMatches;

    public string Name { get; }
    public string Category { get; }
    public string Severity { get; }
    public string Description { get; }
    public bool Redactable { get; }

    public RegexClassifier(string name, string category, string severity, string description,
                           string pattern, int minMatches = 1,
                           Func<string, bool>? validator = null, bool redactable = true,
                           RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Compiled)
    {
        Name = name; Category = category; Severity = severity; Description = description;
        _regex = new Regex(pattern, options);
        _validator = validator; _minMatches = minMatches; Redactable = redactable;
    }

    public Classification? Classify(string content, string relativePath)
    {
        var matches = _regex.Matches(content);
        var valid = new List<string>();
        foreach (Match m in matches)
        {
            var value = m.Value;
            if (_validator is null || _validator(value)) valid.Add(value);
        }
        if (valid.Count < _minMatches) return null;
        return new Classification(Name, Category, Severity, Description, valid.Count, Mask(valid[0]));
    }

    public string Redact(string content) => Redactable ? _regex.Replace(content, $"[REDACTED:{Name}]") : content;

    private static string Mask(string value) =>
        value.Length <= 6 ? "***" : value[..3] + new string('*', Math.Min(value.Length - 6, 10)) + value[^3..];
}

/// <summary>Detects a cluster of keywords (e.g. medical, financial, legal terms).</summary>
public sealed class KeywordClassifier : IDataClassifier
{
    private readonly string[] _keywords;
    private readonly int _threshold;
    public string Name { get; }
    public string Category { get; }
    public string Severity { get; }
    public string Description { get; }

    public KeywordClassifier(string name, string category, string severity, string description,
                             IEnumerable<string> keywords, int threshold)
    {
        Name = name; Category = category; Severity = severity; Description = description;
        _keywords = keywords.Select(k => k.ToLowerInvariant()).ToArray();
        _threshold = threshold;
    }

    public Classification? Classify(string content, string relativePath)
    {
        var lower = content.ToLowerInvariant();
        var hits = _keywords.Count(k => lower.Contains(k));
        return hits >= _threshold
            ? new Classification(Name, Category, Severity, Description, hits, null)
            : null;
    }

    public string Redact(string content) => content; // keywords alone are not redacted
}

public static class BuiltInClassifiers
{
    public static IReadOnlyList<IDataClassifier> All() => new IDataClassifier[]
    {
        new RegexClassifier("CREDIT_CARD", "PCI", "HIGH", "Payment card number (Luhn-validated)",
            @"\b\d(?:[ -]?\d){12,18}\b",   // 13-19 digits, separators allowed; Luhn decides
            validator: Luhn.IsValid),
        new RegexClassifier("US_SSN", "PII", "HIGH", "US Social Security number",
            @"\b(?!000|666|9\d\d)(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b"),
        new RegexClassifier("EMAIL_ADDRESS", "PII", "LOW", "Email address",
            @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        new RegexClassifier("AWS_ACCESS_KEY", "CLOUD", "HIGH", "AWS access key ID",
            @"\bAKIA[0-9A-Z]{16}\b"),
        new RegexClassifier("PRIVATE_KEY", "CRED", "HIGH", "Private key material",
            @"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        new RegexClassifier("IBAN", "FIN", "MEDIUM", "International bank account number",
            @"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", validator: v => v.Length >= 15),
        new RegexClassifier("IP_V4", "NET", "LOW", "IPv4 address",
            @"\b(?:\d{1,3}\.){3}\d{1,3}\b", validator: v => v.Split('.').All(o => byte.TryParse(o, out var b) && b <= 255)),
        new KeywordClassifier("MEDICAL_RECORD", "PHI", "MEDIUM", "Cluster of medical/PHI terms",
            ["diagnosis", "patient", "prescription", "medication", "clinic", "treatment", "physician", "icd-10", "lab result"], 3),
        new KeywordClassifier("FINANCIAL_STATEMENT", "FIN", "MEDIUM", "Cluster of financial terms",
            ["invoice", "salary", "payroll", "bank statement", "wire transfer", "balance sheet", "tax return"], 3),
    };
}

public static class Luhn
{
    public static bool IsValid(string number)
    {
        var digits = number.Where(char.IsDigit).ToArray();
        if (digits.Length < 13) return false;
        var sum = 0; var dbl = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d; dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}

/// <summary>Exact Data Match (EDM)-style fingerprinting using hashed word shingles.
/// Build a fingerprint of a golden-records file, then compare new content against it.</summary>
public sealed class DocumentFingerprinter
{
    private const int ShingleSize = 4;
    private readonly HashSet<ulong> _referenceShingles;

    public DocumentFingerprinter(string referenceContent)
        => _referenceShingles = ComputeShingles(referenceContent);

    public double Similarity(string content)
    {
        var shingles = ComputeShingles(content);
        if (shingles.Count == 0) return 0;
        var overlap = shingles.Intersect(_referenceShingles).Count();
        return (double)overlap / Math.Max(shingles.Count, _referenceShingles.Count);
    }

    private static HashSet<ulong> ComputeShingles(string content)
    {
        var words = Regex.Split(content.ToLowerInvariant(), @"\W+").Where(w => w.Length > 1).ToArray();
        var set = new HashSet<ulong>();
        for (var i = 0; i + ShingleSize <= words.Length; i++)
        {
            var h = 1469598103934665603UL; // FNV-1a 64 offset basis
            for (var j = i; j < i + ShingleSize; j++)
                foreach (var c in words[j])
                { h ^= c; h *= 1099511628211UL; }
            set.Add(h);
        }
        return set;
    }
}
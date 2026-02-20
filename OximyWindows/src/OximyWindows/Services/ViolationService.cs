using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Threading;
using OximyWindows.Core;

namespace OximyWindows.Services;

/// <summary>
/// A single violation entry written by the Python addon to ~/.oximy/violations.json.
/// </summary>
public class ViolationEntry
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("policyName")]
    public string PolicyName { get; set; } = "";

    [JsonPropertyName("ruleName")]
    public string RuleName { get; set; } = "";

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "";

    [JsonPropertyName("detectedType")]
    public string DetectedType { get; set; } = "";

    [JsonPropertyName("host")]
    public string Host { get; set; } = "";

    [JsonPropertyName("bundleId")]
    public string BundleId { get; set; } = "";

    [JsonPropertyName("retryAllowed")]
    public bool RetryAllowed { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    // ─── Computed display helpers ─────────────────────────────────────────────

    /// <summary>Segoe MDL2 icon codepoint for the detected PII type.</summary>
    public string PiiIcon => DetectedType.ToLowerInvariant() switch
    {
        "email"                                       => "\uE715",  // Envelope
        "credit_card"                                 => "\uE8C7",  // Payment card
        "phone"                                       => "\uE717",  // Phone
        "ssn" or "passport" or "drivers_license"      => "\uEA18",  // Shield
        "api_key" or "aws_key" or "token" or "secret" => "\uE8A7",  // Key
        "person_name"                                 => "\uE77B",  // Person
        _                                             => "\uE72E",  // Lock (default)
    };

    /// <summary>Human-readable label for the detected PII type.</summary>
    public string PiiLabel => DetectedType.ToLowerInvariant() switch
    {
        "email"           => "Email Address",
        "credit_card"     => "Credit Card",
        "phone"           => "Phone Number",
        "ssn"             => "SSN",
        "passport"        => "Passport",
        "drivers_license" => "Driver's License",
        "api_key"         => "API Key",
        "aws_key"         => "AWS Key",
        "token"           => "Token",
        "secret"          => "Secret",
        "person_name"     => "Person Name",
        _                 => string.IsNullOrEmpty(DetectedType) ? "Sensitive Data" : DetectedType,
    };

    /// <summary>Relative time string (e.g. "just now", "2m ago").</summary>
    public string RelativeTime
    {
        get
        {
            if (!DateTime.TryParse(Timestamp, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
                return "";
            var ago = DateTime.UtcNow - dt.ToUniversalTime();
            if (ago.TotalSeconds < 60) return "just now";
            if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
            if (ago.TotalHours < 24)   return $"{(int)ago.TotalHours}h ago";
            return $"{(int)ago.TotalDays}d ago";
        }
    }
}

/// <summary>
/// Polls ~/.oximy/violations.json every 1 second and surfaces new violations as events.
/// Mirror of ViolationService.swift on Mac.
/// </summary>
public class ViolationService
{
    private static ViolationService? _instance;
    public static ViolationService Instance => _instance ??= new ViolationService();

    private readonly DispatcherTimer _pollTimer;
    private readonly HashSet<string> _seenIds = new();

    /// <summary>All violations seen this session, newest last.</summary>
    public ObservableCollection<ViolationEntry> Violations { get; } = new();

    /// <summary>Fired on the UI thread for each new violation.</summary>
    public event EventHandler<ViolationEntry>? NewViolationDetected;

    private ViolationService()
    {
        _pollTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _pollTimer.Tick += OnPollTick;
    }

    public void Start()
    {
        if (_pollTimer.IsEnabled) return;
        _pollTimer.Start();
        Debug.WriteLine("[ViolationService] Started polling");
    }

    public void Stop()
    {
        _pollTimer.Stop();
        Debug.WriteLine("[ViolationService] Stopped polling");
    }

    private void OnPollTick(object? sender, EventArgs e)
    {
        var path = Path.Combine(Constants.OximyDir, "violations.json");
        if (!File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            var entries = JsonSerializer.Deserialize<List<ViolationEntry>>(json);
            if (entries == null) return;

            foreach (var entry in entries)
            {
                if (string.IsNullOrEmpty(entry.Id) || _seenIds.Contains(entry.Id))
                    continue;

                _seenIds.Add(entry.Id);
                Violations.Add(entry);
                NewViolationDetected?.Invoke(this, entry);
                Debug.WriteLine($"[ViolationService] New violation: {entry.DetectedType} on {entry.Host}");
            }
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"[ViolationService] JSON parse error: {ex.Message}");
        }
        catch (IOException ex)
        {
            Debug.WriteLine($"[ViolationService] IO error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ViolationService] Unexpected error: {ex.Message}");
        }
    }
}

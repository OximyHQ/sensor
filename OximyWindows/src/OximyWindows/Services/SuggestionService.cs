using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Threading;
using OximyWindows.Core;

namespace OximyWindows.Services;

/// <summary>
/// Metadata for a playbook template.
/// </summary>
public class PlaybookInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("category")]
    public string Category { get; set; } = "";

    [JsonPropertyName("promptTemplate")]
    public string PromptTemplate { get; set; } = "";
}

/// <summary>
/// A suggestion surface by the Python addon.
/// </summary>
public class PlaybookSuggestion
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("playbook")]
    public PlaybookInfo Playbook { get; set; } = new();

    [JsonPropertyName("triggerExcerpt")]
    public string TriggerExcerpt { get; set; } = "";

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending";    // "pending" | "used" | "dismissed"
}

/// <summary>
/// Polls ~/.oximy/suggestions.json every 2 seconds, surfaces new suggestions, and
/// writes status back on use/dismiss. Mirror of SuggestionService.swift on Mac.
/// </summary>
public class SuggestionService
{
    private static SuggestionService? _instance;
    public static SuggestionService Instance => _instance ??= new SuggestionService();

    private readonly DispatcherTimer _pollTimer;
    private readonly HashSet<string> _seenIds = new();

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Fired on the UI thread for each new suggestion.</summary>
    public event EventHandler<PlaybookSuggestion>? NewSuggestionAvailable;

    private SuggestionService()
    {
        _pollTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _pollTimer.Tick += OnPollTick;
    }

    public void Start()
    {
        if (_pollTimer.IsEnabled) return;
        _pollTimer.Start();
        Debug.WriteLine("[SuggestionService] Started polling");
    }

    public void Stop()
    {
        _pollTimer.Stop();
        Debug.WriteLine("[SuggestionService] Stopped polling");
    }

    private void OnPollTick(object? sender, EventArgs e)
    {
        var path = Path.Combine(Constants.OximyDir, "suggestions.json");
        if (!File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            var suggestions = JsonSerializer.Deserialize<List<PlaybookSuggestion>>(json);
            if (suggestions == null) return;

            foreach (var suggestion in suggestions)
            {
                if (string.IsNullOrEmpty(suggestion.Id) || _seenIds.Contains(suggestion.Id))
                    continue;
                if (suggestion.Status != "pending")
                {
                    _seenIds.Add(suggestion.Id);
                    continue;
                }

                _seenIds.Add(suggestion.Id);
                NewSuggestionAvailable?.Invoke(this, suggestion);
                Debug.WriteLine($"[SuggestionService] New suggestion: {suggestion.Playbook.Name}");
            }
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"[SuggestionService] JSON parse error: {ex.Message}");
        }
        catch (IOException ex)
        {
            Debug.WriteLine($"[SuggestionService] IO error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SuggestionService] Unexpected error: {ex.Message}");
        }
    }

    /// <summary>
    /// Mark a suggestion as "used" and write back to the JSON file.
    /// </summary>
    public void UseSuggestion(string id) => UpdateSuggestionStatus(id, "used");

    /// <summary>
    /// Mark a suggestion as "dismissed" and write back to the JSON file.
    /// </summary>
    public void DismissSuggestion(string id) => UpdateSuggestionStatus(id, "dismissed");

    private void UpdateSuggestionStatus(string id, string status)
    {
        var path = Path.Combine(Constants.OximyDir, "suggestions.json");
        if (!File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            var suggestions = JsonSerializer.Deserialize<List<PlaybookSuggestion>>(json);
            if (suggestions == null) return;

            var target = suggestions.FirstOrDefault(s => s.Id == id);
            if (target == null) return;

            target.Status = status;

            // Atomic write: write to temp file, then replace
            var tempPath = path + ".tmp";
            var updated = JsonSerializer.Serialize(suggestions, _jsonOptions);
            File.WriteAllText(tempPath, updated);
            File.Replace(tempPath, path, null);

            Debug.WriteLine($"[SuggestionService] Suggestion {id} marked as {status}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SuggestionService] Failed to update suggestion status: {ex.Message}");
        }
    }
}

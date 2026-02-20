using System.Diagnostics;
using System.Management;
using System.Windows;
using System.Windows.Threading;
using OximyWindows.Core;
using OximyWindows.Views;

namespace OximyWindows.Services;

/// <summary>
/// Watches for new process launches and enforces app-level enforcement rules
/// (block / warn / flag). Mirror of AppBlockingService.swift on Mac.
/// </summary>
public class AppBlockingService
{
    private static AppBlockingService? _instance;
    public static AppBlockingService Instance => _instance ??= new AppBlockingService();

    private ManagementEventWatcher? _wmiWatcher;
    private DispatcherTimer? _fallbackTimer;
    private List<EnforcementRule> _rules = new();

    // Per-session dedup: tools already warned/flagged this session
    private readonly HashSet<string> _warnedToolIds = new();
    private readonly HashSet<string> _flaggedToolIds = new();

    private AppBlockingService() { }

    /// <summary>
    /// Start watching for process launches. Call after services are initialised.
    /// </summary>
    public void Start(RemoteStateService remoteStateService)
    {
        remoteStateService.EnforcementRulesChanged += OnRulesChanged;
        _rules = remoteStateService.EnforcementRules;

        if (!TryStartWmiWatcher())
        {
            Debug.WriteLine("[AppBlockingService] WMI unavailable — falling back to poll timer");
            StartFallbackTimer();
        }
    }

    public void Stop()
    {
        _wmiWatcher?.Stop();
        _wmiWatcher?.Dispose();
        _wmiWatcher = null;
        _fallbackTimer?.Stop();
        _fallbackTimer = null;
    }

    private void OnRulesChanged(object? sender, EventArgs e)
    {
        if (sender is RemoteStateService svc)
            _rules = svc.EnforcementRules;
    }

    // ─── WMI watcher ─────────────────────────────────────────────────────────

    private bool TryStartWmiWatcher()
    {
        try
        {
            var query = new WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
                "WHERE TargetInstance ISA 'Win32_Process'");

            _wmiWatcher = new ManagementEventWatcher(query);
            _wmiWatcher.EventArrived += OnWmiProcessCreated;
            _wmiWatcher.Start();

            Debug.WriteLine("[AppBlockingService] WMI process watcher started");
            return true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockingService] WMI watcher failed to start: {ex.Message}");
            return false;
        }
    }

    private void OnWmiProcessCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var instance = e.NewEvent["TargetInstance"] as ManagementBaseObject;
            var processName = instance?["Name"]?.ToString() ?? "";
            var processId   = Convert.ToInt32(instance?["ProcessId"] ?? 0);

            CheckAndEnforce(processName, processId);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockingService] WMI event error: {ex.Message}");
        }
    }

    // ─── Fallback poll timer ──────────────────────────────────────────────────

    private readonly HashSet<int> _knownPids = new();

    private void StartFallbackTimer()
    {
        // Seed known PIDs so we don't fire on already-running processes
        foreach (var p in Process.GetProcesses())
        {
            using (p) _knownPids.Add(p.Id);
        }

        _fallbackTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(5)
        };
        _fallbackTimer.Tick += OnFallbackTick;
        _fallbackTimer.Start();
    }

    private void OnFallbackTick(object? sender, EventArgs e)
    {
        try
        {
            var current = Process.GetProcesses();
            var currentPids = new HashSet<int>(current.Length);
            foreach (var p in current)
            {
                using (p)
                {
                    currentPids.Add(p.Id);
                    if (_knownPids.Contains(p.Id)) continue;
                    _knownPids.Add(p.Id);
                    CheckAndEnforce(p.ProcessName, p.Id);
                }
            }
            // Prune exited PIDs so recycled PIDs are checked again on relaunch
            _knownPids.IntersectWith(currentPids);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockingService] Fallback poll error: {ex.Message}");
        }
    }

    // ─── Enforcement logic ────────────────────────────────────────────────────

    private void CheckAndEnforce(string processName, int processId)
    {
        if (string.IsNullOrEmpty(processName)) return;

        // Normalise: strip .exe, lowercase for comparison
        var normalised = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase)
                                    .ToLowerInvariant();

        foreach (var rule in _rules)
        {
            if (rule.ToolType != "app" || string.IsNullOrEmpty(rule.WindowsAppId))
                continue;

            var ruleTarget = rule.WindowsAppId
                .Replace(".exe", "", StringComparison.OrdinalIgnoreCase)
                .ToLowerInvariant();

            if (normalised != ruleTarget) continue;

            // Check device exemption
            var deviceId = AppState.Instance.DeviceId;
            if (!string.IsNullOrEmpty(deviceId)
                && rule.ExemptDeviceIds?.Contains(deviceId) == true)
            {
                Debug.WriteLine($"[AppBlockingService] {processName} exempt for device {deviceId}");
                continue;
            }

            EnforceRule(rule, processName, processId);
        }
    }

    private void EnforceRule(EnforcementRule rule, string processName, int processId)
    {
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            switch (rule.Mode.ToLowerInvariant())
            {
                case "blocked":
                    KillAndBlock(rule, processName, processId);
                    break;

                case "warn":
                    if (_warnedToolIds.Add(rule.ToolId))
                        ShowWarnWindow(rule, processName);
                    break;

                case "flagged":
                    if (_flaggedToolIds.Add(rule.ToolId))
                        ShowFlagBalloon(rule);
                    break;
            }
        });
    }

    private static void KillAndBlock(EnforcementRule rule, string processName, int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            process.Kill();
            Debug.WriteLine($"[AppBlockingService] Killed blocked process {processName} (pid={processId})");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockingService] Failed to kill {processName}: {ex.Message}");
        }

        var window = new AppBlockWindow(rule, processName, blocked: true);
        window.Show();
    }

    private static void ShowWarnWindow(EnforcementRule rule, string processName)
    {
        var window = new AppBlockWindow(rule, processName, blocked: false);
        window.Show();
    }

    private static void ShowFlagBalloon(EnforcementRule rule)
    {
        // Balloon tip shown via MainWindow's tray icon
        var msg = rule.Message ?? $"{rule.DisplayName} usage has been flagged for review.";
        Debug.WriteLine($"[AppBlockingService] Flagged: {rule.DisplayName} — {msg}");

        // Delegate to MainWindow to show the balloon tip
        if (Application.Current?.MainWindow is Views.MainWindow mw)
            mw.ShowBalloonTip(rule.DisplayName, msg);
    }
}

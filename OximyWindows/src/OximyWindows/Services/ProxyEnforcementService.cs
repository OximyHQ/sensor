using System;
using System.Timers;

namespace OximyWindows.Services
{
    /// <summary>
    /// Detects and recovers from proxy tamper events on Windows.
    /// When enforcement is active, polls registry proxy settings every 5 seconds
    /// and re-enables the proxy if it was disabled externally.
    /// </summary>
    public class ProxyEnforcementService : IDisposable
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        private static readonly Lazy<ProxyEnforcementService> _instance = new(() => new ProxyEnforcementService());
        public static ProxyEnforcementService Instance => _instance.Value;

        private Timer? _timer;
        private int? _expectedPort;
        private bool _disposed;
        private const double PollIntervalMs = 5000; // 5 seconds

        public bool IsEnforcing { get; private set; }
        public int TamperCount { get; private set; }

        private ProxyEnforcementService() { }

        /// <summary>
        /// Start enforcing proxy settings for the given port.
        /// </summary>
        public void StartEnforcement(int port)
        {
            if (IsEnforcing) return;

            _expectedPort = port;
            IsEnforcing = true;
            TamperCount = 0;

            Logger.Info($"Starting proxy enforcement on port {port}");

            _timer = new Timer(PollIntervalMs);
            _timer.Elapsed += OnTimerElapsed;
            _timer.AutoReset = true;
            _timer.Start();
        }

        /// <summary>
        /// Stop enforcing proxy settings.
        /// </summary>
        public void StopEnforcement()
        {
            _timer?.Stop();
            _timer?.Dispose();
            _timer = null;
            _expectedPort = null;
            IsEnforcing = false;

            Logger.Info("Stopped proxy enforcement");
        }

        private void OnTimerElapsed(object? sender, ElapsedEventArgs e)
        {
            if (!IsEnforcing || _expectedPort == null) return;

            try
            {
                CheckAndEnforce();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during proxy enforcement check");
            }
        }

        private void CheckAndEnforce()
        {
            var expectedPort = _expectedPort!.Value;

            // Check current proxy state from registry
            var (isEnabled, currentPort) = ProxyService.GetCurrentProxyState();

            if (!isEnabled || currentPort != expectedPort)
            {
                TamperCount++;
                Logger.Warn($"Proxy tamper detected (count: {TamperCount}) - re-enabling proxy on port {expectedPort}");

                try
                {
                    App.ProxyService.EnableProxy(expectedPort);

                    // Also re-apply browser policies if they were tampered with
                    if (!BrowserPolicyService.ArePoliciesInstalled(expectedPort))
                    {
                        BrowserPolicyService.EnablePolicies(expectedPort);
                        Logger.Info("Browser policies re-applied after tamper detection");
                    }

                    Logger.Info("Proxy re-enabled successfully after tamper detection");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Failed to re-enable proxy after tamper detection");
                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            StopEnforcement();
        }
    }
}

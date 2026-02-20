using System;
using Microsoft.Win32;

namespace OximyWindows.Services
{
    /// <summary>
    /// Manages browser proxy policies for Chrome and Edge on Windows.
    /// Writes HKCU registry policies to enforce proxy settings at the browser level,
    /// preventing VPN extensions from overriding the system proxy.
    /// No admin privileges required — HKCU policies are treated as mandatory by Chromium browsers.
    /// </summary>
    public static class BrowserPolicyService
    {
        private static readonly string[] PolicyPaths = new[]
        {
            @"SOFTWARE\Policies\Google\Chrome",
            @"SOFTWARE\Policies\Microsoft\Edge"
        };

        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Enable browser proxy policies for the given port.
        /// </summary>
        public static void EnablePolicies(int port)
        {
            var proxyServer = $"127.0.0.1:{port}";
            var bypassList = "localhost;127.0.0.1;*.local;169.254/16";

            foreach (var keyPath in PolicyPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.CreateSubKey(keyPath);
                    if (key == null)
                    {
                        Logger.Warn($"Failed to create registry key: HKCU\\{keyPath}");
                        continue;
                    }

                    key.SetValue("ProxyMode", "fixed_servers", RegistryValueKind.String);
                    key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
                    key.SetValue("ProxyBypassList", bypassList, RegistryValueKind.String);

                    Logger.Info($"Browser policy enabled: HKCU\\{keyPath} -> {proxyServer}");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, $"Failed to set browser policy for {keyPath}");
                }
            }
        }

        /// <summary>
        /// Remove browser proxy policies.
        /// </summary>
        public static void DisablePolicies()
        {
            foreach (var keyPath in PolicyPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: true);
                    if (key == null) continue;

                    // Only delete proxy-related values, not all policies
                    foreach (var valueName in new[] { "ProxyMode", "ProxyServer", "ProxyBypassList" })
                    {
                        try { key.DeleteValue(valueName, throwOnMissingValue: false); }
                        catch { /* ignore */ }
                    }

                    // If no other values remain, delete the key entirely
                    if (key.ValueCount == 0 && key.SubKeyCount == 0)
                    {
                        var parentPath = keyPath.Substring(0, keyPath.LastIndexOf('\\'));
                        var subKeyName = keyPath.Substring(keyPath.LastIndexOf('\\') + 1);
                        using var parentKey = Registry.CurrentUser.OpenSubKey(parentPath, writable: true);
                        parentKey?.DeleteSubKey(subKeyName, throwOnMissingSubKey: false);
                    }

                    Logger.Info($"Browser policy removed: HKCU\\{keyPath}");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, $"Failed to remove browser policy for {keyPath}");
                }
            }
        }

        /// <summary>
        /// Check if browser policies are installed with the correct port.
        /// </summary>
        public static bool ArePoliciesInstalled(int port)
        {
            var expectedServer = $"127.0.0.1:{port}";

            foreach (var keyPath in PolicyPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                    if (key == null) return false;

                    var proxyMode = key.GetValue("ProxyMode") as string;
                    var proxyServer = key.GetValue("ProxyServer") as string;

                    if (proxyMode != "fixed_servers" || proxyServer != expectedServer)
                        return false;
                }
                catch
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Clean up orphaned policies on app startup.
        /// If policies exist but the proxy port is dead, remove them to prevent broken browsing.
        /// </summary>
        public static void CleanupOrphanedPolicies()
        {
            foreach (var keyPath in PolicyPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                    if (key == null) continue;

                    var proxyMode = key.GetValue("ProxyMode") as string;
                    var proxyServer = key.GetValue("ProxyServer") as string;

                    if (proxyMode != "fixed_servers" || string.IsNullOrEmpty(proxyServer))
                        continue;

                    // Extract port from "127.0.0.1:PORT"
                    var parts = proxyServer.Split(':');
                    if (parts.Length != 2 || !int.TryParse(parts[1], out var port))
                        continue;

                    // Check if port is alive
                    if (!ProxyService.IsPortListening(port))
                    {
                        Logger.Warn($"FAIL-OPEN: Found orphaned browser policy at HKCU\\{keyPath} pointing to dead port {port} - cleaning up");
                        DisablePolicies();
                        return; // Clean all at once
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, $"Error checking orphaned policy at {keyPath}");
                }
            }
        }
    }
}

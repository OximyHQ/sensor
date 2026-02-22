using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using OximyWindows.Core;
using OximyWindows.Services;

namespace OximyWindows.Views;

/// <summary>
/// Modal enforcement window shown when a blocked or warned app launches.
/// blocked=true  → process was killed, shows "Request Access" button.
/// blocked=false → warn mode, lets user continue but logs the event.
/// </summary>
public partial class AppBlockWindow : Window
{
    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    private readonly EnforcementRule _rule;
    private readonly bool _blocked;
    private bool _requestAccessMode;   // true after first click on ActionButton

    public AppBlockWindow(EnforcementRule rule, string processName, bool blocked)
    {
        InitializeComponent();
        _rule    = rule;
        _blocked = blocked;

        Height = blocked ? 310 : 260;

        PopulateUI(rule, processName, blocked);
    }

    private void PopulateUI(EnforcementRule rule, string processName, bool blocked)
    {
        AppNameText.Text = rule.DisplayName.Length > 0 ? rule.DisplayName : processName;
        LoadAppIcon(processName);

        if (blocked)
        {
            ModeIconText.Text      = "\uECE4";  // Blocked / no-entry circle
            ModeIconText.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD1, 0x34, 0x38));
            HeadlineText.Text      = "Blocked by your organization";
            ActionButton.Content   = "Request Access";
        }
        else
        {
            ModeIconText.Text      = "\uE7BA";  // Warning triangle
            ModeIconText.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xB9, 0x00));
            HeadlineText.Text      = "Flagged by your organization";
            ActionButton.Content   = "Understood";
        }

        MessageText.Text = rule.Message
            ?? (blocked
                ? $"Your organization has restricted access to {AppNameText.Text}."
                : $"Your use of {AppNameText.Text} has been flagged for review.");
    }

    private void LoadAppIcon(string processName)
    {
        try
        {
            // Try to get the icon from the running processes
            var process = Process.GetProcessesByName(
                processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();

            var fileName = process?.MainModule?.FileName;
            if (fileName == null) return;

            var icon = System.Drawing.Icon.ExtractAssociatedIcon(fileName);
            if (icon == null) return;

            using var bitmap = icon.ToBitmap();
            var hBitmap = bitmap.GetHbitmap();
            try
            {
                var bitmapSource = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                    hBitmap, IntPtr.Zero, Int32Rect.Empty,
                    BitmapSizeOptions.FromWidthAndHeight(44, 44));
                AppIconImage.Source = bitmapSource;
            }
            finally
            {
                DeleteObject(hBitmap);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockWindow] Failed to load app icon: {ex.Message}");
        }
    }

    private void DismissButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private async void ActionButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_blocked)
        {
            // Warn mode — "Understood" just closes the window
            Close();
            return;
        }

        if (!_requestAccessMode)
        {
            // First click: reveal the reason text box
            _requestAccessMode = true;
            ReasonPanel.Visibility = Visibility.Visible;
            ActionButton.Content   = "Send Request";
            Height = 380;
            return;
        }

        // Second click: send the request
        var reason = ReasonBox.Text.Trim();
        if (string.IsNullOrEmpty(reason))
        {
            ReasonBox.BorderBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD1, 0x34, 0x38));
            return;
        }

        ActionButton.IsEnabled  = false;
        ActionButton.Content    = "Sending...";
        DismissButton.IsEnabled = false;

        try
        {
            await App.APIClient.RequestAccessAsync(_rule.ToolId, reason, AppState.Instance.DeviceId);
            ActionButton.Content = "✓ Sent";
            await Task.Delay(1500);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AppBlockWindow] RequestAccess failed: {ex.Message}");
            ActionButton.Content    = "Send Request";
            ActionButton.IsEnabled  = true;
            DismissButton.IsEnabled = true;
            return;
        }

        Close();
    }
}

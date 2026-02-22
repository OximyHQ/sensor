namespace OximyWindows.Core;

/// <summary>
/// Compile-time secret defaults. All values are empty by default;
/// the actual secrets are injected at runtime via environment variables
/// (SENTRY_DSN, BETTERSTACK_ERRORS_DSN, BETTERSTACK_LOGS_TOKEN, BETTERSTACK_LOGS_HOST)
/// set by the CI build pipeline or local dev environment.
/// </summary>
internal static class Secrets
{
    public static readonly string SentryDsn = string.Empty;
    public static readonly string BetterStackLogsToken = string.Empty;
    public static readonly string BetterStackLogsHost = string.Empty;
}

namespace OneBigHead.Server.Authentication;

internal static class TokenRevocationTimestamp
{
    // Preserve the historical audit timestamp precision. Session validity uses
    // the account stamp and does not depend on wall-clock order or precision.
    public static DateTime From(DateTimeOffset value) => new(
        value.UtcTicks - value.UtcTicks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
}

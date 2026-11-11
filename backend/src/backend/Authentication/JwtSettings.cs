namespace OneBigHead.Server.Authentication;

public class JwtSettings
{
    public string SigningKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int SlidingExpirationMinutes { get; set; } = 1440; // 24 hours
    public int AbsoluteExpirationDays { get; set; } = 7;
}
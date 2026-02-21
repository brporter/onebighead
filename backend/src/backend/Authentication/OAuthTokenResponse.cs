namespace OneBigHead.Server.Authentication;

public class OAuthTokenResponse
{
    public bool Success { get; set; }
    public string? IdToken { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Error { get; set; }
}
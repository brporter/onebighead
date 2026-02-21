namespace OneBigHead.Server.Authentication;

// TODO: One Type Per File

public class AuthenticationSettings
{
    public JwtSettings Jwt { get; set; } = new();
    public OidcProviderSettings Providers { get; set; } = new();
    public CookieSettings Cookie { get; set; } = new();
    public OAuthSettings OAuth { get; set; } = new();
}
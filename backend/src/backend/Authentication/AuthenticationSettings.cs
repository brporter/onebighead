namespace OneBigHead.Server.Authentication;

public class AuthenticationSettings
{
    public JwtSettings Jwt { get; set; } = new();
    public OidcProviderSettings Providers { get; set; } = new();
    public CookieSettings Cookie { get; set; } = new();
    public OAuthSettings OAuth { get; set; } = new();
}
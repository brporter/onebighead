namespace OneBigHead.Server.Authentication;

// TODO: One Type Per File

public class AuthenticationSettings
{
    public JwtSettings Jwt { get; set; } = new();
    public OidcProviderSettings Providers { get; set; } = new();
    public CookieSettings Cookie { get; set; } = new();
    public OAuthSettings OAuth { get; set; } = new();
}

public class JwtSettings
{
    public string SigningKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int SlidingExpirationMinutes { get; set; } = 1440; // 24 hours
    public int AbsoluteExpirationDays { get; set; } = 7;
}

public class OidcProviderSettings
{
    public OidcProvider Microsoft { get; set; } = new();
    public OidcProvider Google { get; set; } = new();
    public OidcProvider Apple { get; set; } = new();
}

public class OidcProvider
{
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

public class OAuthSettings
{
    public string BaseUrl { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/api/auth/callback";
    public string PostLoginRedirectUrl { get; set; } = "/collections";
    public string PostLoginErrorUrl { get; set; } = "/signin";
}

public class CookieSettings
{
    public string Name { get; set; } = "auth_token";
    public bool Secure { get; set; } = true;
    public string SameSite { get; set; } = "Strict"; // TODO: Convert to enum in code
}



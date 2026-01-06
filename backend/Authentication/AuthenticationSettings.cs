namespace backend.Authentication;

public class AuthenticationSettings
{
    public JwtSettings Jwt { get; set; } = new();
    public OidcProviderSettings Providers { get; set; } = new();
    public CookieSettings Cookie { get; set; } = new();
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
    public bool Enabled { get; set; }
}

public class CookieSettings
{
    public string Name { get; set; } = "auth_token";
    public bool Secure { get; set; } = true;
    public string SameSite { get; set; } = "Strict";
}



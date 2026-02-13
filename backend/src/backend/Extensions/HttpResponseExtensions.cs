using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Extensions;

/// <summary>
/// Extension methods for HttpResponse to handle authentication cookies.
/// </summary>
public static class HttpResponseExtensions
{
    /// <summary>
    /// Sets the authentication cookie with the provided JWT token.
    /// </summary>
    /// <param name="response">The HTTP response.</param>
    /// <param name="token">The JWT token to set.</param>
    /// <param name="settings">The authentication settings.</param>
    public static void SetAuthCookie(this HttpResponse response, string token, AuthenticationSettings settings)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(settings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(settings.Jwt.AbsoluteExpirationDays),
            Path = "/"
        };

        response.Cookies.Append(settings.Cookie.Name, token, cookieOptions);
    }

    /// <summary>
    /// Clears the authentication cookie (for logout).
    /// </summary>
    /// <param name="response">The HTTP response.</param>
    /// <param name="settings">The authentication settings.</param>
    public static void ClearAuthCookie(this HttpResponse response, AuthenticationSettings settings)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(settings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(-1),
            Path = "/"
        };

        response.Cookies.Append(settings.Cookie.Name, "", cookieOptions);
    }
}

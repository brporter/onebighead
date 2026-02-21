using Microsoft.AspNetCore.Authentication;

namespace OneBigHead.Server.Authentication;

public static class CookieJwtAuthenticationExtensions
{
    public const string SchemeName = "CookieJwt";

    public static AuthenticationBuilder AddCookieJwtAuthentication(
        this AuthenticationBuilder builder,
        Action<CookieJwtAuthenticationOptions>? configureOptions = null)
    {
        return builder.AddScheme<CookieJwtAuthenticationOptions, CookieJwtAuthenticationHandler>(
            SchemeName,
            configureOptions ?? (_ => { }));
    }
}
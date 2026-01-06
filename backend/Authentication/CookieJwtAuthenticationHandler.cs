using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace backend.Authentication;

public class CookieJwtAuthenticationHandler : AuthenticationHandler<CookieJwtAuthenticationOptions>
{
    private readonly ITokenService _tokenService;
    private readonly AuthenticationSettings _authSettings;

    public CookieJwtAuthenticationHandler(
        IOptionsMonitor<CookieJwtAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ITokenService tokenService,
        IOptions<AuthenticationSettings> authSettings)
        : base(options, logger, encoder)
    {
        _tokenService = tokenService;
        _authSettings = authSettings.Value;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Cookies[_authSettings.Cookie.Name];

        if (string.IsNullOrEmpty(token))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var principal = _tokenService.ValidateAppToken(token);

        if (principal is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid token"));
        }

        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

public class CookieJwtAuthenticationOptions : AuthenticationSchemeOptions
{
}

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


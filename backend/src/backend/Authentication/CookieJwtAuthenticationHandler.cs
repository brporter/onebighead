using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Authentication;

public class CookieJwtAuthenticationHandler : AuthenticationHandler<CookieJwtAuthenticationOptions>
{
    /// <summary>
    /// HttpContext.Items key used to carry the <see cref="AuthErrorType"/> from
    /// authentication to the challenge response.
    /// </summary>
    public const string AuthErrorItemKey = "AuthErrorType";

    private readonly ITokenService _tokenService;
    private readonly IAccountSessionValidator _sessions;
    private readonly AuthenticationSettings _authSettings;

    public CookieJwtAuthenticationHandler(
        IOptionsMonitor<CookieJwtAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ITokenService tokenService,
        IAccountSessionValidator sessions,
        IOptions<AuthenticationSettings> authSettings)
        : base(options, logger, encoder)
    {
        _tokenService = tokenService;
        _sessions = sessions;
        _authSettings = authSettings.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Cookies[_authSettings.Cookie.Name];

        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        // Verify the signature and lifetime before looking up account state.
        var principal = _tokenService.ValidateAppToken(token);

        if (principal is null)
        {
            return AuthenticateResult.Fail("Invalid token");
        }

        var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var issuedAtClaim = principal.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
        var stampClaim = principal.FindFirst(ClaimNames.AuthenticationStamp)?.Value;

        if (!int.TryParse(userIdClaim, out var userId) || userId <= 0 ||
            !long.TryParse(issuedAtClaim, out var issuedAtUnixSeconds) ||
            issuedAtUnixSeconds < DateTimeOffset.MinValue.ToUnixTimeSeconds() ||
            issuedAtUnixSeconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
        {
            return AuthenticateResult.Fail("Invalid token claims");
        }

        // Cookies issued before stamps were introduced also require a new sign-in.
        if (!Guid.TryParseExact(stampClaim, "N", out var stamp) || stamp == Guid.Empty ||
            !await _sessions.IsCurrentAsync(userId, stamp, Context.RequestAborted))
        {
            Context.Items[AuthErrorItemKey] = AuthErrorType.SessionRevoked;
            return AuthenticateResult.Fail("Token has been revoked");
        }

        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;

        if (Context.Items.TryGetValue(AuthErrorItemKey, out var value) &&
            value is AuthErrorType errorType &&
            errorType != AuthErrorType.None)
        {
            Response.ContentType = "application/json";
            await Response.WriteAsync(JsonSerializer.Serialize(new
            {
                code = errorType.ToString(),
                error = "Authentication is no longer valid"
            }));
        }
    }
}

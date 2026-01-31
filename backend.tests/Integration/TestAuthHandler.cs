using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Test authentication handler that creates authenticated users from request headers.
/// </summary>
public class TestAuthHandler : AuthenticationHandler<TestAuthSchemeOptions>
{
    public const string SchemeName = "TestAuth";
    public const string TenantIdHeader = "X-Test-TenantId";
    public const string UserIdHeader = "X-Test-UserId";
    public const string EmailHeader = "X-Test-Email";
    public const string TenantRoleHeader = "X-Test-TenantRole";

    public TestAuthHandler(
        IOptionsMonitor<TestAuthSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check if authentication headers are present
        if (!Request.Headers.TryGetValue(TenantIdHeader, out var tenantIdValue) ||
            !Request.Headers.TryGetValue(UserIdHeader, out var userIdValue))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var tenantId = tenantIdValue.ToString();
        var userId = userIdValue.ToString();
        var email = Request.Headers.TryGetValue(EmailHeader, out var emailValue)
            ? emailValue.ToString()
            : "test@example.com";
        var tenantRole = Request.Headers.TryGetValue(TenantRoleHeader, out var roleValue)
            ? roleValue.ToString()
            : "TenantAdmin"; // Default to TenantAdmin for backwards compatibility

        var claims = new List<Claim>
        {
            new("tenant_id", tenantId),
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, email),
            new("sub", userId),
            new("tenant_role", tenantRole)
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

public class TestAuthSchemeOptions : AuthenticationSchemeOptions
{
}

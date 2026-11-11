using System.Security.Claims;

namespace OneBigHead.Server.Authentication;

/// <summary>Reads the identity required by account linking after provider token validation.</summary>
internal static class ExternalIdentityClaims
{
    public static OidcValidationResult Read(ClaimsPrincipal? principal)
    {
        var email = principal?.FindFirst("email")?.Value ?? principal?.FindFirst(ClaimTypes.Email)?.Value;
        var subject = principal?.FindFirst("sub")?.Value ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(subject))
            return new() { Error = "Email or subject claim missing" };
        return new() { IsValid = true, Email = email, Subject = subject };
    }
}

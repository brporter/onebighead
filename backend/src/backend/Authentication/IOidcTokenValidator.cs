using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public interface IOidcTokenValidator
{
    Task<OidcValidationResult> ValidateTokenAsync(string token, IdentityProvider provider);
}
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public interface IOAuthService
{
    string GenerateAuthorizationUrl(IdentityProvider provider, string state, string? nonce = null);
    Task<OAuthTokenResponse> ExchangeCodeForTokensAsync(string code, IdentityProvider provider);
    string GenerateSecureState();
    bool ValidateState(string state, string storedState);
}
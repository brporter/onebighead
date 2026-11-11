using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public interface IExternalUserService
{
    Task<ExternalSignInResult> GetOrCreateAsync(IdentityProvider provider, OidcValidationResult identity,
        CancellationToken cancellationToken = default);
}

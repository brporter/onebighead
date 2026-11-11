using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

/// <summary>Validates token callbacks with the same named provider policy used by browser sign-in.</summary>
public sealed class OidcTokenValidator(IOptions<AuthenticationSettings> settings,
    IOptionsMonitor<OpenIdConnectOptions> providers, ILogger<OidcTokenValidator> logger) : IOidcTokenValidator
{
    public async Task<OidcValidationResult> ValidateTokenAsync(string token, IdentityProvider provider)
    {
        if (!Enum.IsDefined(provider) || provider == IdentityProvider.None || !settings.Value.Providers.Get(provider).IsConfigured)
            return new() { Error = $"Provider {provider} is not configured or enabled" };

        try
        {
            var options = providers.Get(provider.ToString());
            var configuration = await options.ConfigurationManager!.GetConfigurationAsync(CancellationToken.None);
            var parameters = options.TokenValidationParameters.Clone();
            parameters.ValidIssuers = (parameters.ValidIssuers ?? []).Append(configuration.Issuer);
            parameters.IssuerSigningKeys = (parameters.IssuerSigningKeys ?? []).Concat(configuration.SigningKeys);
            // IdentityModel owns cached discovery and signing-key refresh. Static
            // configurations still work through the explicit issuer/key values above.
            parameters.ConfigurationManager = options.ConfigurationManager as BaseConfigurationManager;

            var result = await options.TokenHandler.ValidateTokenAsync(token, parameters);
            if (!result.IsValid)
            {
                logger.LogWarning(result.Exception, "Token validation failed for provider {Provider}", provider);
                return new() { Error = "Token validation failed" };
            }
            return ExternalIdentityClaims.Read(new ClaimsPrincipal(result.ClaimsIdentity));
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unexpected error validating token for provider {Provider}", provider);
            return new() { Error = "An unexpected error occurred during token validation" };
        }
    }
}

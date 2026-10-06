using Microsoft.IdentityModel.Validators;
using System.IdentityModel.Tokens.Jwt;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace OneBigHead.Server.Authentication;

public class OidcTokenValidator : IOidcTokenValidator
{
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<OidcTokenValidator> _logger;
    private readonly Dictionary<IdentityProvider, ConfigurationManager<OpenIdConnectConfiguration>> _configManagers;

    public OidcTokenValidator(IOptions<AuthenticationSettings> settings, ILogger<OidcTokenValidator> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _configManagers = new Dictionary<IdentityProvider, ConfigurationManager<OpenIdConnectConfiguration>>();

        InitializeConfigurationManagers();
    }

    private void InitializeConfigurationManagers()
    {
        foreach (var provider in new[] { IdentityProvider.Microsoft, IdentityProvider.Google, IdentityProvider.Apple })
        {
            var configuration = _settings.Providers.Get(provider);
            if (!configuration.Enabled) continue;
            _configManagers[provider] = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{configuration.Authority}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever());
        }
    }

    public async Task<OidcValidationResult> ValidateTokenAsync(string token, IdentityProvider provider)
    {
        if (!_configManagers.TryGetValue(provider, out var configManager))
        {
            return new OidcValidationResult
            {
                IsValid = false,
                Error = $"Provider {provider} is not configured or enabled"
            };
        }

        try
        {
            var config = await configManager.GetConfigurationAsync(CancellationToken.None);
            var providerSettings = _settings.Providers.Get(provider);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.Issuer,
                IssuerValidator = provider == IdentityProvider.Microsoft
                    ? AadIssuerValidator.GetAadIssuerValidator(providerSettings.Authority).Validate
                    : null,
                ValidateAudience = true,
                ValidAudience = providerSettings.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            var email = principal.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                        ?? principal.FindFirst("email")?.Value;
            var subject = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                          ?? principal.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(email))
            {
                return new OidcValidationResult
                {
                    IsValid = false,
                    Error = "Email claim not found in token"
                };
            }

            return new OidcValidationResult
            {
                IsValid = true,
                Email = email,
                Subject = subject
            };
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning(ex, "Token validation failed for provider {Provider}", provider);
            return new OidcValidationResult
            {
                IsValid = false,
                Error = "Token validation failed: " + ex.Message
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating token for provider {Provider}", provider);
            return new OidcValidationResult
            {
                IsValid = false,
                Error = "An unexpected error occurred during token validation"
            };
        }
    }

}

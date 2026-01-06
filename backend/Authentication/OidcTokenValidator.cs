using System.IdentityModel.Tokens.Jwt;
using backend.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace backend.Authentication;

public interface IOidcTokenValidator
{
    Task<OidcValidationResult> ValidateTokenAsync(string token, IdentityProvider provider);
}

public class OidcValidationResult
{
    public bool IsValid { get; set; }
    public string? Email { get; set; }
    public string? Subject { get; set; }
    public string? Error { get; set; }
}

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
        if (_settings.Providers.Microsoft.Enabled)
        {
            var metadataAddress = $"{_settings.Providers.Microsoft.Authority}/.well-known/openid-configuration";
            _configManagers[IdentityProvider.Microsoft] = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
        }

        if (_settings.Providers.Google.Enabled)
        {
            var metadataAddress = $"{_settings.Providers.Google.Authority}/.well-known/openid-configuration";
            _configManagers[IdentityProvider.Google] = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
        }

        if (_settings.Providers.Apple.Enabled)
        {
            var metadataAddress = $"{_settings.Providers.Apple.Authority}/.well-known/openid-configuration";
            _configManagers[IdentityProvider.Apple] = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
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
            var providerSettings = GetProviderSettings(provider);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.Issuer,
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

    private OidcProvider GetProviderSettings(IdentityProvider provider)
    {
        return provider switch
        {
            IdentityProvider.Microsoft => _settings.Providers.Microsoft,
            IdentityProvider.Google => _settings.Providers.Google,
            IdentityProvider.Apple => _settings.Providers.Apple,
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };
    }
}


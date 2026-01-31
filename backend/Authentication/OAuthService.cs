using System.Security.Cryptography;
using System.Text.Json;
using System.Web;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Authentication;

public interface IOAuthService
{
    string GenerateAuthorizationUrl(IdentityProvider provider, string state, string? nonce = null);
    Task<OAuthTokenResponse> ExchangeCodeForTokensAsync(string code, IdentityProvider provider);
    string GenerateSecureState();
    bool ValidateState(string state, string storedState);
}

public class OAuthTokenResponse
{
    public bool Success { get; set; }
    public string? IdToken { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Error { get; set; }
}

public class OAuthService : IOAuthService
{
    private readonly AuthenticationSettings _settings;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OAuthService> _logger;
    private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

    // Provider-specific authorization and token endpoints
    private static readonly Dictionary<IdentityProvider, (string AuthEndpoint, string TokenEndpoint, string Scopes)> ProviderEndpoints = new()
    {
        [IdentityProvider.Microsoft] = (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "openid profile email"
        ),
        [IdentityProvider.Google] = (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "openid profile email"
        ),
        [IdentityProvider.Apple] = (
            "https://appleid.apple.com/auth/authorize",
            "https://appleid.apple.com/auth/token",
            "openid name email"
        )
    };

    public OAuthService(
        IOptions<AuthenticationSettings> settings,
        IHttpClientFactory httpClientFactory,
        ILogger<OAuthService> logger)
    {
        _settings = settings.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public string GenerateSecureState()
    {
        Span<byte> bytes = stackalloc byte[32];
        _rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }

    public bool ValidateState(string state, string storedState)
    {
        if (string.IsNullOrWhiteSpace(state) || string.IsNullOrWhiteSpace(storedState))
        {
            return false;
        }
        return string.CompareOrdinal(state, storedState) == 0;
    }

    public string GenerateAuthorizationUrl(IdentityProvider provider, string state, string? nonce = null)
    {
        var providerSettings = GetProviderSettings(provider);
        if (!providerSettings.Enabled)
        {
            throw new InvalidOperationException($"Provider {provider} is not enabled");
        }

        if (!ProviderEndpoints.TryGetValue(provider, out var endpoints))
        {
            throw new InvalidOperationException($"Unknown provider: {provider}");
        }

        var redirectUri = $"{_settings.OAuth.BaseUrl}{_settings.OAuth.CallbackPath}/{provider.ToString().ToLower()}";

        var queryParams = new Dictionary<string, string>
        {
            ["client_id"] = providerSettings.ClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = endpoints.Scopes,
            ["state"] = state
        };

        // Add nonce for OpenID Connect
        if (!string.IsNullOrEmpty(nonce))
        {
            queryParams["nonce"] = nonce;
        }

        // Provider-specific parameters
        if (provider == IdentityProvider.Microsoft)
        {
            queryParams["response_mode"] = "query";
        }
        else if (provider == IdentityProvider.Apple)
        {
            queryParams["response_mode"] = "form_post";
        }

        var queryString = string.Join("&", 
            queryParams.Select(kvp => $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

        return $"{endpoints.AuthEndpoint}?{queryString}";
    }

    public async Task<OAuthTokenResponse> ExchangeCodeForTokensAsync(string code, IdentityProvider provider)
    {
        var providerSettings = GetProviderSettings(provider);
        if (!ProviderEndpoints.TryGetValue(provider, out var endpoints))
        {
            return new OAuthTokenResponse
            {
                Success = false,
                Error = $"Unknown provider: {provider}"
            };
        }

        var redirectUri = $"{_settings.OAuth.BaseUrl}{_settings.OAuth.CallbackPath}/{provider.ToString().ToLower()}";

        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = providerSettings.ClientId,
            ["client_secret"] = providerSettings.ClientSecret
        };

        try
        {
            var client = _httpClientFactory.CreateClient();
            var content = new FormUrlEncodedContent(tokenRequest);
            
            var response = await client.PostAsync(endpoints.TokenEndpoint, content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token exchange failed for {Provider}: {StatusCode} - {Response}", 
                    provider, response.StatusCode, responseBody);
                return new OAuthTokenResponse
                {
                    Success = false,
                    Error = $"Token exchange failed: {response.StatusCode}"
                };
            }

            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

            return new OAuthTokenResponse
            {
                Success = true,
                IdToken = tokenResponse.TryGetProperty("id_token", out var idToken) ? idToken.GetString() : null,
                AccessToken = tokenResponse.TryGetProperty("access_token", out var accessToken) ? accessToken.GetString() : null,
                RefreshToken = tokenResponse.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exchanging code for tokens with {Provider}", provider);
            return new OAuthTokenResponse
            {
                Success = false,
                Error = "An error occurred during token exchange"
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


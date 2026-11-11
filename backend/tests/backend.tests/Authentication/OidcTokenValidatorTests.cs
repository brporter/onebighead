using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class OidcTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://identity.example.test";
    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string MicrosoftIssuer = "https://login.microsoftonline.com/" + Tenant + "/v2.0";
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly Mock<ILogger<OidcTokenValidator>> _logger = new();
    private RsaSecurityKey Key => new(_rsa) { KeyId = "current-key" };
    public void Dispose() => _rsa.Dispose();

    [Theory]
    [InlineData(IdentityProvider.Google)]
    [InlineData(IdentityProvider.Apple)]
    [InlineData(IdentityProvider.Microsoft)]
    public async Task RegisteredProvider_ValidatesSignedIdentityWithItsNamedPolicy(IdentityProvider provider)
    {
        using var services = Services(provider);
        var result = await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(
            Token(issuer: provider == IdentityProvider.Microsoft ? MicrosoftIssuer : Issuer), provider);
        Assert.True(result.IsValid, result.Error);
        Assert.Equal("reader@example.test", result.Email);
        Assert.Equal("provider-subject", result.Subject);
        Assert.Null(result.Error);
        _logger.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(IdentityProvider.None)]
    [InlineData((IdentityProvider)999)]
    [InlineData(IdentityProvider.Google)]
    public async Task UnsupportedOrDisabledProvider_DoesNotReadDiscovery(IdentityProvider provider)
    {
        var options = new Mock<IOptionsMonitor<OpenIdConnectOptions>>(MockBehavior.Strict);
        var validator = new OidcTokenValidator(Options.Create(new AuthenticationSettings()), options.Object, _logger.Object);
        var result = await validator.ValidateTokenAsync("unused", provider);
        Assert.False(result.IsValid);
        Assert.Contains("not configured or enabled", result.Error);
        options.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task IncompleteProvider_DoesNotReadDiscovery(bool missingAudience)
    {
        var settings = Settings(IdentityProvider.Google);
        if (missingAudience) settings.Providers.Google.ClientId = " ";
        else settings.Providers.Google.Authority = " ";
        var options = new Mock<IOptionsMonitor<OpenIdConnectOptions>>(MockBehavior.Strict);
        Assert.False((await new OidcTokenValidator(Options.Create(settings), options.Object, _logger.Object)
            .ValidateTokenAsync("unused", IdentityProvider.Google)).IsValid);
        options.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("audience")]
    [InlineData("issuer")]
    [InlineData("signature")]
    [InlineData("unsigned")]
    [InlineData("expired")]
    [InlineData("premature")]
    [InlineData("no-expiration")]
    [InlineData("malformed")]
    public async Task InvalidToken_IsRejectedWithoutExposingValidationDetails(string invalid)
    {
        var token = invalid switch
        {
            "audience" => Token(audience: "another-client"),
            "issuer" => Token(issuer: "https://untrusted.example.test"),
            "unsigned" => Token(unsigned: true),
            "expired" => Token(notBefore: DateTime.UtcNow.AddHours(-1), expires: DateTime.UtcNow.AddMinutes(-10)),
            "premature" => Token(notBefore: DateTime.UtcNow.AddMinutes(10), expires: DateTime.UtcNow.AddMinutes(20)),
            "no-expiration" => Token(noExpiration: true),
            "malformed" => "not-a-jwt",
            _ => Token()
        };
        if (invalid == "signature")
        {
            var pieces = token.Split('.');
            pieces[2] = (pieces[2][0] == 'A' ? 'B' : 'A') + pieces[2][1..];
            token = string.Join('.', pieces);
        }
        using var services = Services();
        var result = await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(token, IdentityProvider.Google);
        Assert.False(result.IsValid);
        Assert.Null(result.Subject);
        Assert.Null(result.Email);
        Assert.Equal("Token validation failed", result.Error);
        var log = Assert.Single(_logger.Invocations);
        Assert.Equal(LogLevel.Warning, log.Arguments[0]);
    }

    [Theory]
    [InlineData(null, "subject")]
    [InlineData("", "subject")]
    [InlineData(" \t", "subject")]
    [InlineData("reader@example.test", null)]
    [InlineData("reader@example.test", "")]
    [InlineData("reader@example.test", " \t")]
    public async Task MissingIdentityClaims_AreRejectedAfterSignatureValidation(string? email, string? subject)
    {
        var claims = new List<Claim>();
        if (email != null) claims.Add(new("email", email));
        if (subject != null) claims.Add(new("sub", subject));
        using var services = Services();
        var result = await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(Token(claims: claims), IdentityProvider.Google);
        Assert.False(result.IsValid);
        Assert.Equal("Email or subject claim missing", result.Error);
    }

    [Fact]
    public async Task MappedIdentityClaims_RemainSupported()
    {
        using var services = Services();
        var token = Token(claims: [new(ClaimTypes.Email, "mapped@example.test"), new(ClaimTypes.NameIdentifier, "mapped-subject")]);
        var result = await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(token, IdentityProvider.Google);
        Assert.True(result.IsValid);
        Assert.Equal("mapped@example.test", result.Email);
        Assert.Equal("mapped-subject", result.Subject);
    }

    [Theory]
    [InlineData("alternate-client", false)]
    [InlineData(null, true)]
    [InlineData("", true)]
    public async Task ExplicitAudiencePolicy_IsPreservedAndSharedOptionsAreNotMutated(string? audience, bool useList)
    {
        using var services = Services(configure: options =>
        {
            options.TokenValidationParameters.ValidAudience = audience;
            options.TokenValidationParameters.ValidAudiences = useList ? ["alternate-client"] : null;
        });
        var policy = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google").TokenValidationParameters;
        // ASP.NET's post-configuration supplies the client ID when the primary
        // audience is empty. The callback must preserve that effective policy.
        var primaryAudience = string.IsNullOrEmpty(audience) ? "client" : audience;
        Assert.Equal(primaryAudience, policy.ValidAudience);
        var validator = services.GetRequiredService<IOidcTokenValidator>();
        Assert.True((await validator.ValidateTokenAsync(Token(audience: "alternate-client"), IdentityProvider.Google)).IsValid);
        Assert.Equal(primaryAudience == "client", (await validator.ValidateTokenAsync(Token(), IdentityProvider.Google)).IsValid);
        Assert.Equal(primaryAudience, policy.ValidAudience);
        Assert.Null(policy.ValidIssuers);
        Assert.Null(policy.IssuerSigningKeys);
        Assert.Null(policy.ConfigurationManager);
    }

    [Fact]
    public async Task ExtraTrustedIssuerAndKey_AreRetainedAlongsideDiscoveryValues()
    {
        using var other = RSA.Create(2048);
        var extra = new RsaSecurityKey(other) { KeyId = "additional-key" };
        using var services = Services(configure: options =>
        {
            options.TokenValidationParameters.ValidIssuers = ["https://additional.example.test"];
            options.TokenValidationParameters.IssuerSigningKeys = [extra];
        });
        var validator = services.GetRequiredService<IOidcTokenValidator>();
        Assert.True((await validator.ValidateTokenAsync(Token(issuer: "https://additional.example.test", key: extra), IdentityProvider.Google)).IsValid);
        Assert.True((await validator.ValidateTokenAsync(Token(), IdentityProvider.Google)).IsValid);
        var policy = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google").TokenValidationParameters;
        Assert.Equal("https://additional.example.test", Assert.Single(policy.ValidIssuers!));
        Assert.Same(extra, Assert.Single(policy.IssuerSigningKeys!));
    }

    [Fact]
    public async Task NamedLifetimePolicy_IsUsedInsteadOfAnIndependentClockSkew()
    {
        using var services = Services(configure: options => options.TokenValidationParameters.ClockSkew = TimeSpan.Zero);
        var expired = Token(notBefore: DateTime.UtcNow.AddMinutes(-5), expires: DateTime.UtcNow.AddMinutes(-1));
        Assert.False((await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(expired, IdentityProvider.Google)).IsValid);
    }

    [Fact]
    public async Task Discovery_IsSharedCachedAndSafeForConcurrentValidation()
    {
        var requests = new List<string>();
        using var backchannel = new HttpClient(new DiscoveryHandler(request =>
        {
            lock (requests) requests.Add(request.RequestUri!.AbsolutePath);
            return DiscoveryResponse(request, Key);
        }));
        using var services = Services(configure: options => { options.Configuration = null; options.Backchannel = backchannel; });
        var validator = services.GetRequiredService<IOidcTokenValidator>();
        var token = Token();
        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => validator.ValidateTokenAsync(token, IdentityProvider.Google)));
        Assert.All(results, result => Assert.True(result.IsValid, result.Error));
        Assert.Equal(new[] { "/.well-known/openid-configuration", "/keys" }, requests);
        var manager = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google").ConfigurationManager;
        Assert.NotNull(await manager!.GetConfigurationAsync(default));
        Assert.Equal(2, requests.Count);
    }

    [Fact]
    public async Task DiscoveryFailure_ProducesGenericErrorAndDoesNotExposeInternalDetails()
    {
        using var backchannel = new HttpClient(new DiscoveryHandler(_ => throw new HttpRequestException("private-provider-detail")));
        using var services = Services(configure: options => { options.Configuration = null; options.Backchannel = backchannel; });
        var result = await services.GetRequiredService<IOidcTokenValidator>().ValidateTokenAsync(Token(), IdentityProvider.Google);
        Assert.False(result.IsValid);
        Assert.Equal("An unexpected error occurred during token validation", result.Error);
        Assert.Equal(LogLevel.Error, Assert.Single(_logger.Invocations).Arguments[0]);
    }

    [Fact]
    public async Task NewSigningKey_RefreshesCachedDiscoveryAndValidatesAfterRollover()
    {
        using var replacementRsa = RSA.Create(2048);
        var replacement = new RsaSecurityKey(replacementRsa) { KeyId = "replacement-key" };
        var published = Key;
        var refreshed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var backchannel = new HttpClient(new DiscoveryHandler(request =>
        {
            var key = Volatile.Read(ref published);
            var response = DiscoveryResponse(request, key);
            if (request.RequestUri!.AbsolutePath == "/keys" && key.KeyId == replacement.KeyId) refreshed.TrySetResult();
            return response;
        }));
        using var services = Services(configure: options => { options.Configuration = null; options.Backchannel = backchannel; });
        var validator = services.GetRequiredService<IOidcTokenValidator>();
        Assert.True((await validator.ValidateTokenAsync(Token(), IdentityProvider.Google)).IsValid);
        Volatile.Write(ref published, replacement);
        var rotatedToken = Token(key: replacement);
        await validator.ValidateTokenAsync(rotatedToken, IdentityProvider.Google);
        await refreshed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var manager = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google").ConfigurationManager!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!(await manager.GetConfigurationAsync(timeout.Token)).SigningKeys.Any(k => k.KeyId == replacement.KeyId))
            await Task.Delay(10, timeout.Token);
        var result = await validator.ValidateTokenAsync(rotatedToken, IdentityProvider.Google);
        Assert.True(result.IsValid, result.Error);
        Assert.Equal("provider-subject", result.Subject);
    }

    private ServiceProvider Services(IdentityProvider provider = IdentityProvider.Google, Action<OpenIdConnectOptions>? configure = null)
    {
        var settings = Settings(provider);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(settings));
        services.AddSingleton(_logger.Object);
        services.AddAuthentication().AddExternalProviders(settings);
        services.Configure<OpenIdConnectOptions>(provider.ToString(), options =>
        {
            options.Configuration = new OpenIdConnectConfiguration { Issuer = provider == IdentityProvider.Microsoft ? MicrosoftIssuer : Issuer };
            options.Configuration.SigningKeys.Add(Key);
            configure?.Invoke(options);
        });
        services.AddSingleton<IOidcTokenValidator, OidcTokenValidator>();
        return services.BuildServiceProvider();
    }

    private static AuthenticationSettings Settings(IdentityProvider provider)
    {
        var settings = new AuthenticationSettings();
        var configuration = settings.Providers.Get(provider);
        configuration.Enabled = true;
        configuration.ClientId = "client";
        configuration.Authority = provider == IdentityProvider.Microsoft ? "https://login.microsoftonline.com/common/v2.0" : Issuer + "/";
        return settings;
    }

    private string Token(string issuer = Issuer, string audience = "client", IEnumerable<Claim>? claims = null,
        DateTime? notBefore = null, DateTime? expires = null, bool unsigned = false, bool noExpiration = false, SecurityKey? key = null) =>
        new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(issuer, audience,
            claims ?? [new("email", "reader@example.test"), new("sub", "provider-subject"), new("tid", Tenant)],
            noExpiration ? null : notBefore ?? DateTime.UtcNow.AddMinutes(-1), noExpiration ? null : expires ?? DateTime.UtcNow.AddMinutes(5),
            unsigned ? null : new SigningCredentials(key ?? Key, SecurityAlgorithms.RsaSha256)));

    private static HttpResponseMessage DiscoveryResponse(HttpRequestMessage request, RsaSecurityKey key)
    {
        string json;
        if (request.RequestUri!.AbsolutePath == "/.well-known/openid-configuration")
            json = JsonSerializer.Serialize(new { issuer = Issuer, jwks_uri = Issuer + "/keys", authorization_endpoint = Issuer + "/authorize", token_endpoint = Issuer + "/token" });
        else
        {
            Assert.Equal("/keys", request.RequestUri.AbsolutePath);
            var parameters = key.Rsa.ExportParameters(false);
            json = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = key.KeyId,
                n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } });
        }
        return new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    private sealed class DiscoveryHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }
}

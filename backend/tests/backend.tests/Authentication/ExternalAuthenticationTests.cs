using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class ExternalAuthenticationTests
{
    [Theory]
    [InlineData("Google", false, false)]
    [InlineData("Apple", true, false)]
    [InlineData("Google", false, true)]
    public async Task Handler_ValidatesCallbackBeforeIssuingAppCookie(string scheme, bool formPost, bool invalidNonce)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test-key" };
        var settings = Settings();
        settings.OAuth.BaseUrl = formPost ? "https://app.example" : "";
        var users = new Mock<IExternalUserService>();
        users.Setup(s => s.GetOrCreateAsync(It.IsAny<IdentityProvider>(), It.IsAny<OidcValidationResult>()))
            .ReturnsAsync((new User { Id = 1, Email = "user@example.com" }, WorkspaceRole.WorkspaceAdmin));
        var tokens = new Mock<ITokenService>();
        tokens.Setup(s => s.GenerateAppToken(It.IsAny<User>(), WorkspaceRole.WorkspaceAdmin)).Returns("app-jwt");
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(users.Object);
        builder.Services.AddSingleton(tokens.Object);
        builder.Services.AddAuthentication(CookieJwtAuthenticationExtensions.SchemeName)
            .AddCookie(CookieJwtAuthenticationExtensions.SchemeName).AddExternalProviders(settings);
        string? nonce = null;
        string? verifier = null;
        builder.Services.Configure<OpenIdConnectOptions>(scheme, options =>
        {
            options.Configuration = new OpenIdConnectConfiguration
            {
                Issuer = "https://identity.example",
                AuthorizationEndpoint = "https://identity.example/authorize",
                TokenEndpoint = "https://identity.example/token"
            };
            options.Configuration.SigningKeys.Add(key);
            options.Backchannel = new HttpClient(new TokenEndpoint(async request =>
            {
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync());
                verifier = form.GetValueOrDefault("code_verifier");
                Assert.Equal("authorization_code", form["grant_type"]);
                Assert.Equal("code", form["code"]);
                var jwt = new JwtSecurityToken("https://identity.example", "client",
                    [new Claim("iat", EpochTime.GetIntDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64), new Claim("sub", "subject"), new Claim("email", "user@example.com"), new Claim("nonce", invalidNonce ? "wrong" : nonce!)],
                    DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new
                    {
                        id_token = new JwtSecurityTokenHandler().WriteToken(jwt), access_token = "access", token_type = "Bearer"
                    }), Encoding.UTF8, "application/json")
                };
            }));
        });
        await using var app = builder.Build();
        app.UseAuthentication();
        app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/collections/42" }, [scheme]));
        await app.StartAsync();
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        var challenge = await client.GetAsync("/login");
        var query = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);
        nonce = query["nonce"];
        Assert.False(string.IsNullOrEmpty(nonce));
        Assert.Equal(formPost ? "form_post" : "", query.GetValueOrDefault("response_mode").ToString());
        Assert.Equal(!formPost, query.ContainsKey("code_challenge"));
        client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", challenge.Headers.GetValues("Set-Cookie").Select(c => c.Split(';')[0])));
        var path = $"/api/auth/callback/{scheme.ToLowerInvariant()}";
        var values = new Dictionary<string, string> { ["code"] = "code", ["state"] = query["state"].ToString() };
        var response = formPost ? await client.PostAsync(path, new FormUrlEncodedContent(values))
            : await client.GetAsync(QueryHelpers.AddQueryString(path, values!));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        if (invalidNonce)
        {
            Assert.StartsWith("/signin?error=", response.Headers.Location!.OriginalString);
            users.Verify(s => s.GetOrCreateAsync(It.IsAny<IdentityProvider>(), It.IsAny<OidcValidationResult>()), Times.Never);
            Assert.DoesNotContain(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("auth_token="));
        }
        else
        {
            Assert.Equal("/collections/42", response.Headers.Location!.OriginalString);
            Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("auth_token=app-jwt"));
            users.Verify(s => s.GetOrCreateAsync(Enum.Parse<IdentityProvider>(scheme), It.Is<OidcValidationResult>(i => i.Email == "user@example.com" && i.Subject == "subject")), Times.Once);
        }
        Assert.Equal(!formPost, !string.IsNullOrEmpty(verifier));
    }

    [Fact]
    public async Task Registration_UsesMicrosoftIssuerValidatorAndSkipsDisabledProviders()
    {
        var builder = WebApplication.CreateBuilder();
        var settings = Settings();
        settings.Providers.Google.Enabled = false;
        settings.Providers.Microsoft = new OidcProvider { Enabled = true, ClientId = "client", Authority = "https://login.microsoftonline.com/common/v2.0" };
        builder.Services.AddAuthentication().AddExternalProviders(settings);
        await using var app = builder.Build();
        var schemes = await app.Services.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        Assert.DoesNotContain(schemes, s => s.Name == "Google");
        Assert.NotNull(app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Microsoft").TokenValidationParameters.IssuerValidator);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TicketWithoutIdentityOrAccount_DoesNotIssueCookie(bool missingClaims)
    {
        var builder = WebApplication.CreateBuilder();
        var users = new Mock<IExternalUserService>();
        users.Setup(s => s.GetOrCreateAsync(It.IsAny<IdentityProvider>(), It.IsAny<OidcValidationResult>()))
            .ReturnsAsync(((User?)null, WorkspaceRole.Normal));
        builder.Services.AddSingleton(users.Object);
        builder.Services.AddAuthentication().AddExternalProviders(Settings());
        await using var app = builder.Build();
        var options = app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google");
        var http = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = app.Services };
        var identity = new ClaimsIdentity(missingClaims ? [] : [new Claim("sub", "subject"), new Claim("email", "user@example.com")]);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), "Google");
        var context = new TicketReceivedContext(http, new AuthenticationScheme("Google", "Google", typeof(OpenIdConnectHandler)), options, ticket);
        await options.Events.TicketReceived(context);
        Assert.Equal(302, http.Response.StatusCode);
        Assert.StartsWith("/signin?error=", http.Response.Headers.Location.ToString());
        Assert.Equal(0, http.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public void ProviderSettings_RejectUnsupportedProvider() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new OidcProviderSettings().Get(IdentityProvider.None));

    private static AuthenticationSettings Settings() => new()
    {
        Cookie = new CookieSettings { Name = "auth_token", Secure = true },
        Providers = new OidcProviderSettings
        {
            Google = new OidcProvider { Enabled = true, Authority = "https://identity.example", ClientId = "client", ClientSecret = "secret" },
            Apple = new OidcProvider { Enabled = true, Authority = "https://identity.example", ClientId = "client", ClientSecret = "secret" }
        }
    };

    private sealed class TokenEndpoint(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(request);
    }
}

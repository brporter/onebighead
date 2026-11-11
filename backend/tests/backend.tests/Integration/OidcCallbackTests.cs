using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class OidcCallbackTests
{
    [Theory]
    [InlineData("valid", HttpStatusCode.OK)]
    [InlineData("invalid-signature", HttpStatusCode.Unauthorized)]
    [InlineData("missing-subject", HttpStatusCode.Unauthorized)]
    [InlineData("missing-email", HttpStatusCode.Unauthorized)]
    [InlineData("disabled", HttpStatusCode.Unauthorized)]
    [InlineData("unsupported", HttpStatusCode.BadRequest)]
    public async Task Callback_ValidatesBeforeProvisioningAndIssuingAnAppCookie(string kind, HttpStatusCode expected)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "local-test-key" };
        const string issuer = "https://identity.example.test";
        var configuration = new OpenIdConnectConfiguration { Issuer = issuer };
        configuration.SigningKeys.Add(key);
        var settings = new AuthenticationSettings
        {
            Providers = new() { Google = new() { Enabled = kind != "disabled", ClientId = "client", Authority = issuer } },
            Jwt = new() { SigningKey = "local-test-signing-key-with-more-than-32-characters", Issuer = "test-app", Audience = "test-app" }
        };
        var user = new User { Id = 7, Email = "reader@example.test", ActiveWorkspaceId = 2,
            ActiveWorkspace = new Workspace { Id = 2, Name = "Library" } };
        var users = new Mock<IExternalUserService>(MockBehavior.Strict);
        users.Setup(u => u.GetOrCreateAsync(IdentityProvider.Google,
            It.Is<OidcValidationResult>(identity => identity.IsValid && identity.Subject == "subject" && identity.Email == user.Email), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ExternalSignInResult(user, WorkspaceRole.Normal));
        using var factory = new CustomWebApplicationFactory();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.AddSingleton(Options.Create(settings));
            services.AddSingleton(users.Object);
            services.Configure<OpenIdConnectOptions>("Google", options =>
            {
                options.ClientId = "client";
                options.TokenValidationParameters.ValidAudience = "client";
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
            });
        }));
        using var client = host.CreateClient();
        var claims = new List<Claim>();
        if (kind != "missing-email") claims.Add(new("email", user.Email));
        if (kind != "missing-subject") claims.Add(new("sub", "subject"));
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(issuer, "client", claims,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), new SigningCredentials(key, SecurityAlgorithms.RsaSha256)));
        if (kind == "invalid-signature")
        {
            var pieces = token.Split('.');
            pieces[2] = (pieces[2][0] == 'A' ? 'B' : 'A') + pieces[2][1..];
            token = string.Join('.', pieces);
        }
        var response = await client.PostAsJsonAsync("/api/auth/callback", new AuthCallbackRequest
            { Provider = kind == "unsupported" ? "999" : "Google", Token = token });
        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.OK)
        {
            var result = await response.Content.ReadFromJsonAsync<AuthCallbackResponse>();
            Assert.True(result!.Success);
            Assert.Equal(user.Email, result.Email);
            Assert.Equal(2, result.WorkspaceId);
            Assert.Equal("Library", result.WorkspaceName);
            Assert.Contains(response.Headers.GetValues("Set-Cookie"), cookie => cookie.StartsWith(settings.Cookie.Name + "="));
            users.VerifyAll();
        }
        else
        {
            Assert.False(response.Headers.Contains("Set-Cookie"));
            users.VerifyNoOtherCalls();
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(token, body);
            Assert.DoesNotContain("IDX", body);
        }
    }
}

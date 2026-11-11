using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;
using OneBigHead.Server.Pages;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class PublicPagesTests
{
    [Fact]
    public void DevelopmentSignIn_EndpointRequestAndViewAreCompiledOnlyInDebug()
    {
        var assembly = typeof(SignInModel).Assembly;
        var endpoint = typeof(OneBigHead.Server.Controllers.AuthController).GetMethod("DevLogin");
        var request = assembly.GetType("OneBigHead.Server.DTOs.DevLoginRequest");
        var views = assembly.GetCustomAttributes<Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute>();
        const string developmentView = "/Pages/Shared/_DevelopmentSignIn.cshtml";
#if DEBUG
        Assert.NotNull(endpoint);
        Assert.NotNull(request);
        Assert.Contains(views, view => view.Identifier == developmentView);
#else
        Assert.Null(endpoint);
        Assert.Null(request);
        Assert.DoesNotContain(views, view => view.Identifier == developmentView);
#endif
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LandingPage_UsesCookieAuthenticationIncludingRevocation(bool revoked)
    {
        var revocations = new Mock<IAccountSessionValidator>();
        revocations.Setup(r => r.IsCurrentAsync(7, It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ReturnsAsync(!revoked);
        var workspaces = new Mock<IWorkspaceAccessService>();
        workspaces.Setup(w => w.HasUserAnyActiveWorkspaceAsync(7)).ReturnsAsync(true);
        using var factory = new CustomWebApplicationFactory();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.Configure<AuthenticationOptions>(options =>
            {
                options.DefaultAuthenticateScheme = CookieJwtAuthenticationExtensions.SchemeName;
                options.DefaultChallengeScheme = CookieJwtAuthenticationExtensions.SchemeName;
            });
            services.AddSingleton(revocations.Object);
            services.AddSingleton(workspaces.Object);
        }));
        using var client = host.CreateClient();
        var token = host.Services.GetRequiredService<ITokenService>().GenerateAppToken(new User
            { Id = 7, Email = "reader@example.test", ActiveWorkspaceId = 1 }, WorkspaceRole.Normal);
        var cookieName = host.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        client.DefaultRequestHeaders.Add("Cookie", $"{cookieName}={token}");
        var response = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        if (revoked)
        {
            Assert.Contains("Get Started", html);
            Assert.DoesNotContain("My Collections", html);
            Assert.DoesNotContain("Sign Out", html);
        }
        else
        {
            Assert.Contains("My Collections", html);
            Assert.Contains("Go to Collections", html);
            Assert.DoesNotContain("Get Started", html);
        }
        revocations.Verify(r => r.IsCurrentAsync(7, It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Theory]
    [InlineData("/settings?section=support", "/settings?section=support")]
    [InlineData("/');alert('untrusted');//", "/');alert('untrusted');//")]
    [InlineData("/</script><script>alert('untrusted')</script>", "/</script><script>alert('untrusted')</script>")]
    [InlineData("https://elsewhere.example.test", "/collections")]
    [InlineData("//elsewhere.example.test", "/collections")]
    [InlineData("/\r\n/elsewhere.example.test", "/collections")]
    public async Task SignIn_EncodesReturnUrlsAsDataAndKeepsDestinationsLocal(string supplied, string expected)
    {
        using var factory = new CustomWebApplicationFactory();
        using var client = factory.CreateClient();
        var html = await client.GetStringAsync("/signin?returnUrl=" + Uri.EscapeDataString(supplied));
        var declaration = Regex.Match(html, @"const returnUrl = ([^\r\n]+);");
        Assert.True(declaration.Success);
        Assert.Equal(expected, JsonSerializer.Deserialize<string>(declaration.Groups[1].Value));
        Assert.DoesNotContain("</script><script>", html);
        Assert.DoesNotContain("alert('untrusted')", html);
        Assert.Contains("function signInWithProvider(provider, event)", html);
        Assert.Contains("signInWithProvider('Microsoft', event)", html);
        Assert.Contains("signInWithProvider('Google', event)", html);
        Assert.Contains("signInWithProvider('Apple', event)", html);
#if DEBUG
        Assert.Contains("id=\"dev-login-form\"", html);
#else
        Assert.DoesNotContain("id=\"dev-login-form\"", html);
        Assert.DoesNotContain("/api/auth/dev-login", html);
#endif
    }

    [Fact]
    public async Task SignIn_EncodesErrorMessagesAndPrefersTypedSessionErrors()
    {
        using var factory = new CustomWebApplicationFactory();
        using var client = factory.CreateClient();
        var encoded = await client.GetStringAsync("/signin?error=" + Uri.EscapeDataString("<script>untrusted</script>"));
        Assert.Contains("&lt;script&gt;untrusted&lt;/script&gt;", encoded);
        Assert.DoesNotContain("<script>untrusted</script>", encoded);
        var typed = await client.GetStringAsync("/signin?error=untrusted&errorType=SessionRevoked");
        Assert.DoesNotContain("untrusted", typed);
        Assert.Contains(WebUtility.HtmlEncode(AuthErrorMessages.GetMessage(AuthErrorType.SessionRevoked)!), typed);
    }

    [Theory]
    [InlineData("/about", "About OneBigHead")]
    [InlineData("/terms", "Terms of Service")]
    [InlineData("/privacy", "Privacy Policy")]
    public async Task PublicInformation_RendersWithSharedNavigation(string path, string title)
    {
        using var factory = new CustomWebApplicationFactory();
        using var client = factory.CreateClient();
        var html = await client.GetStringAsync(path);
        Assert.Contains(title, html);
        Assert.Contains("landing__header", html);
        Assert.Contains("landing__footer", html);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ErrorPage_OffersRecoveryWithoutDeploymentInstructions(bool withoutReference)
    {
        using var factory = new CustomWebApplicationFactory();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            if (withoutReference) services.Configure<MvcOptions>(options => options.Filters.Add(new HideErrorReference()));
        }));
        using var client = host.CreateClient();
        var response = await client.GetAsync("/error");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Something went wrong", html);
        Assert.Contains("Return home", html);
        Assert.Contains("Contact support", html);
        Assert.Contains("/settings?section=support", html);
        Assert.DoesNotContain("ASPNETCORE_ENVIRONMENT", html);
        Assert.DoesNotContain("Development Mode", html);
        Assert.Equal(!withoutReference, html.Contains("include this reference"));
        Assert.Equal(!withoutReference, html.Contains("landing__reference"));
    }

    private sealed class HideErrorReference : IPageFilter
    {
        public void OnPageHandlerSelected(PageHandlerSelectedContext context) { }
        public void OnPageHandlerExecuting(PageHandlerExecutingContext context) { }
        public void OnPageHandlerExecuted(PageHandlerExecutedContext context)
        {
            if (context.HandlerInstance is ErrorModel model) model.RequestId = null;
        }
    }
}

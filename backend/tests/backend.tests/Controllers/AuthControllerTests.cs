using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class AuthControllerTests
{
    private readonly Mock<IOidcTokenValidator> _mockTokenValidator;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IWorkspaceUserRepository> _mockWorkspaceUserRepository;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly AuthenticationSettings _settings;
    private readonly AuthController _controller;
    private readonly Mock<ICurrentUserSessionReader> _sessions = new();
    private readonly Mock<IAccountTerms> _accountTerms = new();
    private readonly Mock<IExternalUserService> _externalUsers = new();

    public AuthControllerTests()
    {
        _mockTokenValidator = new Mock<IOidcTokenValidator>();
        _mockTokenService = new Mock<ITokenService>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockWorkspaceUserRepository = new Mock<IWorkspaceUserRepository>();
        _mockLogger = new Mock<ILogger<AuthController>>();

        _settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings
            {
                SigningKey = "test-key-that-is-at-least-32-characters-long",
                Issuer = "test-issuer",
                Audience = "test-audience",
                SlidingExpirationMinutes = 60,
                AbsoluteExpirationDays = 7
            },
            Cookie = new CookieSettings
            {
                Name = "auth_token",
                Secure = true,
                SameSite = "Strict"
            },
            OAuth = new OAuthSettings
            {
                BaseUrl = "https://localhost",
                CallbackPath = "/api/auth/callback",
                PostLoginRedirectUrl = "/collections",
                PostLoginErrorUrl = "/error"
            },
            Providers = new OidcProviderSettings
            {
                Microsoft = new OidcProvider { Enabled = true, ClientId = "ms-client", ClientSecret = "ms-secret", Authority = "https://login.microsoftonline.com/common/v2.0" },
                Google = new OidcProvider { Enabled = true, ClientId = "google-client", ClientSecret = "google-secret", Authority = "https://accounts.google.com" },
                Apple = new OidcProvider { Enabled = false }
            }
        };

        var options = Options.Create(_settings);

        _controller = new AuthController(
            _mockTokenValidator.Object,
            _mockTokenService.Object,
            _mockUserRepository.Object,
            _mockWorkspaceUserRepository.Object,
            _externalUsers.Object,
            _sessions.Object,
            _accountTerms.Object,
            options,
            _mockLogger.Object);

        SetupHttpContext();
        var url = new Mock<IUrlHelper>();
        url.Setup(u => u.IsLocalUrl(It.IsAny<string>())).Returns((string value) => value.StartsWith("/") && !value.StartsWith("//"));
        _controller.Url = url.Object;
    }

    private void SetupHttpContext(bool authenticated = false, int workspaceId = 1, string email = "test@example.com")
    {
        var httpContext = new DefaultHttpContext();
        
        if (authenticated)
        {
            var claims = new List<Claim>
            {
                new("workspace_id", workspaceId.ToString()),
                new(ClaimTypes.NameIdentifier, "1"),
                new(ClaimTypes.Email, email)
            };
            var identity = new ClaimsIdentity(claims, "TestAuth");
            httpContext.User = new ClaimsPrincipal(identity);
        }

        httpContext.Request.Scheme = "https";
        httpContext.Request.Host = new HostString("localhost");
        httpContext.Response.Body = new MemoryStream();

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("None")]
    [InlineData("99")]
    public void Login_RejectsUnsupportedProvider(string provider) => Assert.IsType<BadRequestObjectResult>(_controller.Login(provider));

    [Theory]
    [InlineData("google", "Google")]
    [InlineData("MICROSOFT", "Microsoft")]
    public void Login_ChallengesNamedProvider(string provider, string scheme)
    {
        var result = Assert.IsType<ChallengeResult>(_controller.Login(provider, "/collections/42"));
        Assert.Equal(scheme, Assert.Single(result.AuthenticationSchemes));
        Assert.Equal("/collections/42", result.Properties!.RedirectUri);
    }

    [Fact]
    public void Login_UsesDefaultReturnUrlForExternalUrl()
    {
        var result = Assert.IsType<ChallengeResult>(_controller.Login("google", "https://other.example"));
        Assert.Equal("/collections", result.Properties!.RedirectUri);
    }

    [Fact]
    public void Login_ReportsDisabledProvider() => Assert.Contains("not%20enabled", Assert.IsType<RedirectResult>(_controller.Login("apple")).Url);

    [Fact]
    public void UnavailableCallback_ReportsError() => Assert.StartsWith("/error?error=", Assert.IsType<RedirectResult>(_controller.UnavailableCallback()).Url);

    #region Callback (JSON) Tests

    [Fact]
    public async Task Callback_ReturnsBadRequest_WhenTokenMissing()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "", Provider = "google" };

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("None")]
    [InlineData("999")]
    public async Task Callback_ReturnsBadRequest_WhenProviderInvalid(string provider)
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "token", Provider = provider };

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenValidator.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Callback_ReturnsUnauthorized_WhenTokenInvalid()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "invalid-token", Provider = "google" };
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("invalid-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = false, Error = "Invalid token" });

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Callback_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "valid-token", Provider = "google" };
        var user = new User { Id = 1, ActiveWorkspaceId = 1, Email = "test@example.com", ActiveWorkspace = new Workspace { Name = "Test Workspace" } };

        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("valid-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Email = "test@example.com", Subject = "sub123" });
        _externalUsers.Setup(service => service.GetOrCreateAsync(IdentityProvider.Google,
            It.Is<OidcValidationResult>(identity => identity.Subject == "sub123"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ExternalSignInResult(user, WorkspaceRole.Normal));
        _mockTokenService.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("app-token");

        // Act
        var result = await _controller.Callback(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AuthCallbackResponse>(okResult.Value);
        Assert.True(response.Success);
        Assert.Equal("test@example.com", response.Email);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Use the original account and provider.")]
    public async Task Callback_RejectsAccountMismatchWithoutIssuingACookie(string? error)
    {
        using var cancellation = new CancellationTokenSource();
        _controller.HttpContext.RequestAborted = cancellation.Token;
        var identity = new OidcValidationResult { IsValid = true, Email = "test@example.com", Subject = "other" };
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("token", IdentityProvider.Google)).ReturnsAsync(identity);
        _externalUsers.Setup(s => s.GetOrCreateAsync(IdentityProvider.Google, identity, cancellation.Token))
            .ReturnsAsync(new ExternalSignInResult(null, Error: error));
        var response = Assert.IsType<UnauthorizedObjectResult>(await _controller.Callback(new AuthCallbackRequest { Provider = "google", Token = "token" }));
        var json = System.Text.Json.JsonSerializer.Serialize(response.Value);
        Assert.Contains(error ?? ExternalSignInResult.DefaultError, json);
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
        _mockTokenService.VerifyNoOtherCalls();
        _externalUsers.Verify(s => s.GetOrCreateAsync(IdentityProvider.Google, identity, cancellation.Token), Times.Once);
    }

    #endregion

    #region Logout Tests

    [Fact]
    public void Logout_ReturnsOk_AndDeletesCookie()
    {
        // Act
        var result = _controller.Logout();

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    #endregion

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    public async Task CurrentUser_RejectsInvalidIdentity(string? userId)
    {
        var claims = userId is null ? Array.Empty<Claim>() : [new Claim(ClaimTypes.NameIdentifier, userId)];
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
        Assert.IsType<UnauthorizedObjectResult>(await _controller.GetCurrentUser());
        _sessions.Verify(s => s.ReadAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task CurrentUser_RejectsUnauthenticatedIdentity()
    {
        Assert.IsType<UnauthorizedObjectResult>(await _controller.GetCurrentUser());
        _controller.HttpContext.User = new ClaimsPrincipal();
        Assert.IsType<UnauthorizedObjectResult>(await _controller.GetCurrentUser());
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "1")]));
        Assert.IsType<UnauthorizedObjectResult>(await _controller.GetCurrentUser());
    }

    [Fact]
    public async Task CurrentUser_RejectsMissingAccount()
    {
        SetupHttpContext(authenticated: true);
        Assert.IsType<UnauthorizedObjectResult>(await _controller.GetCurrentUser());
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(5)]
    public async Task CurrentUser_RefreshesCookieFromTheAuthoritativeSession(int? workspaceId)
    {
        SetupHttpContext(authenticated: true, workspaceId: 999, email: "stale@example.test");
        var user = new User { Id = 1, ActiveWorkspaceId = workspaceId, Email = "current@example.test", IsSystemAdministrator = true };
        if (workspaceId is int id)
            user.WorkspaceMemberships.Add(new WorkspaceUser { WorkspaceId = id, WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
                Workspace = new Workspace { Id = id, Name = "Current", HasCompletedWelcome = true } });
        var response = CurrentUserResponse.FromUser(user);
        _sessions.Setup(s => s.ReadAsync(1)).ReturnsAsync(new CurrentUserSession(user, response));
        _mockTokenService.Setup(t => t.GenerateAppToken(user, response.WorkspaceRole)).Returns("refreshed-token");
        var result = Assert.IsType<OkObjectResult>(await _controller.GetCurrentUser());
        Assert.Same(response, result.Value);
        Assert.Equal(workspaceId, response.WorkspaceId);
        Assert.Equal("current@example.test", response.Email);
        Assert.Equal("no-store", _controller.Response.Headers.CacheControl);
        Assert.Contains("auth_token=refreshed-token", _controller.Response.Headers.SetCookie.ToString());
    }

#if DEBUG
    [Fact]
    public async Task DevLogin_AuthenticatesAnExistingAccountWithoutAWorkspace()
    {
        var user = new User { Id = 1, Email = "existing@example.test", ActiveWorkspaceId = null };
        _mockUserRepository.Setup(r => r.GetByEmailAsync(user.Email)).ReturnsAsync(user);
        _mockTokenService.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("workspace-less-token");
        Assert.IsType<OkObjectResult>(await _controller.DevLogin(new DevLoginRequest { Email = user.Email }));
        Assert.Contains("workspace-less-token", _controller.Response.Headers.SetCookie.ToString());
        _mockWorkspaceUserRepository.Verify(r => r.GetMembershipAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task DevLogin_RestoresTheAccountAndUsesItsCurrentMembership(bool deleted, bool hasMembership)
    {
        var user = new User { Id = 1, ActiveWorkspaceId = 5, Email = "existing@example.test", IsDeleted = deleted, DeletedAt = DateTime.UtcNow };
        _mockUserRepository.Setup(r => r.GetByEmailAsync(user.Email)).ReturnsAsync(user);
        if (hasMembership) _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(1, 5))
            .ReturnsAsync(new WorkspaceUser { WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        var role = hasMembership ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal;
        _mockTokenService.Setup(t => t.GenerateAppToken(user, role)).Returns("membership-token");
        Assert.IsType<OkObjectResult>(await _controller.DevLogin(new DevLoginRequest { Email = " Existing@Example.Test " }));
        Assert.Contains("membership-token", _controller.Response.Headers.SetCookie.ToString());
        _mockUserRepository.Verify(r => r.UpdateAsync(user), deleted ? Times.Once : Times.Never);
        Assert.False(user.IsDeleted);
        if (deleted) Assert.Null(user.DeletedAt);
    }

    [Fact]
    public async Task DevLogin_NewAccountReceivesItsOwnAdministratorWorkspace()
    {
        var user = new User { Id = 2, ActiveWorkspaceId = 6, Email = "new@example.test" };
        _mockUserRepository.Setup(r => r.CreateWithNewWorkspaceAsync(user.Email, IdentityProvider.Microsoft, It.IsAny<string>())).ReturnsAsync(user);
        _mockTokenService.Setup(t => t.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin)).Returns("new-account-token");
        Assert.IsType<OkObjectResult>(await _controller.DevLogin(new DevLoginRequest { Email = user.Email }));
        Assert.Contains("new-account-token", _controller.Response.Headers.SetCookie.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task DevLogin_RequiresAnEmail(string email) =>
        Assert.IsType<BadRequestObjectResult>(await _controller.DevLogin(new DevLoginRequest { Email = email }));

#endif

    [Fact]
    public async Task Callback_AcceptsAnExistingWorkspaceLessIdentity()
    {
        var user = new User { Id = 1, Email = "remaining@example.test" };
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("valid", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Subject = "subject", Email = user.Email });
        _externalUsers.Setup(s => s.GetOrCreateAsync(IdentityProvider.Google, It.IsAny<OidcValidationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ExternalSignInResult(user));
        _mockTokenService.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("remaining-token");
        var result = Assert.IsType<OkObjectResult>(await _controller.Callback(new AuthCallbackRequest { Token = "valid", Provider = "google" }));
        var response = Assert.IsType<AuthCallbackResponse>(result.Value);
        Assert.Null(response.WorkspaceId);
        Assert.Equal("", response.WorkspaceName);
        Assert.Contains("remaining-token", _controller.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public async Task Callback_FailedIdentityLinkDoesNotIssueACookie()
    {
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("valid", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Subject = "subject", Email = "pending@example.test" });
        _externalUsers.Setup(s => s.GetOrCreateAsync(IdentityProvider.Google, It.IsAny<OidcValidationResult>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ExternalSignInResult.Rejected("Account sign-in changed. Please try again."));
        var result = Assert.IsType<UnauthorizedObjectResult>(await _controller.Callback(new AuthCallbackRequest { Token = "valid", Provider = "google" }));
        Assert.Equal(401, result.StatusCode);
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task AcceptTerms_RequiresAValidAccountIdentity(string? id)
    {
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test"));
        Assert.IsType<UnauthorizedObjectResult>(await _controller.AcceptTerms());
        _accountTerms.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AcceptTerms_RecordsConsentOnlyForAnExistingAccount()
    {
        SetupHttpContext(authenticated: true);
        Assert.IsType<NotFoundObjectResult>(await _controller.AcceptTerms());
        using var cancellation = new CancellationTokenSource();
        _controller.HttpContext.RequestAborted = cancellation.Token;
        var acceptedAt = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
        _accountTerms.Setup(command => command.AcceptAsync(1, cancellation.Token)).ReturnsAsync(acceptedAt);
        var result = Assert.IsType<OkObjectResult>(await _controller.AcceptTerms());
        var response = Assert.IsType<AcceptTermsResponse>(result.Value);
        Assert.True(response.HasAcceptedTerms);
        Assert.Equal(acceptedAt, response.AcceptedTermsAt);
        _accountTerms.Verify(command => command.AcceptAsync(1, cancellation.Token), Times.Once);
        _mockUserRepository.VerifyNoOtherCalls();
    }


}
